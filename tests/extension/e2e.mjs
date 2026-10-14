// Teste ponta a ponta da extensão MainDug num Chrome real.
//
// Sobe a API Flask local (SQLite temporário), uma página de login falsa servida em
// mybank.test / bank.test / other.test (via --host-resolver-rules) e carrega uma cópia
// da extensão com o manifest ajustado para aceitar a API em 127.0.0.1.
//
// Pré-requisitos (uma vez):
//   npx @puppeteer/browsers install chrome@stable      # Chrome for Testing (o Chrome com marca ignora --load-extension)
//   cd tests/extension && npm install
// Rodar:
//   CHROME_PATH=/caminho/para/chrome node tests/extension/e2e.mjs

import { spawn, execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EXTENSION_SRC = path.join(ROOT, 'src/extension/maindug');
const PYTHON = path.join(ROOT, 'venv/bin/python');
const CHROME_PATH = process.env.CHROME_PATH;
const API_PORT = 5077;
const SITE_PORT = 8089;
const API = `http://127.0.0.1:${API_PORT}/api`;

if (!CHROME_PATH) {
    console.error('Defina CHROME_PATH (Chrome for Testing). Veja o cabeçalho deste arquivo.');
    process.exit(2);
}

const workDir = mkdtempSync(path.join(tmpdir(), 'maindug-e2e-'));
const apiEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    EXEC_MODE: 'dev',
    DEBUG: 'false',
    SECRET_KEY: 'e2e-session-secret',
    ENCRYPTION_KEY: 'e2e-encryption-key',
    JWT_SECRET: 'e2e-jwt-secret-with-at-least-32-bytes!',
    DATABASE_URL: `sqlite:///${path.join(workDir, 'e2e.db')}`,
    RATE_LIMIT_STORAGE: 'memory://',
    PORT: String(API_PORT),
};

const results = [];
function check(name, ok, detail = '') {
    results.push({ name, ok });
    console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ` (${detail})` : ''}`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, timeoutMs = 10_000, intervalMs = 200) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const value = await predicate().catch(() => null);
        if (value) return value;
        await sleep(intervalMs);
    }
    return null;
}

// ==========================================
// INFRA: API, site de teste, extensão
// ==========================================

function startApi() {
    const proc = spawn(PYTHON, [path.join(ROOT, 'src/app.py')], { env: apiEnv, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    proc.stderr.on('data', (chunk) => { stderr += chunk; });
    proc.logs = () => stderr;
    return proc;
}

async function api(pathname, { method = 'GET', token, body } = {}) {
    const response = await fetch(API + pathname, {
        method,
        headers: { ...(token && { Authorization: `Bearer ${token}` }), ...(body && { 'Content-Type': 'application/json' }) },
        body: body && JSON.stringify(body),
    });
    return { status: response.status, data: await response.json().catch(() => null) };
}

async function createUser(login, password) {
    // Cadastro pelo formulário web (com CSRF), como um usuário faria.
    const site = API.replace(/\/api$/, '');
    const page = await fetch(`${site}/signup/`);
    const cookie = page.headers.get('set-cookie').split(';')[0];
    const csrf = (await page.text()).match(/name="csrf-token" content="([^"]+)"/)[1];
    const response = await fetch(`${site}/signup/`, {
        method: 'POST',
        redirect: 'manual',
        headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf_token: csrf, login, password, passwordConfirm: password }),
    });
    if (response.status !== 302) throw new Error(`cadastro falhou: ${response.status}`);
}

function countUsageLogs(credentialId) {
    const code = `import sys; sys.path.insert(0, 'src')\nfrom database import Config, Logs\nwith Config.app.app_context(): print(Config.session.query(Logs).filter_by(passwordId=${Number(credentialId)}).count())`;
    return Number(execFileSync(PYTHON, ['-c', code], { cwd: ROOT, env: apiEnv }).toString().trim());
}

function startLoginSite() {
    const loginPage = `<!doctype html><meta charset="utf-8"><title>Login</title>
        <form method="post" action="/welcome">
          <input id="username" name="username" autocomplete="username">
          <input id="password" name="password" type="password">
          <button id="submit" type="submit">Entrar</button>
        </form>`;
    const welcomePage = '<!doctype html><meta charset="utf-8"><title>Bem-vindo</title><h1>Logado</h1>';
    const server = http.createServer((request, response) => {
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        response.end(request.url.startsWith('/welcome') ? welcomePage : loginPage);
    });
    return new Promise((resolve) => server.listen(SITE_PORT, '127.0.0.1', () => resolve(server)));
}

function prepareExtension() {
    const dir = path.join(workDir, 'extension');
    cpSync(EXTENSION_SRC, dir, { recursive: true });
    const manifestPath = path.join(dir, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    // Só nesta cópia de teste: acesso à API local sem o pedido de permissão (que exige clique).
    manifest.host_permissions.push('http://127.0.0.1/*');
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    return dir;
}

// ==========================================
// UI DA EXTENSÃO NA PÁGINA (shadow root fechada)
// ==========================================

/** Procura, inclusive dentro de shadow roots fechadas (CDP pierce), um botão com o texto dado. */
async function findPromptButton(page, text) {
    const cdp = await page.createCDPSession();
    try {
        const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
        const stack = [root];
        while (stack.length) {
            const node = stack.pop();
            if (node.nodeName === 'BUTTON' && (node.children || []).some((child) => child.nodeValue?.trim() === text)) {
                const { model } = await cdp.send('DOM.getBoxModel', { nodeId: node.nodeId });
                const [x1, y1, , , x3, y3] = model.content;
                return { x: (x1 + x3) / 2, y: (y1 + y3) / 2 };
            }
            stack.push(...(node.children || []), ...(node.shadowRoots || []));
        }
        return null;
    } finally {
        await cdp.detach();
    }
}

/** Clique real (Input.dispatchMouseEvent => event.isTrusted === true). */
async function clickPromptButton(page, text) {
    const point = await waitFor(() => findPromptButton(page, text));
    if (!point) return false;
    await page.mouse.click(point.x, point.y);
    return true;
}

const hasPrompt = (page) => page.evaluate(() => !!document.querySelector('maindug-prompt'));

// ==========================================
// CENÁRIOS
// ==========================================

async function main() {
    const apiProc = startApi();
    const site = await startLoginSite();
    let browser;
    try {
        if (!(await waitFor(async () => (await fetch(`${API}/redirect/manage`)).ok, 15_000))) {
            throw new Error(`API não subiu:\n${apiProc.logs()}`);
        }

        await createUser('e2e-user', 'Senha-E2E-2026');
        const { data: auth } = await api('/auth/login', { method: 'POST', body: { login: 'e2e-user', password: 'Senha-E2E-2026' } });
        const token = auth.token;
        const { data: bank } = await api('/passwords', { method: 'POST', token, body: { site: 'mybank.test', login: 'leo', password: 'Banco-123456' } });

        const extensionDir = prepareExtension();
        browser = await puppeteer.launch({
            executablePath: CHROME_PATH,
            headless: true,
            ignoreDefaultArgs: ['--disable-extensions'],
            args: [
                '--no-sandbox',
                `--disable-extensions-except=${extensionDir}`,
                `--load-extension=${extensionDir}`,
                '--host-resolver-rules=MAP *.test 127.0.0.1',
            ],
        });

        // 1. Extensão carrega e o service worker sobe.
        const worker = await browser.waitForTarget(
            (target) => target.type() === 'service_worker' && target.url().endsWith('/background.js'),
            { timeout: 15_000 },
        ).catch(() => null);
        check('extensão carrega e o service worker sobe', !!worker);
        if (!worker) return;
        const extensionId = new URL(worker.url()).host;

        // 2. Login pelo popup.
        const popup = await browser.newPage();
        const popupErrors = [];
        popup.on('pageerror', (error) => popupErrors.push(error.message));
        await popup.goto(`chrome-extension://${extensionId}/popup.html`);
        await popup.evaluate((apiBaseUrl) => chrome.storage.local.set({ settings: { apiBaseUrl, autoFill: true, autoSave: true, notifications: false, darkMode: false } }), API);
        await popup.reload();
        await popup.type('#loginInput', 'e2e-user');
        await popup.type('#passwordInput', 'Senha-E2E-2026');
        await popup.click('#loginBtn');
        const listed = await waitFor(() => popup.evaluate(() => !document.getElementById('mainHeader').hidden && document.getElementById('allList').textContent.includes('mybank.test')));
        check('login pelo popup e lista vinda da API', !!listed && popupErrors.length === 0, popupErrors.join('; '));

        // 3. mybank.test: sugestão aparece; clique real preenche; uso é registrado.
        const page = await browser.newPage();
        await page.goto(`http://mybank.test:${SITE_PORT}/login`);
        const clicked = await clickPromptButton(page, 'leo');
        const filled = clicked && await waitFor(() => page.evaluate(() =>
            document.getElementById('username').value === 'leo' && document.getElementById('password').value === 'Banco-123456'));
        check('mybank.test: sugestão + clique real preenchem usuário e senha', !!filled);
        const logged = await waitFor(async () => countUsageLogs(bank.id) === 1);
        check('preenchimento registra o uso ("Ver Logs")', !!logged);
        check('sender.url chega sem a permissão "tabs" (casamento feito no worker)', !!filled);

        // 4. bank.test (domínio parecido): nada é oferecido.
        await page.goto(`http://bank.test:${SITE_PORT}/login`);
        await sleep(2000);
        check('bank.test não recebe a credencial de mybank.test', !(await hasPrompt(page)));

        // 5. other.test: login novo -> navegação -> "Salvar?" -> credencial criada.
        await page.goto(`http://other.test:${SITE_PORT}/login`);
        await page.type('#username', 'novo@other.test');
        await page.type('#password', 'Outra-Senha-987');
        await Promise.all([page.waitForNavigation(), page.click('#submit')]);
        const saved = await clickPromptButton(page, 'Salvar');
        const created = saved && await waitFor(async () => {
            const { data: list } = await api('/passwords', { token });
            const entry = list.find((item) => item.site === 'other.test' && item.login === 'novo@other.test');
            return entry && (await api(`/passwords/${entry.id}/decrypt`, { token })).data.password === 'Outra-Senha-987';
        });
        check('other.test: "Salvar?" após o login cria a credencial com site = domínio', !!created);

        // 6. mybank.test com senha nova: "Atualizar?" troca a senha salva.
        await page.goto(`http://mybank.test:${SITE_PORT}/login`);
        await clickPromptButton(page, '×');
        await page.evaluate(() => { document.getElementById('username').value = ''; document.getElementById('password').value = ''; });
        await page.type('#username', 'leo');
        await page.type('#password', 'Banco-NOVA-654');
        await Promise.all([page.waitForNavigation(), page.click('#submit')]);
        const updated = await clickPromptButton(page, 'Atualizar') && await waitFor(async () =>
            (await api(`/passwords/${bank.id}/decrypt`, { token })).data.password === 'Banco-NOVA-654');
        check('senha diferente para login existente oferece "Atualizar" e troca a senha', !!updated);

        // 7. No próprio site do MainDug: login e "Nova Credencial" não podem virar "Salvar?" nem sugestão.
        const siteUrl = API.replace(/\/api$/, '');
        const vault = await browser.newPage();
        await vault.goto(`${siteUrl}/login/`);
        await vault.type('input[name="login"]', 'e2e-user');
        await vault.type('input[name="password"]', 'Senha-E2E-2026');
        await Promise.all([vault.waitForNavigation(), vault.click('form button[type="submit"]')]);
        await sleep(2500);
        const promptAfterLogin = await hasPrompt(vault);
        await vault.click('[data-bs-target="#addPasswordModal"]');
        await vault.waitForSelector('#add-site', { visible: true });
        await sleep(1000);
        const promptInModal = await hasPrompt(vault);
        await vault.type('#add-site', 'cofre-teste.com');
        await vault.type('#addPasswordForm input[name="login"]', 'alguem');
        await vault.type('#addPasswordForm input[name="password"]', 'Credencial-Nova-1');
        await Promise.all([vault.waitForNavigation(), vault.click('#addPasswordForm button[type="submit"]')]);
        await sleep(2500);
        const promptAfterAdd = await hasPrompt(vault);
        check('site do MainDug: sem "Salvar?" nem sugestão (login, modal, nova credencial)',
            !promptAfterLogin && !promptInModal && !promptAfterAdd,
            `após login: ${promptAfterLogin}, no modal: ${promptInModal}, após adicionar: ${promptAfterAdd}`);
        if (results.some((result) => !result.ok)) {
            console.log('\n--- chamadas /api e erros da API ---\n' + apiProc.logs().split('\n').filter((line) => /\/api\/|Traceback|Error/.test(line)).slice(-40).join('\n'));
        }
    } finally {
        await browser?.close();
        site.close();
        apiProc.kill();
        rmSync(workDir, { recursive: true, force: true });
    }
}

main()
    .catch((error) => {
        console.error(error);
        results.push({ ok: false });
    })
    .finally(() => {
        const failed = results.filter((result) => !result.ok).length;
        console.log(failed ? `\n${failed} falha(s)` : `\nTodos os ${results.length} cenários passaram`);
        process.exit(failed ? 1 : 0);
    });
