// Infraestrutura e cenários compartilhados pelos testes e2e da extensão (Chrome e Firefox).
//
// Sobe a API Flask local (SQLite temporário) e uma página de login falsa servida em
// mybank.test / bank.test / other.test, e prepara uma cópia da extensão com o manifest
// ajustado para aceitar a API em 127.0.0.1. Cada navegador fornece só como abrir a
// extensão e como dar um clique real nos botões da caixa (que vive numa shadow root fechada).

import { spawn, execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const EXTENSION_SRC = path.join(ROOT, 'src/extension/maindug');
export const API_PORT = 5077;
export const SITE_PORT = 8089;
export const API = `http://127.0.0.1:${API_PORT}/api`;
export const SITE_URL = API.replace(/\/api$/, '');
export const TEST_HOSTS = ['mybank.test', 'bank.test', 'other.test'];

const PYTHON = path.join(ROOT, 'venv/bin/python');
const USER = { login: 'e2e-user', password: 'Senha-E2E-2026' };

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function waitFor(predicate, timeoutMs = 10_000, intervalMs = 200) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const value = await predicate().catch(() => null);
        if (value) return value;
        await sleep(intervalMs);
    }
    return null;
}

export const hasPrompt = (page) => page.evaluate(() => !!document.querySelector('maindug-prompt'));

// ==========================================
// INFRA
// ==========================================

function startApi(apiEnv) {
    const proc = spawn(PYTHON, [path.join(ROOT, 'src/app.py')], { env: apiEnv, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    proc.stderr.on('data', (chunk) => { stderr += chunk; });
    proc.logs = () => stderr;
    return proc;
}

export async function api(pathname, { method = 'GET', token, body } = {}) {
    const response = await fetch(API + pathname, {
        method,
        headers: { ...(token && { Authorization: `Bearer ${token}` }), ...(body && { 'Content-Type': 'application/json' }) },
        body: body && JSON.stringify(body),
    });
    return { status: response.status, data: await response.json().catch(() => null) };
}

async function createUser({ login, password }) {
    // Cadastro pelo formulário web (com CSRF), como um usuário faria.
    const page = await fetch(`${SITE_URL}/signup/`);
    const cookie = page.headers.get('set-cookie').split(';')[0];
    const csrf = (await page.text()).match(/name="csrf-token" content="([^"]+)"/)[1];
    const response = await fetch(`${SITE_URL}/signup/`, {
        method: 'POST',
        redirect: 'manual',
        headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf_token: csrf, login, password, passwordConfirm: password }),
    });
    if (response.status !== 302) throw new Error(`cadastro falhou: ${response.status}`);
}

function startLoginSite(reports) {
    const loginPage = `<!doctype html><meta charset="utf-8"><title>Login</title>
        <form method="post" action="/welcome">
          <input id="username" name="username" autocomplete="username">
          <input id="password" name="password" type="password">
          <button id="submit" type="submit">Entrar</button>
        </form>`;
    const welcomePage = '<!doctype html><meta charset="utf-8"><title>Bem-vindo</title><h1>Logado</h1>';
    const server = http.createServer((request, response) => {
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        const url = new URL(request.url, 'http://localhost');
        if (url.pathname === '/report') {
            // Resultados enviados por páginas de teste da extensão que o WebDriver não enxerga.
            reports.push(JSON.parse(url.searchParams.get('data')));
            response.end('ok');
        } else if (url.pathname === '/frame') {
            // Só para o Firefox: abre o popup da extensão num iframe (o BiDi não navega abas para moz-extension://).
            const src = url.searchParams.get('src').replace(/"/g, '');
            response.end(`<!doctype html><meta charset="utf-8"><iframe src="${src}" style="width:420px;height:640px;border:0"></iframe>`);
        } else {
            response.end(url.pathname.startsWith('/welcome') ? welcomePage : loginPage);
        }
    });
    return new Promise((resolve) => server.listen(SITE_PORT, '127.0.0.1', () => resolve(server)));
}

function prepareExtension(workDir, patchManifest) {
    const dir = path.join(workDir, 'extension');
    cpSync(EXTENSION_SRC, dir, { recursive: true });
    const manifestPath = path.join(dir, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    // Só nesta cópia de teste: acesso à API local sem o pedido de permissão (que exige clique).
    manifest.host_permissions.push('http://127.0.0.1/*');
    patchManifest?.(manifest, dir);
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    return dir;
}

/**
 * Sobe API + site de teste, cria o usuário e a credencial de mybank.test, roda `body(ctx)`,
 * imprime o resultado e encerra o processo com código 0/1.
 */
export async function runSuite(body, { patchManifest } = {}) {
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
    const check = (name, ok, detail = '') => {
        results.push({ name, ok });
        console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ` (${detail})` : ''}`);
    };

    const apiProc = startApi(apiEnv);
    const reports = [];
    const site = await startLoginSite(reports);
    try {
        if (!(await waitFor(async () => (await fetch(`${API}/redirect/manage`)).ok, 15_000))) {
            throw new Error(`API não subiu:\n${apiProc.logs()}`);
        }
        await createUser(USER);
        const { data: auth } = await api('/auth/login', { method: 'POST', body: USER });
        const { data: bank } = await api('/passwords', {
            method: 'POST', token: auth.token, body: { site: 'mybank.test', login: 'leo', password: 'Banco-123456' },
        });

        const countUsageLogs = (credentialId) => {
            const code = `import sys; sys.path.insert(0, 'src')\nfrom database import Config, Logs\nwith Config.app.app_context(): print(Config.session.query(Logs).filter_by(passwordId=${Number(credentialId)}).count())`;
            return Number(execFileSync(PYTHON, ['-c', code], { cwd: ROOT, env: apiEnv }).toString().trim());
        };

        await body({
            check, token: auth.token, bank, user: USER, countUsageLogs, reports,
            apiLogs: () => apiProc.logs(),
            extensionDir: prepareExtension(workDir, patchManifest),
        });

        if (results.some((result) => !result.ok)) {
            console.log('\n--- chamadas /api e erros da API ---\n' +
                apiProc.logs().split('\n').filter((line) => /\/api\/|Traceback|Error/.test(line)).slice(-40).join('\n'));
        }
    } catch (error) {
        console.error(error);
        results.push({ ok: false });
    } finally {
        site.close();
        apiProc.kill();
        rmSync(workDir, { recursive: true, force: true });
    }

    const failed = results.filter((result) => !result.ok).length;
    console.log(failed ? `\n${failed} falha(s)` : `\nTodos os ${results.length} cenários passaram`);
    process.exit(failed ? 1 : 0);
}

// ==========================================
// CENÁRIOS (iguais nos dois navegadores)
// ==========================================

/**
 * Login pelo popup. `openPopup()` devolve o popup pronto (uma página ou um frame) e é chamada
 * de novo depois de gravar as configurações, para o popup reler a URL da API local.
 */
export async function scenarioPopupLogin(ctx, openPopup) {
    let popup = await openPopup();
    await popup.evaluate((apiBaseUrl) => chrome.storage.local.set({
        settings: { apiBaseUrl, autoFill: true, autoSave: true, notifications: false, darkMode: false },
    }), API);
    popup = await openPopup();
    await popup.type('#loginInput', ctx.user.login);
    await popup.type('#passwordInput', ctx.user.password);
    await popup.click('#loginBtn');
    const listed = await waitFor(() => popup.evaluate(() =>
        !document.getElementById('mainHeader').hidden && document.getElementById('allList').textContent.includes('mybank.test')));
    const status = await popup.evaluate(() => document.getElementById('loginStatus').textContent).catch(() => '');
    ctx.check('login pelo popup e lista vinda da API', !!listed, listed ? '' : `lista não carregou; status: "${status}"`);
    return !!listed;
}

export async function scenarioFill(ctx, page, clickPromptButton) {
    await page.goto(`http://mybank.test:${SITE_PORT}/login`);
    const clicked = await clickPromptButton(page, 'leo');
    const filled = clicked && await waitFor(() => page.evaluate(() =>
        document.getElementById('username').value === 'leo' && document.getElementById('password').value === 'Banco-123456'));
    ctx.check('mybank.test: sugestão + clique real preenchem usuário e senha', !!filled, clicked ? '' : 'caixa não apareceu');
    ctx.check('preenchimento registra o uso ("Ver Logs")', !!(await waitFor(async () => ctx.countUsageLogs(ctx.bank.id) === 1)));
    ctx.check('sender.url chega sem a permissão "tabs" (casamento feito no worker)', !!filled);
}

export async function scenarioLookalike(ctx, page) {
    await page.goto(`http://bank.test:${SITE_PORT}/login`);
    await sleep(2000);
    ctx.check('bank.test não recebe a credencial de mybank.test', !(await hasPrompt(page)));
}

export async function scenarioSave(ctx, page, clickPromptButton) {
    await page.goto(`http://other.test:${SITE_PORT}/login`);
    await page.type('#username', 'novo@other.test');
    await page.type('#password', 'Outra-Senha-987');
    await Promise.all([page.waitForNavigation(), page.click('#submit')]);
    const saved = await clickPromptButton(page, 'Salvar');
    const created = saved && await waitFor(async () => {
        const { data: list } = await api('/passwords', { token: ctx.token });
        const entry = list.find((item) => item.site === 'other.test' && item.login === 'novo@other.test');
        return entry && (await api(`/passwords/${entry.id}/decrypt`, { token: ctx.token })).data.password === 'Outra-Senha-987';
    });
    ctx.check('other.test: "Salvar?" após o login cria a credencial com site = domínio', !!created, saved ? '' : 'caixa não apareceu');
}

export async function scenarioUpdate(ctx, page, clickPromptButton) {
    await page.goto(`http://mybank.test:${SITE_PORT}/login`);
    await clickPromptButton(page, '×');
    await page.evaluate(() => { document.getElementById('username').value = ''; document.getElementById('password').value = ''; });
    await page.type('#username', 'leo');
    await page.type('#password', 'Banco-NOVA-654');
    await Promise.all([page.waitForNavigation(), page.click('#submit')]);
    const updated = await clickPromptButton(page, 'Atualizar') && await waitFor(async () =>
        (await api(`/passwords/${ctx.bank.id}/decrypt`, { token: ctx.token })).data.password === 'Banco-NOVA-654');
    ctx.check('senha diferente para login existente oferece "Atualizar" e troca a senha', !!updated);
}

/** No próprio site do MainDug: login e "Nova Credencial" não podem virar "Salvar?" nem sugestão. */
export async function scenarioVaultSite(ctx, vault) {
    await vault.goto(`${SITE_URL}/login/`);
    await vault.type('input[name="login"]', ctx.user.login);
    await vault.type('input[name="password"]', ctx.user.password);
    await Promise.all([vault.waitForNavigation(), vault.click('form button[type="submit"]')]);
    await sleep(2500);
    const afterLogin = await hasPrompt(vault);
    await vault.click('[data-bs-target="#addPasswordModal"]');
    await vault.waitForSelector('#add-site', { visible: true });
    await sleep(1000);
    const inModal = await hasPrompt(vault);
    await vault.type('#add-site', 'cofre-teste.com');
    await vault.type('#addPasswordForm input[name="login"]', 'alguem');
    await vault.type('#addPasswordForm input[name="password"]', 'Credencial-Nova-1');
    await Promise.all([vault.waitForNavigation(), vault.click('#addPasswordForm button[type="submit"]')]);
    await sleep(2500);
    const afterAdd = await hasPrompt(vault);
    ctx.check('site do MainDug: sem "Salvar?" nem sugestão (login, modal, nova credencial)',
        !afterLogin && !inModal && !afterAdd, `após login: ${afterLogin}, no modal: ${inModal}, após adicionar: ${afterAdd}`);
}
