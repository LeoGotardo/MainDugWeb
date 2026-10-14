// Teste ponta a ponta da extensão MainDug no Firefox (cenários em harness.mjs).
//
// Pré-requisitos (uma vez):
//   npx @puppeteer/browsers install firefox@stable     # Firefox fora do snap (o snap não aceita perfis em /tmp)
//   cd tests/extension && npm install
// Rodar:
//   FIREFOX_PATH=/caminho/para/firefox node tests/extension/e2e-firefox.mjs
//
// O WebDriver BiDi não navega abas para moz-extension:// nem enxerga páginas de extensão. Por isso a
// cópia de teste ganha uma página `probe.html`: aberta num iframe, ela se reabre numa aba de nível
// superior (mesmo tipo de contexto do popup), confere as APIs, faz o login com o mesmo código do
// popup (lib/api.js, lib/session.js, lib/vault.js) e manda o resultado ao servidor de teste.
// Os cenários de preencher e salvar rodam depois, em páginas web normais.

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import puppeteer from 'puppeteer-core';
import {
    runSuite, waitFor, hasPrompt, API, SITE_PORT, TEST_HOSTS, EXTENSION_SRC,
    scenarioFill, scenarioLookalike, scenarioSave, scenarioUpdate, scenarioVaultSite,
} from './harness.mjs';

const FIREFOX_PATH = process.env.FIREFOX_PATH;
if (!FIREFOX_PATH) {
    console.error('Defina FIREFOX_PATH. Veja o cabeçalho deste arquivo.');
    process.exit(2);
}

const GECKO_ID = JSON.parse(readFileSync(path.join(EXTENSION_SRC, 'manifest.json'), 'utf8')).browser_specific_settings.gecko.id;
// O UUID de moz-extension:// é aleatório por perfil; fixá-lo permite montar a URL da página de sondagem.
const EXTENSION_UUID = '6d2f3c1e-5b7a-4e8f-9a0b-1c2d3e4f5a6b';
const REPORT_URL = `http://127.0.0.1:${SITE_PORT}/report`;

const PROBE_HTML = '<!doctype html><meta charset="utf-8"><title>probe</title><script type="module" src="probe.js"></script>';
const PROBE_JS = `
import { api } from './lib/api.js';
import { setSession } from './lib/session.js';
import { refreshIndex } from './lib/vault.js';

const params = new URLSearchParams(location.search);
const report = (data) => fetch('${REPORT_URL}?data=' + encodeURIComponent(JSON.stringify(data)));

if (window.top !== window) {
    // Dentro do iframe: storage.session não existe aqui; reabre como aba de nível superior.
    // Dentro do iframe o Firefox só dá APIs de content script (sem storage.session nem tabs):
    // pede ao background da cópia de teste que abra esta página numa aba de nível superior.
    report({ stage: 'iframe', sessionApi: typeof chrome.storage.session, tabsApi: typeof chrome.tabs });
    chrome.runtime.sendMessage({ type: '__e2eOpenProbe', path: 'probe.html' + location.search });
} else {
    (async () => {
        const result = {
            stage: 'top',
            sessionApi: typeof chrome.storage.session,
            promiseApi: chrome.storage.local.get('settings') instanceof Promise,
            apiPermission: await chrome.permissions.contains({ origins: ['${new URL(API).origin}/*'] }),
            sitePermission: await chrome.permissions.contains({ origins: ['http://mybank.test/*'] }),
        };
        try {
            const data = await api.login(params.get('login'), params.get('password'));
            await setSession({ token: data.token, login: data.user.login, userId: data.userId });
            result.indexSize = (await refreshIndex()).length;
        } catch (error) {
            result.error = String(error);
        }
        report(result);
    })();
}
`;

/**
 * Clique real num botão da caixa da extensão via teclado (Tab + Enter => event.isTrusted).
 * Não há como alcançar a shadow root fechada pelo BiDi; a ordem de foco é conhecida:
 * os elementos focáveis da página de teste e, em seguida, a caixa: "×" e depois o botão de ação.
 */
async function clickPromptButton(page, text) {
    if (!(await waitFor(() => hasPrompt(page)))) return false;
    const pageFocusables = await page.evaluate(() => {
        document.activeElement?.blur();
        return [...document.querySelectorAll('input, button, a[href], select, textarea')]
            .filter((element) => !element.disabled && element.getClientRects().length > 0).length;
    });
    const positionInPrompt = text === '×' ? 0 : 1;
    for (let i = 0; i <= pageFocusables + positionInPrompt; i++) await page.keyboard.press('Tab');
    await page.keyboard.press('Enter');
    return true;
}

runSuite(async (ctx) => {
    const browser = await puppeteer.launch({
        browser: 'firefox',
        executablePath: FIREFOX_PATH,
        headless: true,
        extraPrefsFirefox: {
            'extensions.webextensions.uuids': JSON.stringify({ [GECKO_ID]: EXTENSION_UUID }),
            'network.dns.localDomains': TEST_HOSTS.join(','),
        },
    });
    try {
        const installedId = await browser.installExtension(ctx.extensionDir).catch((error) => {
            console.error(error);
            return null;
        });
        ctx.check('extensão instala no Firefox (background.scripts)', installedId === GECKO_ID, String(installedId));
        if (installedId !== GECKO_ID) return;

        const query = new URLSearchParams({ login: ctx.user.login, password: ctx.user.password });
        const host = await browser.newPage();
        await host.goto(`http://127.0.0.1:${SITE_PORT}/frame?src=${encodeURIComponent(`moz-extension://${EXTENSION_UUID}/probe.html?${query}`)}`);
        const probe = await waitFor(async () => ctx.reports.find((item) => item.stage === 'top'), 15_000);
        const framed = ctx.reports.find((item) => item.stage === 'iframe');

        ctx.check('página de extensão em nível superior tem storage.session (como o popup)', probe?.sessionApi === 'object', JSON.stringify(probe));
        ctx.check('chrome.* devolve Promise no Firefox (o código usa await)', probe?.promiseApi === true);
        ctx.check('permissões de host concedidas na instalação (API e sites)', probe?.apiPermission === true && probe?.sitePermission === true);
        ctx.check('login na API com o código do popup e índice carregado', probe?.indexSize === 1, probe?.error || '');
        if (framed) console.log('  (dentro de iframe: ' + JSON.stringify(framed) + ')');
        if (probe?.indexSize !== 1) return;

        const page = await browser.newPage();
        await scenarioFill(ctx, page, clickPromptButton);
        await scenarioLookalike(ctx, page);
        await scenarioSave(ctx, page, clickPromptButton);
        await scenarioUpdate(ctx, page, clickPromptButton);
        await scenarioVaultSite(ctx, await browser.newPage());
    } finally {
        await browser.close();
    }
}, {
    // Só na cópia de teste: página de sondagem acessível por iframe da página local.
    patchManifest: (manifest, dir) => {
        manifest.web_accessible_resources = [{ resources: ['probe.html'], matches: ['http://127.0.0.1/*'] }];
        writeFileSync(path.join(dir, 'probe.html'), PROBE_HTML);
        writeFileSync(path.join(dir, 'probe.js'), PROBE_JS);
        const backgroundPath = path.join(dir, 'background.js');
        writeFileSync(backgroundPath, readFileSync(backgroundPath, 'utf8') + `
// --- só na cópia de teste (e2e-firefox.mjs) ---
chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === '__e2eOpenProbe') chrome.tabs.create({ url: chrome.runtime.getURL(message.path) });
});
`);
        // A URL padrão da API passa a ser a local (o popup real pede isso pela tela de servidor).
        const configPath = path.join(dir, 'lib/config.js');
        writeFileSync(configPath, readFileSync(configPath, 'utf8').replace(/DEFAULT_API_BASE = '[^']+'/, `DEFAULT_API_BASE = '${API}'`));
    },
});
