// Teste ponta a ponta da extensão MainDug no Chrome (cenários em harness.mjs).
//
// Pré-requisitos (uma vez):
//   npx @puppeteer/browsers install chrome@stable      # Chrome for Testing (o Chrome com marca ignora --load-extension)
//   cd tests/extension && npm install
// Rodar:
//   CHROME_PATH=/caminho/para/chrome node tests/extension/e2e.mjs

import puppeteer from 'puppeteer-core';
import {
    runSuite, waitFor, scenarioPopupLogin, scenarioFill, scenarioLookalike, scenarioSave, scenarioUpdate, scenarioVaultSite,
} from './harness.mjs';

const CHROME_PATH = process.env.CHROME_PATH;
if (!CHROME_PATH) {
    console.error('Defina CHROME_PATH (Chrome for Testing). Veja o cabeçalho deste arquivo.');
    process.exit(2);
}

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

runSuite(async (ctx) => {
    const browser = await puppeteer.launch({
        executablePath: CHROME_PATH,
        headless: true,
        ignoreDefaultArgs: ['--disable-extensions'],
        args: [
            '--no-sandbox',
            `--disable-extensions-except=${ctx.extensionDir}`,
            `--load-extension=${ctx.extensionDir}`,
            '--host-resolver-rules=MAP *.test 127.0.0.1',
        ],
    });
    try {
        const worker = await browser.waitForTarget(
            (target) => target.type() === 'service_worker' && target.url().endsWith('/background.js'),
            { timeout: 15_000 },
        ).catch(() => null);
        ctx.check('extensão carrega e o service worker sobe', !!worker);
        if (!worker) return;

        const extensionId = new URL(worker.url()).host;
        const popup = await browser.newPage();
        const popupErrors = [];
        popup.on('pageerror', (error) => popupErrors.push(error.message));
        const openPopup = async () => {
            await popup.goto(`chrome-extension://${extensionId}/popup.html`);
            return popup;
        };
        if (!(await scenarioPopupLogin(ctx, openPopup))) return;
        ctx.check('popup sem erros de JavaScript', popupErrors.length === 0, popupErrors.join('; '));

        const page = await browser.newPage();
        await scenarioFill(ctx, page, clickPromptButton);
        await scenarioLookalike(ctx, page);
        await scenarioSave(ctx, page, clickPromptButton);
        await scenarioUpdate(ctx, page, clickPromptButton);
        await scenarioVaultSite(ctx, await browser.newPage());
    } finally {
        await browser.close();
    }
});
