// Content script do MainDug: detecta formulários de login, mostra a sugestão de preenchimento
// e o "Salvar senha?". Não toma decisões de segurança: quem confere o domínio e libera a senha
// é o service worker (background.js), a partir do `sender.url` desta página.
//
// Script clássico (content scripts não podem ser módulos): tudo aqui é autocontido.

(() => {
    if (window.__mainDugContent) return;
    window.__mainDugContent = true;

    const PROMPT_TAG = 'maindug-prompt';
    const SCAN_DEBOUNCE_MS = 500;
    const SPA_SAVE_CHECK_MS = 2500;
    const MAX_SUGGESTIONS = 5;

    let suggestionRequested = false;  // já perguntamos ao worker por credenciais nesta página
    let savePromptShown = false;
    let uiHost = null;
    let lastSubmission = null;

    // ==========================================
    // UTILITÁRIOS
    // ==========================================

    function send(message) {
        try {
            return chrome.runtime.sendMessage(message).catch(() => null);
        } catch {
            // extensão recarregada/removida: este content script ficou órfão
            return Promise.resolve(null);
        }
    }

    function isVisible(element) {
        if (!element.isConnected || element.disabled || element.getClientRects().length === 0) return false;
        const style = getComputedStyle(element);
        return style.visibility !== 'hidden' && style.display !== 'none';
    }

    function visiblePasswordFields(scope = document) {
        return [...scope.querySelectorAll('input[type="password"]')].filter(isVisible);
    }

    const TEXT_TYPES = new Set(['text', 'email', 'tel', '']);

    /** Campo de usuário de um formulário: autocomplete > type=email > último campo de texto antes da senha. */
    function findUsernameField(passwordField) {
        const scope = passwordField.form || document;
        const candidates = [...scope.querySelectorAll('input')].filter(
            (input) => TEXT_TYPES.has((input.getAttribute('type') || '').toLowerCase()) && isVisible(input),
        );

        const byAutocomplete = candidates.find((input) => /\b(username|email)\b/.test(input.autocomplete || ''));
        if (byAutocomplete) return byAutocomplete;

        const byType = candidates.find((input) => input.type === 'email');
        if (byType) return byType;

        const before = candidates.filter(
            (input) => input.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING,
        );
        return before[before.length - 1] || null;
    }

    function setValue(input, value) {
        // Setter nativo + eventos: frameworks (React, Vue) percebem a mudança.
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function fillLogin(username, password) {
        const passwordField = visiblePasswordFields()[0];
        if (!passwordField) return false;
        const usernameField = findUsernameField(passwordField);
        if (usernameField && username) setValue(usernameField, username);
        setValue(passwordField, password);
        return true;
    }

    // ==========================================
    // UI ISOLADA (shadow root fechada)
    // ==========================================

    const STYLE = `
        :host { all: initial; }
        .card {
            position: fixed; top: 16px; right: 16px; z-index: 2147483647;
            width: 300px; box-sizing: border-box; padding: 16px;
            background: #fff; color: #1a202c; border: 2px solid #ff7300; border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,.2);
            font: 14px/1.4 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .title { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
        .brand { font-weight: 700; color: #ff7300; }
        .close { background: none; border: 0; font-size: 18px; line-height: 1; color: #718096; cursor: pointer; }
        p { margin: 0 0 12px; }
        .warn { color: #c05621; font-size: 12px; }
        .options { display: flex; flex-direction: column; gap: 6px; }
        button.option, button.primary, button.secondary {
            font: inherit; border-radius: 8px; padding: 8px 12px; cursor: pointer; text-align: left;
        }
        button.option, button.secondary { background: #f7fafc; color: #1a202c; border: 1px solid #e2e8f0; }
        button.option:hover, button.secondary:hover { border-color: #ff7300; }
        button.primary { background: #ff7300; color: #fff; border: 0; font-weight: 600; }
        .actions { display: flex; gap: 8px; }
        .actions button { flex: 1; text-align: center; }
        .status { font-weight: 600; color: #2f855a; margin: 0; }
    `;

    function element(tag, props = {}, children = []) {
        const node = document.createElement(tag);
        Object.assign(node, props);
        node.append(...children);
        return node;
    }

    /** Botão que só reage a clique real do usuário (a página não consegue disparar). */
    function trustedButton(className, label, onClick) {
        const button = element('button', { className, type: 'button', textContent: label });
        button.addEventListener('click', (event) => {
            if (!event.isTrusted) return;
            event.preventDefault();
            event.stopPropagation();
            onClick();
        });
        return button;
    }

    function showCard(children) {
        removeCard();
        uiHost = document.createElement(PROMPT_TAG);
        uiHost.style.setProperty('all', 'initial', 'important');
        const root = uiHost.attachShadow({ mode: 'closed' });
        const card = element('div', { className: 'card' }, [
            element('div', { className: 'title' }, [
                element('span', { className: 'brand', textContent: 'MainDug' }),
                trustedButton('close', '×', removeCard),
            ]),
            ...children,
        ]);
        root.append(element('style', { textContent: STYLE }), card);
        document.documentElement.append(uiHost);
        return card;
    }

    function removeCard() {
        uiHost?.remove();
        uiHost = null;
    }

    function showStatus(card, message) {
        card.replaceChildren(element('p', { className: 'status', textContent: message }));
        setTimeout(removeCard, 2000);
    }

    // ==========================================
    // PREENCHER
    // ==========================================

    async function offerFill() {
        if (suggestionRequested || savePromptShown || visiblePasswordFields().length === 0) return;
        suggestionRequested = true;

        const response = await send({ type: 'getMatches' });
        const matches = response?.matches || [];
        if (matches.length === 0 || savePromptShown) return;

        const children = [element('p', { textContent: `Preencher login em ${location.hostname}?` })];
        if (location.protocol !== 'https:') {
            children.push(element('p', { className: 'warn', textContent: 'Atenção: esta página não usa conexão segura (https).' }));
        }
        children.push(element('div', { className: 'options' }, matches.slice(0, MAX_SUGGESTIONS).map((match) =>
            trustedButton('option', match.login, () => requestFill(match.id)),
        )));
        showCard(children);
    }

    async function requestFill(id) {
        const response = await send({ type: 'fillRequest', id });
        if (response?.password !== undefined) fillLogin(response.username, response.password);
        removeCard();
    }

    // ==========================================
    // SALVAR DEPOIS DO LOGIN
    // ==========================================

    function captureLogin(scope) {
        const passwordField = visiblePasswordFields(scope).find((input) => input.value) ||
            [...scope.querySelectorAll('input[type="password"]')].find((input) => input.value);
        if (!passwordField) return;

        const username = findUsernameField(passwordField)?.value || '';
        const password = passwordField.value;
        const key = `${username}\u0000${password}`;
        if (lastSubmission?.key === key && Date.now() - lastSubmission.at < 1000) return;
        lastSubmission = { key, at: Date.now() };

        send({ type: 'loginSubmitted', username, password });
        // Em SPAs a página não recarrega: confere de novo depois que o formulário some.
        setTimeout(checkPendingSave, SPA_SAVE_CHECK_MS);
    }

    async function checkPendingSave() {
        // Formulário de senha ainda visível = login provavelmente falhou; não pergunta ainda.
        if (savePromptShown || visiblePasswordFields().length > 0) return;

        const response = await send({ type: 'getPendingSave' });
        const pending = response?.pending;
        if (!pending || savePromptShown) return;
        savePromptShown = true;

        const isUpdate = pending.mode === 'update';
        const card = showCard([
            element('p', {
                textContent: isUpdate
                    ? `Atualizar a senha salva de ${pending.username} em ${pending.site}?`
                    : `Salvar a senha de ${pending.username} em ${pending.site}?`,
            }),
            element('div', { className: 'actions' }, [
                trustedButton('primary', isUpdate ? 'Atualizar' : 'Salvar', async () => {
                    const result = await send({ type: 'confirmSave' });
                    showStatus(card, result?.ok ? 'Salvo no MainDug ✓' : (result?.error || 'Não foi possível salvar'));
                }),
                trustedButton('secondary', 'Agora não', () => {
                    send({ type: 'dismissSave' });
                    removeCard();
                }),
            ]),
        ]);
    }

    document.addEventListener('submit', (event) => {
        if (event.target instanceof HTMLFormElement) captureLogin(event.target);
    }, true);

    document.addEventListener('click', (event) => {
        const trigger = event.target instanceof Element && event.target.closest('button, input[type="submit"], [role="button"]');
        const form = trigger?.closest('form');
        if (form && form.querySelector('input[type="password"]')) captureLogin(form);
    }, true);

    // ==========================================
    // MENSAGENS DA EXTENSÃO (popup / service worker)
    // ==========================================

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message?.type === 'fill') {
            sendResponse({ ok: fillLogin(message.username, message.password) });
        } else if (message?.type === 'insertPassword') {
            sendResponse({ ok: insertPassword(message.password) });
        }
        return false;
    });

    /** Senha gerada no campo focado; se ele for de senha, preenche também a confirmação logo depois. */
    function insertPassword(password) {
        const active = document.activeElement;
        const target = active instanceof HTMLInputElement && ['password', 'text'].includes(active.type)
            ? active
            : visiblePasswordFields()[0];
        if (!target) return false;

        setValue(target, password);
        if (target.type === 'password') {
            const fields = visiblePasswordFields();
            const confirm = fields[fields.indexOf(target) + 1];
            if (confirm && !confirm.value) setValue(confirm, password);
        }
        return true;
    }

    // ==========================================
    // INÍCIO E MUDANÇAS NA PÁGINA
    // ==========================================

    let scanTimer = null;
    const observer = new MutationObserver(() => {
        clearTimeout(scanTimer);
        scanTimer = setTimeout(() => {
            offerFill();
            if (lastSubmission && Date.now() - lastSubmission.at < 60_000) checkPendingSave();
        }, SCAN_DEBOUNCE_MS);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    checkPendingSave();
    // O worker pode ainda estar gravando o login enviado pela página anterior: confere de novo.
    setTimeout(checkPendingSave, 1500);
    offerFill();
})();
