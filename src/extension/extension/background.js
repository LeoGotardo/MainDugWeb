// Service worker do MainDug.
//
// Regra de ouro: o worker decide. O content script só exibe a UI e repassa cliques;
// o domínio é sempre conferido pelo `sender.url` da mensagem (não por dados vindos da página),
// e a senha só sai daqui quando o usuário pede para preencher.
//
// O worker pode ser suspenso a qualquer momento: todo estado fica em chrome.storage.session.

import { api, ApiError } from './lib/api.js';
import { getSettings, DEFAULT_SETTINGS } from './lib/config.js';
import { AUTO_LOCK_SECONDS, getSession, clearSession } from './lib/session.js';
import { refreshIndex, getIndex, matchesForUrl } from './lib/vault.js';
import { hostOfUrl } from './lib/domain.js';
import { generatePassword } from './lib/passwordGenerator.js';

const PENDING_SAVE_TTL_MS = 2 * 60 * 1000;
const LEGACY_LOCAL_KEYS = ['users', 'passwords', 'encryptionKey', 'currentUser', 'authToken', 'userEmail', 'userId', 'apiBaseUrl'];

// ==========================================
// CICLO DE VIDA
// ==========================================

chrome.idle.setDetectionInterval(AUTO_LOCK_SECONDS);

chrome.idle.onStateChanged.addListener((state) => {
    // 'idle' (sem uso por AUTO_LOCK_SECONDS) ou 'locked' (tela bloqueada): bloqueia o cofre.
    if (state !== 'active') clearSession();
});

chrome.runtime.onInstalled.addListener(async () => {
    // Versões antigas guardavam contas e senhas locais e o token no disco: nada disso é mais usado.
    await chrome.storage.local.remove(LEGACY_LOCAL_KEYS);
    const { settings } = await chrome.storage.local.get('settings');
    await chrome.storage.local.set({ settings: { ...DEFAULT_SETTINGS, ...(settings || {}) } });

    chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({ id: 'generatePassword', title: 'Gerar senha segura', contexts: ['editable'] });
        chrome.contextMenus.create({ id: 'fillLogin', title: 'Preencher login deste site', contexts: ['editable'] });
    });

    chrome.alarms.create('refreshIndex', { periodInMinutes: 10 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'refreshIndex' && (await getSession())) {
        refreshIndex().catch(() => {});
    }
});

// ==========================================
// MENSAGENS
// ==========================================

const contentHandlers = {
    getMatches: handleGetMatches,
    fillRequest: handleFillRequest,
    loginSubmitted: handleLoginSubmitted,
    getPendingSave: handleGetPendingSave,
    confirmSave: handleConfirmSave,
    dismissSave: handleDismissSave,
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return false;

    // Mensagens de content script chegam com `sender.tab`; o popup e outras páginas da extensão, sem.
    const handler = sender.tab ? contentHandlers[message?.type] : null;
    if (!handler) return false;

    handler(message, sender)
        .then(sendResponse)
        .catch((error) => sendResponse({ error: error instanceof ApiError ? error.message : 'Erro inesperado' }));
    return true;
});

/** Credenciais para a página do remetente: só id/site/login, nunca a senha. */
async function handleGetMatches(message, sender) {
    const settings = await getSettings();
    if (!settings.autoFill || !(await getSession())) return { matches: [] };
    const matches = await matchesForUrl(sender.url);
    return { matches: matches.map(({ id, site, login }) => ({ id, site, login })) };
}

/** Senha de uma credencial, só se ela casar com o domínio de quem pede. */
async function handleFillRequest(message, sender) {
    const matches = await matchesForUrl(sender.url);
    const credential = matches.find((entry) => entry.id === message.id);
    if (!credential) return { error: 'Credencial não pertence a este site' };

    const { password } = await api.decrypt(credential.id);
    api.recordUse(credential.id).catch(() => {});
    return { username: credential.login, password };
}

// ---------- salvar depois do login ----------

async function getPendingSaves() {
    const { pendingSaves } = await chrome.storage.session.get('pendingSaves');
    const now = Date.now();
    return Object.fromEntries(Object.entries(pendingSaves || {}).filter(([, item]) => now - item.at < PENDING_SAVE_TTL_MS));
}

async function setPendingSave(tabId, value) {
    const pending = await getPendingSaves();
    if (value) pending[tabId] = value;
    else delete pending[tabId];
    await chrome.storage.session.set({ pendingSaves: pending });
}

async function handleLoginSubmitted(message, sender) {
    const settings = await getSettings();
    const host = hostOfUrl(sender.url);
    const username = typeof message.username === 'string' ? message.username.trim() : '';
    const password = typeof message.password === 'string' ? message.password : '';
    if (!settings.autoSave || !host || !username || !password || !(await getSession())) return { ok: false };

    await setPendingSave(sender.tab.id, { host, username, password, at: Date.now() });
    return { ok: true };
}

/** Existe um "Salvar senha?" pendente para esta aba e este site? Responde sem a senha. */
async function handleGetPendingSave(message, sender) {
    const pending = (await getPendingSaves())[sender.tab.id];
    if (!pending || pending.host !== hostOfUrl(sender.url) || !(await getSession())) return { pending: null };

    const existing = (await getIndex()).find(
        (entry) => entry.host === pending.host && (entry.login || '').toLowerCase() === pending.username.toLowerCase(),
    );
    if (existing) {
        const { password } = await api.decrypt(existing.id);
        if (password === pending.password) {
            // Já salva com esta mesma senha: nada a perguntar.
            await setPendingSave(sender.tab.id, null);
            return { pending: null };
        }
    }
    return { pending: { site: pending.host, username: pending.username, mode: existing ? 'update' : 'create' } };
}

async function handleConfirmSave(message, sender) {
    const pending = (await getPendingSaves())[sender.tab.id];
    if (!pending || pending.host !== hostOfUrl(sender.url)) return { error: 'Nada para salvar' };

    try {
        await api.create({ site: pending.host, login: pending.username, password: pending.password });
    } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 409) throw error;
        await api.update(error.body.id, { password: pending.password });
    }
    await setPendingSave(sender.tab.id, null);
    await refreshIndex();
    notify('Senha salva', `Credencial de ${pending.username} em ${pending.host} salva no MainDug.`);
    return { ok: true };
}

async function handleDismissSave(message, sender) {
    await setPendingSave(sender.tab.id, null);
    return { ok: true };
}

// ==========================================
// MENU DE CONTEXTO E ATALHOS
// ==========================================

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'generatePassword') insertGeneratedPassword(tab);
    if (info.menuItemId === 'fillLogin') fillFromMenu(tab);
});

chrome.commands.onCommand.addListener(async (command, tab) => {
    if (command !== 'generate-password') return;
    const target = tab || (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    if (target) insertGeneratedPassword(target);
});

async function insertGeneratedPassword(tab) {
    let password = generatePassword(16);
    if (await getSession()) {
        try {
            ({ password } = await api.generate({ length: 16, excludeSimilar: true }));
        } catch {
            // sem servidor: fica a senha gerada localmente
        }
    }
    chrome.tabs.sendMessage(tab.id, { type: 'insertPassword', password }).catch(() => {});
}

async function fillFromMenu(tab) {
    if (!(await getSession())) {
        notify('MainDug bloqueado', 'Abra a extensão e faça login para preencher.');
        return;
    }
    // activeTab concede tab.url aqui, porque o usuário clicou no menu.
    const matches = await matchesForUrl(tab.url);
    if (matches.length === 0) {
        notify('Nenhuma credencial', 'Não há credenciais salvas para este site.');
    } else if (matches.length > 1) {
        chrome.action.openPopup().catch(() => notify('Várias credenciais', 'Abra a extensão para escolher qual preencher.'));
    } else {
        const [credential] = matches;
        const { password } = await api.decrypt(credential.id);
        await chrome.tabs.sendMessage(tab.id, { type: 'fill', username: credential.login, password });
        api.recordUse(credential.id).catch(() => {});
    }
}

async function notify(title, message) {
    if (!(await getSettings()).notifications) return;
    chrome.notifications.create({ type: 'basic', iconUrl: 'icons/128.png', title, message, priority: 1 });
}
