// Popup do MainDug: login na API, lista de credenciais, preencher/copiar e configurações.

import { api, ApiError } from './lib/api.js';
import { getSettings, saveSettings, siteUrl, hostPermissionFor, DEFAULT_API_BASE } from './lib/config.js';
import { getSession, setSession, clearSession } from './lib/session.js';
import { refreshIndex, getIndex } from './lib/vault.js';
import { hostOfUrl, matchesHost } from './lib/domain.js';

const $ = (id) => document.getElementById(id);

let index = [];
let activeTab = null;
let pageHost = null;

// ==========================================
// INICIALIZAÇÃO
// ==========================================

document.addEventListener('DOMContentLoaded', async () => {
    const settings = await getSettings();
    applySettingsToForm(settings);
    setupListeners();

    [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    // activeTab concede a URL da aba ativa enquanto o popup está aberto.
    pageHost = activeTab?.url ? hostOfUrl(activeTab.url) : null;

    const session = await getSession();
    if (session) {
        showMain(session);
        await loadCredentials();
    } else {
        showLogin();
    }
});

function setupListeners() {
    $('loginForm').addEventListener('submit', handleLogin);
    $('signupBtn').addEventListener('click', openSite('/signup/'));
    $('openSiteBtn').addEventListener('click', openSite('/'));
    $('logoutBtn').addEventListener('click', handleLogout);
    $('logoutAccountBtn').addEventListener('click', handleLogout);
    $('searchPasswords').addEventListener('input', () => render());

    document.querySelectorAll('.tab').forEach((tab) => {
        tab.addEventListener('click', () => showTab(tab.dataset.tab));
    });

    for (const key of ['autoFill', 'autoSave', 'notifications', 'darkMode']) {
        $(key).addEventListener('change', async (event) => {
            const settings = await saveSettings({ [key]: event.target.checked });
            applyTheme(settings);
        });
    }

    $('saveServerBtn').addEventListener('click', () => changeServer($('apiBaseUrl').value.trim()));
    $('resetServerBtn').addEventListener('click', () => changeServer(DEFAULT_API_BASE));
}

// ==========================================
// SESSÃO
// ==========================================

async function handleLogin(event) {
    event.preventDefault();
    const login = $('loginInput').value.trim();
    const password = $('passwordInput').value;
    if (!login || !password) return;

    $('loginBtn').disabled = true;
    try {
        const data = await api.login(login, password);
        const session = { token: data.token, login: data.user.login, userId: data.userId };
        await setSession(session);
        $('passwordInput').value = '';
        showMain(session);
        await loadCredentials();
    } catch (error) {
        showStatus(loginErrorMessage(error));
    } finally {
        $('loginBtn').disabled = false;
    }
}

function loginErrorMessage(error) {
    if (!(error instanceof ApiError)) return 'Erro inesperado ao entrar.';
    if (error.status === 0) return 'Sem conexão com o servidor MainDug.';
    if (error.status === 401) return 'Login ou senha incorretos.';
    if (error.status === 429) return 'Muitas tentativas. Aguarde um minuto.';
    return error.message;
}

async function handleLogout() {
    await clearSession();
    index = [];
    showLogin();
    toast('Cofre bloqueado.');
}

// ==========================================
// CREDENCIAIS
// ==========================================

async function loadCredentials() {
    $('passwordLoader').hidden = false;
    try {
        index = await refreshIndex();
    } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
            showLogin();
            showStatus('Sessão expirada. Entre novamente.');
            return;
        }
        index = await getIndex().catch(() => []);
        toast('Não foi possível atualizar a lista.');
    } finally {
        $('passwordLoader').hidden = true;
    }
    render();
}

function render() {
    const term = $('searchPasswords').value.trim().toLowerCase();
    const visible = index
        .filter((entry) => !term || (entry.site || '').toLowerCase().includes(term) || (entry.login || '').toLowerCase().includes(term))
        .sort((a, b) => (a.site || '').localeCompare(b.site || ''));
    const forSite = visible.filter((entry) => matchesHost(pageHost, entry.host));

    fillList($('siteList'), forSite, true);
    $('siteSection').hidden = forSite.length === 0;

    fillList($('allList'), visible, false);
    $('allTitle').textContent = `Todas (${visible.length})`;
    $('emptyState').hidden = index.length > 0;
}

function fillList(container, entries, canFill) {
    const template = $('credentialTemplate');
    container.replaceChildren(...entries.map((entry) => {
        const item = template.content.firstElementChild.cloneNode(true);
        item.querySelector('.site-name').textContent = entry.site;
        item.querySelector('.username').textContent = entry.login;

        const fillBtn = item.querySelector('.fill-btn');
        if (canFill) fillBtn.addEventListener('click', () => fillCredential(entry));
        else fillBtn.remove();

        item.querySelector('.copy-btn').addEventListener('click', () => copyPassword(entry));
        return item;
    }));
}

async function fillCredential(entry) {
    // Revalida: só preenche se a credencial casa com o domínio da aba ativa.
    if (!activeTab || !matchesHost(pageHost, entry.host)) {
        toast('Esta credencial não é deste site.');
        return;
    }
    try {
        const { password } = await api.decrypt(entry.id);
        await chrome.tabs.sendMessage(activeTab.id, { type: 'fill', username: entry.login, password });
        api.recordUse(entry.id).catch(() => {});
        window.close();
    } catch (error) {
        toast(error instanceof ApiError ? error.message : 'Não foi possível preencher esta página.');
    }
}

async function copyPassword(entry) {
    try {
        const { password } = await api.decrypt(entry.id);
        await navigator.clipboard.writeText(password);
        toast('Senha copiada.');
    } catch (error) {
        toast(error instanceof ApiError ? error.message : 'Não foi possível copiar.');
    }
}

// ==========================================
// CONFIGURAÇÕES
// ==========================================

function applySettingsToForm(settings) {
    for (const key of ['autoFill', 'autoSave', 'notifications', 'darkMode']) $(key).checked = settings[key];
    $('apiBaseUrl').value = settings.apiBaseUrl;
    $('loginServer').textContent = new URL(settings.apiBaseUrl).host;
    applyTheme(settings);
}

function applyTheme(settings) {
    document.body.classList.toggle('dark-mode', settings.darkMode);
}

function validateServerUrl(value) {
    let url;
    try {
        url = new URL(value);
    } catch {
        return null;
    }
    const isDefault = url.origin === new URL(DEFAULT_API_BASE).origin;
    const isLocal = ['localhost', '127.0.0.1'].includes(url.hostname);
    return isDefault || isLocal ? url.href.replace(/\/$/, '') : null;
}

async function changeServer(value) {
    const apiBaseUrl = validateServerUrl(value);
    if (!apiBaseUrl) {
        toast('Use o servidor oficial ou localhost/127.0.0.1.');
        return;
    }
    // Precisa vir direto do clique: permissions.request exige gesto do usuário.
    if (new URL(apiBaseUrl).origin !== new URL(DEFAULT_API_BASE).origin) {
        const granted = await chrome.permissions.request({ origins: [hostPermissionFor(apiBaseUrl)] });
        if (!granted) {
            toast('Permissão para acessar o servidor negada.');
            return;
        }
    }

    const current = await getSettings();
    if (current.apiBaseUrl !== apiBaseUrl) {
        await clearSession();
        index = [];
    }
    const settings = await saveSettings({ apiBaseUrl });
    applySettingsToForm(settings);
    toast('Servidor atualizado.');
    if (!(await getSession())) showLogin();
}

// ==========================================
// UI
// ==========================================

function showLogin() {
    $('mainHeader').hidden = true;
    $('mainNav').hidden = true;
    showTab('login');
}

function showMain(session) {
    $('mainHeader').hidden = false;
    $('mainNav').hidden = false;
    $('userLogin').textContent = session.login;
    $('accountLogin').textContent = session.login;
    $('avatar').textContent = (session.login || '?').slice(0, 2).toUpperCase();
    showTab('passwords');
}

function showTab(name) {
    document.querySelectorAll('.tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
    document.querySelectorAll('.tab-content').forEach((content) => content.classList.toggle('active', content.id === name));
}

function openSite(path) {
    return async () => {
        const { apiBaseUrl } = await getSettings();
        chrome.tabs.create({ url: siteUrl(apiBaseUrl) + path });
    };
}

function showStatus(message) {
    const status = $('loginStatus');
    status.textContent = message;
    status.className = 'status-message error';
    status.hidden = false;
}

let toastTimer;
function toast(message) {
    const element = $('toast');
    element.textContent = message;
    element.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => element.classList.remove('show'), 3000);
}
