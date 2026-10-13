// Configurações da extensão (chrome.storage.local: não são segredos e sobrevivem ao fechar o navegador).

export const DEFAULT_API_BASE = 'https://maindug.leogotardo.com.br/api';

export const DEFAULT_SETTINGS = {
    autoFill: true,
    autoSave: true,
    notifications: true,
    darkMode: false,
    apiBaseUrl: DEFAULT_API_BASE,
};

export async function getSettings() {
    const { settings } = await chrome.storage.local.get('settings');
    return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function saveSettings(patch) {
    const settings = { ...(await getSettings()), ...patch };
    await chrome.storage.local.set({ settings });
    return settings;
}

/** URL do site a partir da URL da API ("https://x/api" -> "https://x"). */
export function siteUrl(apiBaseUrl) {
    return apiBaseUrl.replace(/\/api\/?$/, '');
}

/** Padrão de permissão de host para uma URL de API ("http://localhost:5000/api" -> "http://localhost/*"). */
export function hostPermissionFor(apiBaseUrl) {
    const { protocol, hostname } = new URL(apiBaseUrl);
    return `${protocol}//${hostname}/*`;
}
