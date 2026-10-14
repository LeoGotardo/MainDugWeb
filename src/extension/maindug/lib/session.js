// Sessão e estado sensível: só em chrome.storage.session.
//
// storage.session fica em memória, some ao fechar o navegador e, no nível de acesso padrão
// (TRUSTED_CONTEXTS), não é visível para content scripts. Não altere esse nível de acesso.
// O service worker pode ser suspenso a qualquer momento: nenhum estado fica em variáveis de módulo.

/** Bloqueio automático: sessão é apagada após este tempo de inatividade do sistema (ou tela bloqueada). */
export const AUTO_LOCK_SECONDS = 15 * 60;

const SESSION_KEYS = ['session', 'vaultIndex', 'pendingSaves'];

/** @returns {Promise<{token: string, login: string, userId: string} | null>} */
export async function getSession() {
    const { session } = await chrome.storage.session.get('session');
    return session || null;
}

export async function setSession(session) {
    await chrome.storage.session.set({ session });
}

export async function clearSession() {
    await chrome.storage.session.remove(SESSION_KEYS);
}
