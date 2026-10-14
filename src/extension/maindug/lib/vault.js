// Índice local das credenciais (id, site, login, host). Não contém senhas.
//
// Fica em chrome.storage.session para que o casamento de domínio aconteça na extensão:
// nenhum hostname de página visitada é enviado ao servidor.

import { api } from './api.js';
import { getSession } from './session.js';
import { credentialHost, hostOfUrl, matchesHost } from './domain.js';

export async function refreshIndex() {
    const items = await api.listAll();
    const index = items.map((item) => ({
        id: item.id,
        site: item.site,
        login: item.login,
        host: credentialHost(item),
    }));
    await chrome.storage.session.set({ vaultIndex: index });
    return index;
}

/** Índice atual; recarrega da API se a sessão existe mas o índice ainda não foi carregado. */
export async function getIndex() {
    if (!(await getSession())) return [];
    const { vaultIndex } = await chrome.storage.session.get('vaultIndex');
    return vaultIndex || refreshIndex();
}

/** Credenciais que casam com a URL da página (comparação exata de domínio, ver domain.js). */
export async function matchesForUrl(url) {
    const pageHost = hostOfUrl(url);
    if (!pageHost) return [];
    return (await getIndex()).filter((entry) => matchesHost(pageHost, entry.host));
}
