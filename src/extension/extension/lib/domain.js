// Casamento de domínio entre a página e a credencial salva.
//
// A credencial casa com o mesmo host ou com um subdomínio dele (com fronteira de ponto):
// "mybank.com" casa com "mybank.com" e "login.mybank.com", nunca com "bank.com",
// "ank.com" ou "mybank.com.evil.io". Nomes que não são domínio ("GitHub") nunca casam.

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//;
const HOST_CHARS = /^[a-z0-9.-]+$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Host comparável de um site salvo ou de uma URL: minúsculas, sem esquema/porta/caminho/`www.`. */
export function normalizeHost(site) {
    if (typeof site !== 'string') return null;
    const text = site.trim().toLowerCase();
    if (!text) return null;

    let host;
    if (SCHEME.test(text)) {
        try {
            host = new URL(text).hostname;
        } catch {
            return null;
        }
    } else {
        host = text.split(/[/?#]/)[0].split(':')[0];
    }

    if (host.startsWith('www.')) host = host.slice(4);
    if (!host.includes('.') || !HOST_CHARS.test(host)) return null;
    if (host.startsWith('.') || host.endsWith('.') || host.includes('..')) return null;
    return host;
}

/** Host de uma página (só http/https). */
export function hostOfUrl(url) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
        return normalizeHost(parsed.hostname);
    } catch {
        return null;
    }
}

export function matchesHost(pageHost, credentialHost) {
    if (!pageHost || !credentialHost) return false;
    if (pageHost === credentialHost) return true;
    // Para IPs não existe "subdomínio": só o endereço exato casa.
    return !IPV4.test(credentialHost) && pageHost.endsWith('.' + credentialHost);
}
