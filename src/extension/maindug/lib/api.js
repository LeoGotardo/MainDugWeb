// Cliente da API MainDug (src/apiRoutes.py). Usado pelo service worker e pelo popup.

import { getSettings } from './config.js';
import { getSession, clearSession } from './session.js';

export class ApiError extends Error {
    constructor(status, message, body = null) {
        super(message);
        this.status = status;
        this.body = body;
    }
}

async function apiFetch(path, { method = 'GET', body, auth = true } = {}) {
    const { apiBaseUrl } = await getSettings();
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    if (auth) {
        const session = await getSession();
        if (!session) throw new ApiError(401, 'Faça login no MainDug');
        headers.Authorization = `Bearer ${session.token}`;
    }

    let response;
    try {
        response = await fetch(apiBaseUrl.replace(/\/$/, '') + path, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body),
        });
    } catch {
        throw new ApiError(0, 'Sem conexão com o servidor MainDug');
    }

    let data = null;
    try {
        data = await response.json();
    } catch {
        // resposta sem JSON
    }

    if (response.status === 401 && auth) {
        // Token expirado ou conta desativada: a sessão local não vale mais.
        await clearSession();
    }
    if (!response.ok) {
        throw new ApiError(response.status, data?.error || `Erro ${response.status}`, data);
    }
    return data;
}

const PAGE_SIZE = 100;

export const api = {
    login: (login, password) => apiFetch('/auth/login', { method: 'POST', body: { login, password }, auth: false }),

    /** Todas as credenciais (sem senha). A API limita 100 por página e repete a última página além do fim. */
    async listAll() {
        const all = [];
        const seen = new Set();
        for (let page = 1; ; page++) {
            const items = await apiFetch(`/passwords?page=${page}&perPage=${PAGE_SIZE}`);
            const fresh = items.filter((item) => !seen.has(item.id));
            fresh.forEach((item) => seen.add(item.id));
            all.push(...fresh);
            if (items.length < PAGE_SIZE || fresh.length === 0) return all;
        }
    },

    decrypt: (id) => apiFetch(`/passwords/${encodeURIComponent(id)}/decrypt`),
    create: (credential) => apiFetch('/passwords', { method: 'POST', body: credential }),
    update: (id, changes) => apiFetch(`/passwords/${encodeURIComponent(id)}`, { method: 'PUT', body: changes }),
    recordUse: (id) => apiFetch(`/passwords/${encodeURIComponent(id)}/use`, { method: 'POST' }),
    generate: (options) => apiFetch('/generate-password', { method: 'POST', body: options }),
};
