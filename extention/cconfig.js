// config.js - Configuração centralizada da API

const CONFIG = {
    // URL da API - Altere para seu servidor em produção
    API_BASE_URL: 'http://localhost:5000/api',
    
    // Configurações de timeout
    REQUEST_TIMEOUT: 30000, // 30 segundos
    
    // Configurações de retry
    MAX_RETRIES: 3,
    RETRY_DELAY: 1000, // 1 segundo
    
    // Configurações de cache
    CACHE_DURATION: 300000, // 5 minutos
    
    // Configurações de senha
    PASSWORD_MIN_LENGTH: 6,
    PASSWORD_MAX_LENGTH: 128,
    DEFAULT_PASSWORD_LENGTH: 16,
    
    // Configurações de token
    TOKEN_REFRESH_INTERVAL: 300000, // 5 minutos
    
    // Notificações
    NOTIFICATION_DURATION: 3000 // 3 segundos
};

// Função auxiliar para fazer requisições com retry
async function fetchWithRetry(url, options = {}, retries = CONFIG.MAX_RETRIES) {
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);
        
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        
        clearTimeout(timeout);
        
        return response;
    } catch (error) {
        if (retries > 0 && (error.name === 'AbortError' || error.message.includes('network'))) {
            await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY));
            return fetchWithRetry(url, options, retries - 1);
        }
        throw error;
    }
}

// Exportar configurações
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CONFIG, fetchWithRetry };
}