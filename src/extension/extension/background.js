// background.js - Service Worker para a extensão

// Listener para quando a extensão é instalada
chrome.runtime.onInstalled.addListener(() => {
    console.log('SecurePass Extension installed');
    
    // Definir configurações padrão
    chrome.storage.local.get(['settings'], (result) => {
        if (!result.settings) {
            chrome.storage.local.set({
                settings: {
                    autoSave: true,
                    autoFill: true,
                    notifications: true,
                    darkMode: false
                }
            });
        }
    });
});

// Listener para mensagens
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'checkLogin') {
        handleCheckLogin(request.data, sendResponse);
        return true; // Manter a conexão assíncrona
    }
    
    if (request.type === 'notification') {
        showNotification(request.title, request.message);
    }
});

// Verificar login
async function handleCheckLogin(data, sendResponse) {
    try {
        const response = await fetch('http://localhost:5000/api/auth/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        sendResponse(result);
    } catch (error) {
        sendResponse({ error: 'Connection failed', message: 'Erro ao conectar com o servidor' });
    }
}

// Mostrar notificação do navegador
function showNotification(title, message) {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon128.png',
        title: title,
        message: message,
        priority: 2
    });
}

// Listener para quando uma aba é atualizada
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Verificar se o usuário está autenticado
        chrome.storage.local.get(['authToken', 'settings'], (result) => {
            if (result.authToken && result.settings?.autoFill) {
                // Enviar mensagem para o content script tentar auto-preencher
                chrome.tabs.sendMessage(tabId, {
                    type: 'pageLoaded',
                    url: tab.url
                }).catch(() => {
                    // Content script não está pronto ainda
                });
            }
        });
    }
});

// Criar menu de contexto
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'savePassword',
        title: 'Salvar senha com SecurePass',
        contexts: ['password']
    });
    
    chrome.contextMenus.create({
        id: 'generatePassword',
        title: 'Gerar senha segura',
        contexts: ['editable']
    });
});

// Handler para cliques no menu de contexto
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'generatePassword') {
        const password = generateSecurePassword();
        
        // Enviar senha gerada para a página
        chrome.tabs.sendMessage(tab.id, {
            type: 'insertPassword',
            password: password
        });
        
        // Copiar para área de transferência
        chrome.tabs.sendMessage(tab.id, {
            type: 'copyToClipboard',
            text: password
        });
        
        showNotification('Senha Gerada', 'Senha copiada para a área de transferência');
    }
});

// Gerar senha segura
function generateSecurePassword(length = 16) {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const allChars = uppercase + lowercase + numbers + symbols;
    let password = '';
    
    // Garantir pelo menos um caractere de cada tipo
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];
    
    // Preencher o resto
    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }
    
    // Embaralhar
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

// Verificar periodicamente se o token ainda é válido
setInterval(() => {
    chrome.storage.local.get(['authToken'], async (result) => {
        if (result.authToken) {
            try {
                const response = await fetch('http://localhost:5000/api/auth/verify', {
                    headers: {
                        'Authorization': `Bearer ${result.authToken}`
                    }
                });
                
                if (!response.ok) {
                    // Token expirado, fazer logout
                    chrome.storage.local.remove(['authToken', 'userEmail', 'userId']);
                    showNotification('Sessão Expirada', 'Por favor, faça login novamente');
                }
            } catch (error) {
                console.error('Erro ao verificar token:', error);
            }
        }
    });
}, 300000); // Verificar a cada 5 minutos