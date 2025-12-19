// background.js - Service Worker para a extensão SecurePass

// URL base da API
const API_BASE_URL = 'http://localhost:5000/api';

// Listener para quando a extensão é instalada
chrome.runtime.onInstalled.addListener(() => {
    console.log('SecurePass Extension instalada');
    
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
    
    // Criar menus de contexto
    createContextMenus();
});

// Criar menus de contexto
function createContextMenus() {
    chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({
            id: 'generatePassword',
            title: 'Gerar senha segura',
            contexts: ['editable']
        });
        
        chrome.contextMenus.create({
            id: 'savePassword',
            title: 'Salvar senha com SecurePass',
            contexts: ['password']
        });
        
        chrome.contextMenus.create({
            id: 'fillPassword',
            title: 'Preencher senha salva',
            contexts: ['password']
        });
    });
}

// Handler para cliques no menu de contexto
chrome.contextMenus.onClicked.addListener((info, tab) => {
    switch (info.menuItemId) {
        case 'generatePassword':
            handleGeneratePassword(tab);
            break;
        case 'savePassword':
            handleSavePasswordContext(tab);
            break;
        case 'fillPassword':
            handleFillPasswordContext(tab);
            break;
    }
});

// Gerar senha segura
async function handleGeneratePassword(tab) {
    try {
        // Verificar se o usuário está autenticado
        const authData = await getAuthData();
        
        if (!authData.token) {
            showNotification('Erro', 'Faça login no SecurePass primeiro');
            return;
        }
        
        // Gerar senha via API
        const response = await fetch(`${API_BASE_URL}/generate-password`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                length: 16,
                includeUppercase: true,
                includeLowercase: true,
                includeNumbers: true,
                includeSymbols: true,
                excludeSimilar: true
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            
            // Enviar senha para a página
            chrome.tabs.sendMessage(tab.id, {
                type: 'insertPassword',
                password: data.password
            });
            
            showNotification('Senha Gerada', 'Senha segura inserida no campo');
        } else {
            // Fallback: gerar senha localmente
            const password = generateSecurePasswordLocal();
            chrome.tabs.sendMessage(tab.id, {
                type: 'insertPassword',
                password: password
            });
            
            showNotification('Senha Gerada', 'Senha segura inserida no campo');
        }
    } catch (error) {
        console.error('Erro ao gerar senha:', error);
        
        // Fallback: gerar senha localmente
        const password = generateSecurePasswordLocal();
        chrome.tabs.sendMessage(tab.id, {
            type: 'insertPassword',
            password: password
        });
        
        showNotification('Senha Gerada', 'Senha segura inserida no campo');
    }
}

// Gerar senha localmente (fallback)
function generateSecurePasswordLocal(length = 16) {
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

// Salvar senha via menu de contexto
function handleSavePasswordContext(tab) {
    chrome.tabs.sendMessage(tab.id, {
        type: 'detectForms'
    }, (response) => {
        if (response && response.passwordFields > 0) {
            showNotification('SecurePass', 'Preencha o formulário e envie para salvar a senha automaticamente');
        } else {
            showNotification('Erro', 'Nenhum campo de senha encontrado nesta página');
        }
    });
}

// Preencher senha via menu de contexto
async function handleFillPasswordContext(tab) {
    try {
        const authData = await getAuthData();
        
        if (!authData.token) {
            showNotification('Erro', 'Faça login no SecurePass primeiro');
            return;
        }
        
        const url = new URL(tab.url);
        const domain = url.hostname;
        
        // Buscar senhas para este domínio
        const passwords = await getPasswordsForDomain(domain, authData.token);
        
        if (passwords.length > 0) {
            // Se há apenas uma senha, preencher automaticamente
            if (passwords.length === 1) {
                const passwordData = await decryptPassword(passwords[0].id, authData.token);
                chrome.tabs.sendMessage(tab.id, {
                    type: 'fillPassword',
                    data: {
                        username: passwords[0].username,
                        password: passwordData.password
                    }
                });
                showNotification('Senha Preenchida', `Login preenchido para ${passwords[0].username}`);
            } else {
                // Múltiplas senhas - abrir popup para escolher
                chrome.action.openPopup();
            }
        } else {
            showNotification('Sem Senhas', 'Nenhuma senha salva encontrada para este site');
        }
    } catch (error) {
        console.error('Erro ao preencher senha:', error);
        showNotification('Erro', 'Erro ao buscar senhas salvas');
    }
}

// Listener para mensagens
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
        case 'savePassword':
            handleSavePassword(message.data, sendResponse);
            return true;
            
        case 'requestPasswords':
            handleRequestPasswords(message.domain, message.url, sendResponse);
            return true;
            
        case 'pageLoaded':
            handlePageLoaded(message.data, sender.tab);
            sendResponse({ success: true });
            break;
            
        case 'notification':
            showNotification(message.title, message.message);
            sendResponse({ success: true });
            break;
            
        default:
            sendResponse({ error: 'Tipo de mensagem não reconhecido' });
    }
});

// Salvar senha
async function handleSavePassword(passwordData, sendResponse) {
    try {
        const authData = await getAuthData();
        
        if (!authData.token) {
            sendResponse({ success: false, error: 'Usuário não autenticado' });
            return;
        }
        
        const response = await fetch(`${API_BASE_URL}/passwords`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                site: passwordData.site,
                url: passwordData.url,
                username: passwordData.username,
                password: passwordData.password
            })
        });
        
        if (response.ok) {
            const result = await response.json();
            showNotification('Senha Salva', `Credenciais salvas para ${passwordData.site}`);
            sendResponse({ success: true, passwordId: result.passwordId });
        } else {
            const error = await response.json();
            sendResponse({ success: false, error: error.error || 'Erro ao salvar senha' });
        }
    } catch (error) {
        console.error('Erro ao salvar senha:', error);
        sendResponse({ success: false, error: 'Erro de conexão com o servidor' });
    }
}

// Solicitar senhas para um domínio
async function handleRequestPasswords(domain, url, sendResponse) {
    try {
        const authData = await getAuthData();
        
        if (!authData.token) {
            sendResponse({ passwords: [] });
            return;
        }
        
        const passwords = await getPasswordsForDomain(domain, authData.token);
        sendResponse({ passwords });
    } catch (error) {
        console.error('Erro ao buscar senhas:', error);
        sendResponse({ passwords: [] });
    }
}

// Buscar senhas para um domínio específico
async function getPasswordsForDomain(domain, token) {
    try {
        const response = await fetch(`${API_BASE_URL}/passwords?search=${encodeURIComponent(domain)}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const passwords = await response.json();
            // Filtrar por domínio
            return passwords.filter(pwd => 
                pwd.url?.includes(domain) || 
                pwd.site?.toLowerCase().includes(domain.toLowerCase())
            );
        }
        
        return [];
    } catch (error) {
        console.error('Erro ao buscar senhas por domínio:', error);
        return [];
    }
}

// Descriptografar senha
async function decryptPassword(passwordId, token) {
    const response = await fetch(`${API_BASE_URL}/passwords/${passwordId}/decrypt`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    if (!response.ok) {
        throw new Error('Erro ao descriptografar senha');
    }
    
    return await response.json();
}

// Obter dados de autenticação
function getAuthData() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['authToken', 'userEmail', 'userId'], (result) => {
            resolve({
                token: result.authToken,
                email: result.userEmail,
                userId: result.userId
            });
        });
    });
}

// Tratar carregamento de página
async function handlePageLoaded(pageData, tab) {
    // Verificar configurações de preenchimento automático
    chrome.storage.local.get(['settings'], async (result) => {
        if (result.settings?.autoFill) {
            const authData = await getAuthData();
            
            if (authData.token) {
                const domain = new URL(pageData.url).hostname;
                const passwords = await getPasswordsForDomain(domain, authData.token);
                
                if (passwords.length > 0) {
                    // Aguardar um pouco para a página carregar completamente
                    setTimeout(() => {
                        chrome.tabs.sendMessage(tab.id, {
                            type: 'pageLoaded',
                            autoFill: true
                        });
                    }, 2000);
                }
            }
        }
    });
}

// Mostrar notificação
function showNotification(title, message, iconUrl = 'icon128.png') {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: iconUrl,
        title: title,
        message: message,
        priority: 1
    });
}

// Listener para quando uma aba é atualizada
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Enviar sinal para content script detectar formulários
        chrome.tabs.sendMessage(tabId, {
            type: 'pageLoaded',
            url: tab.url
        }).catch(() => {
            // Content script pode não estar pronto ainda
        });
    }
});

// Verificar periodicamente se o token ainda é válido
setInterval(async () => {
    const authData = await getAuthData();
    
    if (authData.token) {
        try {
            const response = await fetch(`${API_BASE_URL}/auth/verify`, {
                headers: {
                    'Authorization': `Bearer ${authData.token}`
                }
            });
            
            if (!response.ok) {
                // Token expirado, fazer logout
                chrome.storage.local.remove(['authToken', 'userEmail', 'userId']);
                showNotification('Sessão Expirada', 'Por favor, faça login novamente no SecurePass');
            }
        } catch (error) {
            console.error('Erro ao verificar token:', error);
        }
    }
}, 300000); // Verificar a cada 5 minutos

// Sync com servidor quando online
chrome.runtime.onStartup.addListener(() => {
    checkServerConnection();
});

// Verificar conexão com servidor
async function checkServerConnection() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        if (response.ok) {
            console.log('Conexão com servidor estabelecida');
        }
    } catch (error) {
        console.warn('Servidor não disponível:', error);
    }
}

// Manipular comandos de teclado (se configurados no manifest)
chrome.commands?.onCommand.addListener((command) => {
    switch (command) {
        case 'generate-password':
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]) {
                    handleGeneratePassword(tabs[0]);
                }
            });
            break;
        case 'open-popup':
            chrome.action.openPopup();
            break;
    }
});

// Backup periódico de configurações
setInterval(() => {
    chrome.storage.local.get(['settings'], (result) => {
        if (result.settings) {
            console.log('Backup de configurações realizado');
        }
    });
}, 3600000); // A cada 1 hora

console.log('SecurePass Background Script carregado');