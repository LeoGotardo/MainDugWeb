// content.js - Script de conteúdo para detecção e preenchimento automático

// Variáveis globais
let passwordFields = [];
let usernameFields = [];
let loginForms = [];
let isDetectionEnabled = true;
let autoFillEnabled = true;
let autoSaveEnabled = true;

// Inicialização quando a página carrega
document.addEventListener('DOMContentLoaded', initializeContentScript);

// Se a página já estiver carregada
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeContentScript);
} else {
    initializeContentScript();
}

// Inicializar o script de conteúdo
function initializeContentScript() {
    console.log('SecurePass Content Script iniciado');
    
    // Carregar configurações
    loadExtensionSettings();
    
    // Detectar formulários de login
    detectLoginForms();
    
    // Observar mudanças no DOM
    setupDOMObserver();
    
    // Configurar listeners para formulários
    setupFormListeners();
    
    // Notificar background script sobre a página
    notifyPageLoad();
}

// Carregar configurações da extensão
function loadExtensionSettings() {
    chrome.storage.local.get(['settings'], (result) => {
        if (result.settings) {
            autoFillEnabled = result.settings.autoFill;
            autoSaveEnabled = result.settings.autoSave;
        }
    });
}

// Detectar formulários de login na página
function detectLoginForms() {
    // Limpar arrays anteriores
    passwordFields = [];
    usernameFields = [];
    loginForms = [];
    
    // Buscar campos de senha
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordFields = Array.from(passwordInputs);
    
    // Buscar campos de usuário (email, text, etc.)
    const usernameSelectors = [
        'input[type="email"]',
        'input[type="text"][name*="email"]',
        'input[type="text"][name*="user"]',
        'input[type="text"][name*="login"]',
        'input[type="text"][id*="email"]',
        'input[type="text"][id*="user"]',
        'input[type="text"][id*="login"]',
        'input[type="text"][placeholder*="email"]',
        'input[type="text"][placeholder*="usuário"]',
        'input[type="text"][placeholder*="user"]',
        'input[autocomplete="username"]',
        'input[autocomplete="email"]'
    ];
    
    usernameSelectors.forEach(selector => {
        const inputs = document.querySelectorAll(selector);
        inputs.forEach(input => {
            if (!usernameFields.includes(input)) {
                usernameFields.push(input);
            }
        });
    });
    
    // Detectar formulários de login
    passwordFields.forEach(passwordField => {
        const form = passwordField.closest('form');
        if (form && !loginForms.includes(form)) {
            loginForms.push(form);
        }
    });
    
    // Se há campos de senha, tentar preenchimento automático
    if (passwordFields.length > 0 && autoFillEnabled) {
        requestAutoFill();
    }
    
    console.log(`Detectados: ${passwordFields.length} campos de senha, ${usernameFields.length} campos de usuário`);
}

// Solicitar preenchimento automático
async function requestAutoFill() {
    try {
        const currentUrl = window.location.href;
        const domain = new URL(currentUrl).hostname;
        
        // Verificar se há senhas salvas para este domínio
        chrome.runtime.sendMessage({
            type: 'requestPasswords',
            domain: domain,
            url: currentUrl
        }, (response) => {
            if (response && response.passwords && response.passwords.length > 0) {
                showAutoFillSuggestion(response.passwords[0]);
            }
        });
    } catch (error) {
        console.error('Erro ao solicitar preenchimento automático:', error);
    }
}

// Mostrar sugestão de preenchimento automático
function showAutoFillSuggestion(passwordData) {
    // Criar popup de sugestão
    const suggestion = createAutoFillSuggestion(passwordData);
    document.body.appendChild(suggestion);
    
    // Remover após 10 segundos se não for clicado
    setTimeout(() => {
        if (suggestion.parentNode) {
            suggestion.remove();
        }
    }, 10000);
}

// Criar elemento de sugestão de preenchimento
function createAutoFillSuggestion(passwordData) {
    const container = document.createElement('div');
    container.id = 'securepass-autofill-suggestion';
    container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #667eea;
        color: white;
        padding: 15px 20px;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        max-width: 300px;
        animation: slideIn 0.3s ease-out;
    `;
    
    container.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="10" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0110 0v4"></path>
            </svg>
            <strong>SecurePass</strong>
        </div>
        <p style="margin: 0 0 15px 0;">Preencher login para <strong>${passwordData.site}</strong>?</p>
        <div style="display: flex; gap: 10px;">
            <button id="autofill-yes" style="
                background: white;
                color: #667eea;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 600;
                font-size: 13px;
            ">Preencher</button>
            <button id="autofill-no" style="
                background: rgba(255,255,255,0.2);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 13px;
            ">Não</button>
        </div>
    `;
    
    // Event listeners
    container.querySelector('#autofill-yes').addEventListener('click', () => {
        fillLoginForm(passwordData);
        container.remove();
    });
    
    container.querySelector('#autofill-no').addEventListener('click', () => {
        container.remove();
    });
    
    // Adicionar animação CSS
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    `;
    document.head.appendChild(style);
    
    return container;
}

// Preencher formulário de login
function fillLoginForm(passwordData) {
    // Preencher campo de usuário
    if (usernameFields.length > 0 && passwordData.username) {
        const usernameField = usernameFields[0];
        usernameField.value = passwordData.username;
        usernameField.dispatchEvent(new Event('input', { bubbles: true }));
        usernameField.dispatchEvent(new Event('change', { bubbles: true }));
    }
    
    // Preencher campo de senha
    if (passwordFields.length > 0 && passwordData.password) {
        const passwordField = passwordFields[0];
        passwordField.value = passwordData.password;
        passwordField.dispatchEvent(new Event('input', { bubbles: true }));
        passwordField.dispatchEvent(new Event('change', { bubbles: true }));
    }
    
    console.log('Formulário preenchido automaticamente');
}

// Configurar observador de mudanças no DOM
function setupDOMObserver() {
    const observer = new MutationObserver((mutations) => {
        let shouldRedetect = false;
        
        mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        if (node.matches('input[type="password"]') || 
                            node.querySelector('input[type="password"]')) {
                            shouldRedetect = true;
                        }
                    }
                });
            }
        });
        
        if (shouldRedetect) {
            setTimeout(detectLoginForms, 1000);
        }
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

// Configurar listeners para formulários
function setupFormListeners() {
    // Listener para envio de formulários
    document.addEventListener('submit', handleFormSubmit);
    
    // Listener para foco em campos de senha
    document.addEventListener('focusin', (e) => {
        if (e.target.type === 'password') {
            highlightPasswordField(e.target);
        }
    });
}

// Destacar campo de senha quando focado
function highlightPasswordField(field) {
    if (!autoSaveEnabled) return;
    
    const originalOutline = field.style.outline;
    field.style.outline = '2px solid #667eea';
    
    field.addEventListener('blur', () => {
        field.style.outline = originalOutline;
    }, { once: true });
}

// Manipular envio de formulário
function handleFormSubmit(e) {
    if (!autoSaveEnabled) return;
    
    const form = e.target;
    const passwordField = form.querySelector('input[type="password"]');
    
    if (!passwordField || !passwordField.value) return;
    
    // Buscar campo de usuário no formulário
    const usernameField = findUsernameField(form);
    
    if (usernameField && usernameField.value) {
        const loginData = {
            url: window.location.href,
            domain: window.location.hostname,
            username: usernameField.value,
            password: passwordField.value,
            site: document.title || window.location.hostname
        };
        
        // Aguardar um pouco para ver se o login foi bem-sucedido
        setTimeout(() => {
            if (shouldOfferToSave()) {
                showSavePasswordPrompt(loginData);
            }
        }, 2000);
    }
}

// Encontrar campo de usuário em um formulário
function findUsernameField(form) {
    const selectors = [
        'input[type="email"]',
        'input[type="text"]',
        'input[autocomplete="username"]',
        'input[autocomplete="email"]'
    ];
    
    for (const selector of selectors) {
        const field = form.querySelector(selector);
        if (field && field.value) {
            return field;
        }
    }
    
    return null;
}

// Verificar se deve oferecer para salvar
function shouldOfferToSave() {
    // Verificar se a página mudou (indicando login bem-sucedido)
    const currentUrl = window.location.href;
    
    // Se a URL mudou ou se não há mais campos de senha visíveis
    const visiblePasswordFields = document.querySelectorAll('input[type="password"]:not([style*="display: none"])');
    
    return visiblePasswordFields.length === 0 || currentUrl !== window.location.href;
}

// Mostrar prompt para salvar senha
function showSavePasswordPrompt(loginData) {
    // Verificar se já existe um prompt
    if (document.getElementById('securepass-save-prompt')) return;
    
    const prompt = createSavePasswordPrompt(loginData);
    document.body.appendChild(prompt);
}

// Criar prompt para salvar senha
function createSavePasswordPrompt(loginData) {
    const container = document.createElement('div');
    container.id = 'securepass-save-prompt';
    container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: white;
        border: 2px solid #667eea;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        max-width: 320px;
        animation: slideIn 0.3s ease-out;
    `;
    
    container.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="#667eea" stroke="#667eea" stroke-width="2">
                <rect x="3" y="11" width="18" height="10" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0110 0v4"></path>
            </svg>
            <strong style="color: #667eea;">SecurePass</strong>
        </div>
        <p style="margin: 0 0 5px 0; color: #333; font-weight: 500;">Salvar esta senha?</p>
        <p style="margin: 0 0 15px 0; color: #666; font-size: 13px;">
            Site: <strong>${loginData.site}</strong><br>
            Usuário: <strong>${loginData.username}</strong>
        </p>
        <div style="display: flex; gap: 10px;">
            <button id="save-password-yes" style="
                background: #667eea;
                color: white;
                border: none;
                padding: 10px 16px;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                font-size: 13px;
                flex: 1;
            ">Salvar</button>
            <button id="save-password-no" style="
                background: #f0f0f0;
                color: #666;
                border: none;
                padding: 10px 16px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 13px;
                flex: 1;
            ">Não</button>
        </div>
        <button id="save-password-close" style="
            position: absolute;
            top: 10px;
            right: 10px;
            background: none;
            border: none;
            color: #999;
            cursor: pointer;
            font-size: 18px;
            line-height: 1;
        ">×</button>
    `;
    
    // Event listeners
    container.querySelector('#save-password-yes').addEventListener('click', () => {
        savePasswordToExtension(loginData);
        container.remove();
    });
    
    container.querySelector('#save-password-no').addEventListener('click', () => {
        container.remove();
    });
    
    container.querySelector('#save-password-close').addEventListener('click', () => {
        container.remove();
    });
    
    // Remover automaticamente após 15 segundos
    setTimeout(() => {
        if (container.parentNode) {
            container.remove();
        }
    }, 15000);
    
    return container;
}

// Salvar senha na extensão
function savePasswordToExtension(loginData) {
    chrome.runtime.sendMessage({
        type: 'savePassword',
        data: loginData
    }, (response) => {
        if (response && response.success) {
            showSuccessMessage('Senha salva com sucesso!');
        } else {
            showErrorMessage('Erro ao salvar senha');
        }
    });
}

// Mostrar mensagem de sucesso
function showSuccessMessage(message) {
    showTemporaryMessage(message, '#28a745');
}

// Mostrar mensagem de erro
function showErrorMessage(message) {
    showTemporaryMessage(message, '#dc3545');
}

// Mostrar mensagem temporária
function showTemporaryMessage(message, backgroundColor) {
    const messageEl = document.createElement('div');
    messageEl.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${backgroundColor};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        font-weight: 500;
        z-index: 999999;
        animation: slideIn 0.3s ease-out;
    `;
    messageEl.textContent = message;
    
    document.body.appendChild(messageEl);
    
    setTimeout(() => {
        messageEl.remove();
    }, 3000);
}

// Notificar background script sobre carregamento da página
function notifyPageLoad() {
    const currentUrl = window.location.href;
    chrome.runtime.sendMessage({
        type: 'pageLoaded',
        data: { 
            url: currentUrl,
            domain: window.location.hostname,
            title: document.title
        }
    });
}

// Listener para mensagens do background script e popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
        case 'fillPassword':
            fillLoginForm(message.data);
            sendResponse({ success: true });
            break;
            
        case 'insertPassword':
            insertGeneratedPassword(message.password);
            sendResponse({ success: true });
            break;
            
        case 'copyToClipboard':
            copyToClipboard(message.text);
            sendResponse({ success: true });
            break;
            
        case 'detectForms':
            detectLoginForms();
            sendResponse({ 
                passwordFields: passwordFields.length,
                usernameFields: usernameFields.length,
                forms: loginForms.length
            });
            break;
            
        case 'pageLoaded':
            if (autoFillEnabled) {
                requestAutoFill();
            }
            sendResponse({ success: true });
            break;
            
        default:
            sendResponse({ error: 'Tipo de mensagem não reconhecido' });
    }
    
    return true; // Manter conexão assíncrona
});

// Inserir senha gerada em campo focado
function insertGeneratedPassword(password) {
    const activeElement = document.activeElement;
    
    if (activeElement && (activeElement.type === 'password' || activeElement.type === 'text')) {
        activeElement.value = password;
        activeElement.dispatchEvent(new Event('input', { bubbles: true }));
        activeElement.dispatchEvent(new Event('change', { bubbles: true }));
        
        showSuccessMessage('Senha inserida!');
    } else if (passwordFields.length > 0) {
        // Se não há campo focado, usar o primeiro campo de senha encontrado
        const passwordField = passwordFields[0];
        passwordField.value = password;
        passwordField.dispatchEvent(new Event('input', { bubbles: true }));
        passwordField.dispatchEvent(new Event('change', { bubbles: true }));
        passwordField.focus();
        
        showSuccessMessage('Senha inserida!');
    }
}

// Copiar texto para área de transferência
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showSuccessMessage('Copiado para área de transferência!');
    } catch (error) {
        // Fallback para navegadores mais antigos
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        showSuccessMessage('Copiado para área de transferência!');
    }
}

// Detectar mudanças de URL (para SPAs)
let currentUrl = window.location.href;
const urlObserver = new MutationObserver(() => {
    if (window.location.href !== currentUrl) {
        currentUrl = window.location.href;
        
        // Re-detectar formulários na nova página
        setTimeout(() => {
            detectLoginForms();
            notifyPageLoad();
        }, 1000);
    }
});

urlObserver.observe(document.body, {
    childList: true,
    subtree: true
});

// Listener para mudanças de estado do histórico (navegação SPA)
window.addEventListener('popstate', () => {
    setTimeout(() => {
        detectLoginForms();
        notifyPageLoad();
    }, 1000);
});

// Listener para pushState e replaceState (navegação SPA)
const originalPushState = history.pushState;
const originalReplaceState = history.replaceState;

history.pushState = function() {
    originalPushState.apply(history, arguments);
    setTimeout(() => {
        detectLoginForms();
        notifyPageLoad();
    }, 1000);
};

history.replaceState = function() {
    originalReplaceState.apply(history, arguments);
    setTimeout(() => {
        detectLoginForms();
        notifyPageLoad();
    }, 1000);
};

// Cleanup quando a página é descarregada
window.addEventListener('beforeunload', () => {
    // Remover qualquer prompt ativo
    const savePrompt = document.getElementById('securepass-save-prompt');
    const autofillSuggestion = document.getElementById('securepass-autofill-suggestion');
    
    if (savePrompt) savePrompt.remove();
    if (autofillSuggestion) autofillSuggestion.remove();
});

// Debug: expor funções para teste no console (apenas em desenvolvimento)
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    window.SecurePassDebug = {
        detectForms: detectLoginForms,
        getPasswordFields: () => passwordFields,
        getUsernameFields: () => usernameFields,
        getForms: () => loginForms,
        testAutoFill: () => requestAutoFill()
    };
    
    console.log('SecurePass Debug mode ativo. Use window.SecurePassDebug para testar.');
}