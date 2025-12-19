// ==========================================
// POPUP.JS - MainDug Extension (API Integrado)
// ==========================================

// Configuração da API
const API_BASE_URL = 'http://localhost:5000/api';

// Estado global
let currentUser = null;
let authToken = null;
let allPasswords = [];
let settings = {
    autoFill: true,
    autoSave: true,
    notifications: true,
    darkMode: false
};

// ==========================================
// INICIALIZAÇÃO
// ==========================================

document.addEventListener('DOMContentLoaded', async function() {
    await loadSettings();
    await checkAuth();
    setupEventListeners();
    applyTheme();
});

// ==========================================
// AUTENTICAÇÃO
// ==========================================

async function checkAuth() {
    const stored = await chrome.storage.local.get(['authToken', 'currentUser']);
    
    if (stored.authToken && stored.currentUser) {
        authToken = stored.authToken;
        currentUser = stored.currentUser;
        
        // Verificar se token ainda é válido
        try {
            const response = await fetch(`${API_BASE_URL}/auth/verify`, {
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
            
            if (response.ok) {
                showMainInterface();
                await loadPasswords();
            } else {
                await handleLogout();
            }
        } catch (error) {
            console.error('Erro ao verificar token:', error);
            await handleLogout();
        }
    } else {
        showLoginInterface();
    }
}

async function handleLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!email || !password) {
        showStatus('loginStatus', 'Por favor, preencha todos os campos.', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.token;
            currentUser = {
                userId: data.userId,
                email: data.user.email,
                name: data.user.name
            };
            
            await chrome.storage.local.set({ authToken, currentUser });
            
            showMainInterface();
            await loadPasswords();
            showToast('Login realizado com sucesso!');
        } else {
            showStatus('loginStatus', data.error || 'Erro ao fazer login', 'error');
        }
    } catch (error) {
        console.error('Erro no login:', error);
        showStatus('loginStatus', 'Erro de conexão com o servidor', 'error');
    }
}

async function handleRegister() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!email || !password) {
        showStatus('loginStatus', 'Por favor, preencha todos os campos.', 'error');
        return;
    }
    
    if (password.length < 6) {
        showStatus('loginStatus', 'A senha deve ter pelo menos 6 caracteres.', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                email, 
                password,
                name: email.split('@')[0]
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showStatus('loginStatus', 'Conta criada! Fazendo login...', 'success');
            
            // Fazer login automático
            setTimeout(() => {
                document.getElementById('loginForm').dispatchEvent(new Event('submit'));
            }, 1000);
        } else {
            showStatus('loginStatus', data.error || 'Erro ao criar conta', 'error');
        }
    } catch (error) {
        console.error('Erro no registro:', error);
        showStatus('loginStatus', 'Erro de conexão com o servidor', 'error');
    }
}

async function handleLogout() {
    try {
        if (authToken) {
            await fetch(`${API_BASE_URL}/auth/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
        }
    } catch (error) {
        console.error('Erro ao fazer logout:', error);
    }
    
    await chrome.storage.local.remove(['authToken', 'currentUser']);
    authToken = null;
    currentUser = null;
    allPasswords = [];
    showLoginInterface();
    showToast('Você saiu da sua conta.');
}

// ==========================================
// GERENCIAMENTO DE SENHAS
// ==========================================

async function loadPasswords() {
    if (!currentUser || !authToken) return;
    
    const loader = document.getElementById('passwordLoader');
    const emptyState = document.getElementById('emptyState');
    
    loader.style.display = 'block';
    
    try {
        const response = await fetch(`${API_BASE_URL}/passwords`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            allPasswords = await response.json();
            renderPasswords(allPasswords);
            
            if (allPasswords.length === 0) {
                emptyState.style.display = 'block';
            } else {
                emptyState.style.display = 'none';
            }
        } else {
            showToast('Erro ao carregar senhas');
        }
    } catch (error) {
        console.error('Erro ao carregar senhas:', error);
        showToast('Erro de conexão ao carregar senhas');
    } finally {
        loader.style.display = 'none';
    }
}

function renderPasswords(passwords) {
    const passwordList = document.getElementById('passwordList');
    passwordList.innerHTML = '';
    
    passwords.forEach((pwd) => {
        const item = document.createElement('div');
        item.className = 'password-item';
        item.innerHTML = `
            <div class="password-info">
                <span class="site-name">${escapeHtml(pwd.site)}</span>
                <span class="username">${escapeHtml(pwd.username)}</span>
            </div>
            <button class="copy-btn" title="Copiar senha" data-id="${pwd.id}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
            </button>
        `;
        
        item.querySelector('.copy-btn').addEventListener('click', async (e) => {
            e.stopPropagation();
            await copyPassword(pwd.id);
        });
        
        item.addEventListener('click', () => fillPassword(pwd.id));
        
        passwordList.appendChild(item);
    });
}

async function savePassword(site, username, password, url = null) {
    if (!currentUser || !authToken) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/passwords`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                site,
                username,
                password,
                url
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            await loadPasswords();
            showToast('Senha salva com sucesso!');
            return true;
        } else {
            showToast(data.error || 'Erro ao salvar senha');
            return false;
        }
    } catch (error) {
        console.error('Erro ao salvar senha:', error);
        showToast('Erro de conexão ao salvar senha');
        return false;
    }
}

async function copyPassword(passwordId) {
    if (!authToken) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/passwords/${passwordId}/decrypt`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            await navigator.clipboard.writeText(data.password);
            showToast('Senha copiada!');
        } else {
            showToast('Erro ao descriptografar senha');
        }
    } catch (error) {
        console.error('Erro ao copiar senha:', error);
        showToast('Erro ao copiar senha');
    }
}

async function fillPassword(passwordId) {
    if (!authToken) return;
    
    try {
        const pwd = allPasswords.find(p => p.id === passwordId);
        if (!pwd) return;
        
        const response = await fetch(`${API_BASE_URL}/passwords/${passwordId}/decrypt`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            
            // Enviar mensagem para content script
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            await chrome.tabs.sendMessage(tab.id, {
                type: 'fillPassword',
                data: {
                    username: pwd.username,
                    password: data.password
                }
            });
            
            showToast('Formulário preenchido!');
            window.close();
        } else {
            showToast('Erro ao descriptografar senha');
        }
    } catch (error) {
        console.error('Erro ao preencher:', error);
        showToast('Erro ao preencher formulário');
    }
}

async function deletePassword(passwordId) {
    if (!authToken) return;
    
    if (!confirm('Tem certeza que deseja excluir esta senha?')) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/passwords/${passwordId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            await loadPasswords();
            showToast('Senha excluída');
        } else {
            showToast('Erro ao excluir senha');
        }
    } catch (error) {
        console.error('Erro ao excluir:', error);
        showToast('Erro ao excluir senha');
    }
}

// ==========================================
// BUSCA
// ==========================================

function setupSearch() {
    const searchInput = document.getElementById('searchPasswords');
    
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        
        const filtered = allPasswords.filter(pwd => 
            pwd.site.toLowerCase().includes(searchTerm) || 
            pwd.username.toLowerCase().includes(searchTerm)
        );
        
        renderPasswords(filtered);
    });
}

// ==========================================
// CONFIGURAÇÕES
// ==========================================

async function loadSettings() {
    const stored = await chrome.storage.local.get(['settings']);
    if (stored.settings) {
        settings = { ...settings, ...stored.settings };
    }
    
    // Aplicar configurações aos elementos
    document.getElementById('autoFill').checked = settings.autoFill;
    document.getElementById('autoSave').checked = settings.autoSave;
    document.getElementById('notifications').checked = settings.notifications;
    document.getElementById('darkMode').checked = settings.darkMode;
}

async function saveSettings() {
    await chrome.storage.local.set({ settings });
}

function setupSettings() {
    // Auto Fill
    document.getElementById('autoFill').addEventListener('change', async (e) => {
        settings.autoFill = e.target.checked;
        await saveSettings();
        showToast(e.target.checked ? 'Preenchimento automático ativado' : 'Preenchimento automático desativado');
    });
    
    // Auto Save
    document.getElementById('autoSave').addEventListener('change', async (e) => {
        settings.autoSave = e.target.checked;
        await saveSettings();
        showToast(e.target.checked ? 'Salvamento automático ativado' : 'Salvamento automático desativado');
    });
    
    // Notifications
    document.getElementById('notifications').addEventListener('change', async (e) => {
        settings.notifications = e.target.checked;
        await saveSettings();
        showToast(e.target.checked ? 'Notificações ativadas' : 'Notificações desativadas');
    });
    
    // Dark Mode
    document.getElementById('darkMode').addEventListener('change', async (e) => {
        settings.darkMode = e.target.checked;
        await saveSettings();
        applyTheme();
        showToast(e.target.checked ? 'Modo escuro ativado' : 'Modo claro ativado');
    });
}

function applyTheme() {
    if (settings.darkMode) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
}

// ==========================================
// EXPORTAR DADOS
// ==========================================

async function exportData() {
    if (!authToken) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/passwords/export/csv`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            
            await chrome.downloads.download({
                url: url,
                filename: 'maindug-passwords.csv',
                saveAs: true
            });
            
            showToast('Dados exportados com sucesso!');
        } else {
            showToast('Erro ao exportar dados');
        }
    } catch (error) {
        console.error('Erro ao exportar:', error);
        showToast('Erro ao exportar dados');
    }
}

// ==========================================
// NAVEGAÇÃO DE ABAS
// ==========================================

function setupTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.dataset.tab;
            
            // Remove active de todas
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            // Adiciona active na clicada
            tab.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });
}

// ==========================================
// UI
// ==========================================

function showLoginInterface() {
    document.getElementById('mainHeader').style.display = 'none';
    document.getElementById('mainNav').style.display = 'none';
    
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('login').classList.add('active');
}

function showMainInterface() {
    document.getElementById('mainHeader').style.display = 'flex';
    document.getElementById('mainNav').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'flex';
    document.getElementById('userEmail').textContent = currentUser.email;
    document.getElementById('accountEmail').textContent = currentUser.email;
    
    // Atualizar foto de perfil
    const name = currentUser.name || currentUser.email.split('@')[0];
    document.getElementById('profilePic').src = 
        `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=667eea&color=fff&size=160`;
    
    // Mudar para aba de senhas
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    document.querySelector('[data-tab="passwords"]').classList.add('active');
    document.getElementById('passwords').classList.add('active');
}

function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function showStatus(elementId, message, type) {
    const statusEl = document.getElementById(elementId);
    statusEl.textContent = message;
    statusEl.className = `status-message ${type}`;
    statusEl.style.display = 'block';
    
    setTimeout(() => {
        statusEl.style.display = 'none';
    }, 5000);
}

// ==========================================
// LISTENERS
// ==========================================

function setupEventListeners() {
    // Login
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('registerBtn').addEventListener('click', handleRegister);
    
    // Logout
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    document.getElementById('logoutAccountBtn').addEventListener('click', handleLogout);
    
    // Busca
    setupSearch();
    
    // Abas
    setupTabs();
    
    // Configurações
    setupSettings();
    
    // Exportar
    document.getElementById('exportData').addEventListener('click', exportData);
}

// ==========================================
// UTILITÁRIOS
// ==========================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==========================================
// MENSAGENS DO BACKGROUND
// ==========================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'passwordDetected') {
        if (settings.autoSave && currentUser && authToken) {
            savePassword(message.site, message.username, message.password, message.url);
        }
    }
    
    sendResponse({ success: true });
    return true;
});