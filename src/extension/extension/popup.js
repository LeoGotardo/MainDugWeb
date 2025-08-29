// Estado da aplicação
let currentUser = null;
let passwords = [];

// Inicialização
document.addEventListener('DOMContentLoaded', () => {
    checkAuthStatus();
    setupTabNavigation();
    setupEventListeners();
    loadSettings();
});

// Verificar status de autenticação
async function checkAuthStatus() {
    chrome.storage.local.get(['authToken', 'userEmail'], (result) => {
        if (result.authToken && result.userEmail) {
            currentUser = { email: result.userEmail, token: result.authToken };
            showAuthenticatedUI();
            loadPasswords();
        } else {
            showUnauthenticatedUI();
        }
    });
}

// Configurar navegação por abas
function setupTabNavigation() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;
            
            // Atualizar abas ativas
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Atualizar conteúdo
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(tabName).classList.add('active');
            
            // Carregar senhas quando abrir a aba
            if (tabName === 'passwords' && currentUser) {
                loadPasswords();
            }
        });
    });
}

// Configurar event listeners
function setupEventListeners() {
    // Login
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('registerBtn').addEventListener('click', handleRegister);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    
    // Busca
    document.getElementById('searchPasswords').addEventListener('input', handleSearch);
    
    // Configurações
    document.getElementById('autoSave').addEventListener('change', saveSettings);
    document.getElementById('autoFill').addEventListener('change', saveSettings);
    document.getElementById('notifications').addEventListener('change', saveSettings);
    document.getElementById('darkMode').addEventListener('change', (e) => {
        saveSettings();
        toggleDarkMode(e.target.checked);
    });
    
    // Exportar dados
    document.getElementById('exportData').addEventListener('click', exportPasswords);
}

// Handler de login
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    showStatus('loginStatus', 'Conectando...', 'info');
    
    try {
        const response = await fetch('http://localhost:5000/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Salvar token e email
            chrome.storage.local.set({
                authToken: data.token,
                userEmail: email,
                userId: data.userId
            });
            
            currentUser = { email, token: data.token };
            showStatus('loginStatus', 'Login realizado com sucesso!', 'success');
            
            setTimeout(() => {
                showAuthenticatedUI();
                document.querySelector('[data-tab="passwords"]').click();
            }, 1000);
        } else {
            showStatus('loginStatus', data.error || 'Erro ao fazer login', 'error');
        }
    } catch (error) {
        showStatus('loginStatus', 'Erro de conexão com o servidor', 'error');
    }
}

// Handler de registro
async function handleRegister() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    if (!email || !password) {
        showStatus('loginStatus', 'Preencha todos os campos', 'error');
        return;
    }
    
    showStatus('loginStatus', 'Criando conta...', 'info');
    
    try {
        const response = await fetch('http://localhost:5000/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showStatus('loginStatus', 'Conta criada com sucesso! Faça login.', 'success');
            document.getElementById('loginForm').reset();
        } else {
            showStatus('loginStatus', data.error || 'Erro ao criar conta', 'error');
        }
    } catch (error) {
        showStatus('loginStatus', 'Erro de conexão com o servidor', 'error');
    }
}

// Handler de logout
function handleLogout() {
    chrome.storage.local.remove(['authToken', 'userEmail', 'userId'], () => {
        currentUser = null;
        passwords = [];
        showUnauthenticatedUI();
        document.querySelector('[data-tab="login"]').click();
    });
}

// Carregar senhas salvas
async function loadPasswords() {
    if (!currentUser) return;
    
    document.getElementById('passwordLoader').style.display = 'block';
    document.getElementById('passwordList').innerHTML = '';
    
    try {
        const response = await fetch('http://localhost:5000/api/passwords', {
            headers: {
                'Authorization': `Bearer ${currentUser.token}`
            }
        });
        
        if (response.ok) {
            passwords = await response.json();
            displayPasswords(passwords);
        } else {
            showEmptyState();
        }
    } catch (error) {
        showEmptyState('Erro ao carregar senhas');
    } finally {
        document.getElementById('passwordLoader').style.display = 'none';
    }
}

// Exibir senhas
function displayPasswords(passwordsToShow) {
    const listElement = document.getElementById('passwordList');
    
    if (passwordsToShow.length === 0) {
        showEmptyState('Nenhuma senha salva ainda');
        return;
    }
    
    listElement.innerHTML = passwordsToShow.map(pwd => `
        <div class="password-item" data-id="${pwd.id}">
            <div class="password-info">
                <div class="password-site">${pwd.site || pwd.url}</div>
                <div class="password-username">${pwd.username}</div>
            </div>
            <div class="password-actions">
                <button class="icon-btn" onclick="copyPassword('${pwd.id}')" title="Copiar senha">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
                    </svg>
                </button>
                <button class="icon-btn" onclick="fillPassword('${pwd.id}')" title="Preencher">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"></path>
                        <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                    </svg>
                </button>
                <button class="icon-btn" onclick="deletePassword('${pwd.id}')" title="Excluir">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"></path>
                    </svg>
                </button>
            </div>
        </div>
    `).join('');
}

// Copiar senha
async function copyPassword(passwordId) {
    const pwd = passwords.find(p => p.id === passwordId);
    if (!pwd) return;
    
    try {
        const response = await fetch(`http://localhost:5000/api/passwords/${passwordId}/decrypt`, {
            headers: {
                'Authorization': `Bearer ${currentUser.token}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            await navigator.clipboard.writeText(data.password);
            showToast('Senha copiada!');
        }
    } catch (error) {
        showToast('Erro ao copiar senha', 'error');
    }
}

// Preencher senha na página ativa
async function fillPassword(passwordId) {
    const pwd = passwords.find(p => p.id === passwordId);
    if (!pwd) return;
    
    try {
        const response = await fetch(`http://localhost:5000/api/passwords/${passwordId}/decrypt`, {
            headers: {
                'Authorization': `Bearer ${currentUser.token}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            
            // Enviar mensagem para a aba ativa
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                chrome.tabs.sendMessage(tabs[0].id, {
                    type: 'fillPassword',
                    data: {
                        username: pwd.username,
                        password: data.password
                    }
                });
            });
            
            // Fechar popup
            window.close();
        }
    } catch (error) {
        showToast('Erro ao preencher senha', 'error');
    }
}

// Deletar senha
async function deletePassword(passwordId) {
    if (!confirm('Tem certeza que deseja excluir esta senha?')) return;
    
    try {
        const response = await fetch(`http://localhost:5000/api/passwords/${passwordId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${currentUser.token}`
            }
        });
        
        if (response.ok) {
            passwords = passwords.filter(p => p.id !== passwordId);
            displayPasswords(passwords);
            showToast('Senha excluída');
        }
    } catch (error) {
        showToast('Erro ao excluir senha', 'error');
    }
}

// Handler de busca
function handleSearch(e) {
    const query = e.target.value.toLowerCase();
    
    if (!query) {
        displayPasswords(passwords);
        return;
    }
    
    const filtered = passwords.filter(pwd => 
        pwd.site?.toLowerCase().includes(query) ||
        pwd.url?.toLowerCase().includes(query) ||
        pwd.username?.toLowerCase().includes(query)
    );
    
    displayPasswords(filtered);
}

// Exportar senhas
async function exportPasswords() {
    if (!currentUser) {
        showToast('Faça login primeiro', 'error');
        return;
    }
    
    try {
        const response = await fetch('http://localhost:5000/api/passwords/export', {
            headers: {
                'Authorization': `Bearer ${currentUser.token}`
            }
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `passwords_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
            showToast('Senhas exportadas com sucesso');
        }
    } catch (error) {
        showToast('Erro ao exportar senhas', 'error');
    }
}

// Carregar configurações
function loadSettings() {
    chrome.storage.local.get(['settings'], (result) => {
        const settings = result.settings || {
            autoSave: true,
            autoFill: true,
            notifications: true,
            darkMode: false
        };
        
        document.getElementById('autoSave').checked = settings.autoSave;
        document.getElementById('autoFill').checked = settings.autoFill;
        document.getElementById('notifications').checked = settings.notifications;
        document.getElementById('darkMode').checked = settings.darkMode;
        
        if (settings.darkMode) {
            toggleDarkMode(true);
        }
    });
}

// Salvar configurações
function saveSettings() {
    const settings = {
        autoSave: document.getElementById('autoSave').checked,
        autoFill: document.getElementById('autoFill').checked,
        notifications: document.getElementById('notifications').checked,
        darkMode: document.getElementById('darkMode').checked
    };
    
    chrome.storage.