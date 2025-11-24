// ==========================================
// POPUP.JS - MainDug Extension
// ==========================================

// Estado global
let currentUser = null;
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
    const stored = await chrome.storage.local.get(['currentUser']);
    
    if (stored.currentUser) {
        currentUser = stored.currentUser;
        showMainInterface();
        await loadPasswords();
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
        // Buscar usuários salvos
        const stored = await chrome.storage.local.get(['users']);
        const users = stored.users || [];
        
        // Verificar credenciais
        const user = users.find(u => u.email === email);
        
        if (user && await verifyPassword(password, user.passwordHash)) {
            currentUser = {
                email: user.email,
                name: user.name || email.split('@')[0]
            };
            
            await chrome.storage.local.set({ currentUser });
            
            showMainInterface();
            await loadPasswords();
            showToast('Login realizado com sucesso!');
        } else {
            showStatus('loginStatus', 'Email ou senha incorretos.', 'error');
        }
    } catch (error) {
        console.error('Erro no login:', error);
        showStatus('loginStatus', 'Erro ao fazer login.', 'error');
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
        const stored = await chrome.storage.local.get(['users']);
        const users = stored.users || [];
        
        // Verificar se usuário já existe
        if (users.find(u => u.email === email)) {
            showStatus('loginStatus', 'Este email já está cadastrado.', 'error');
            return;
        }
        
        // Criar novo usuário
        const newUser = {
            email,
            name: email.split('@')[0],
            passwordHash: await hashPassword(password),
            createdAt: new Date().toISOString()
        };
        
        users.push(newUser);
        await chrome.storage.local.set({ users });
        
        // Fazer login automático
        currentUser = {
            email: newUser.email,
            name: newUser.name
        };
        
        await chrome.storage.local.set({ currentUser });
        
        showMainInterface();
        showToast('Conta criada com sucesso!');
    } catch (error) {
        console.error('Erro no registro:', error);
        showStatus('loginStatus', 'Erro ao criar conta.', 'error');
    }
}

async function handleLogout() {
    await chrome.storage.local.remove('currentUser');
    currentUser = null;
    allPasswords = [];
    showLoginInterface();
    showToast('Você saiu da sua conta.');
}

// ==========================================
// GERENCIAMENTO DE SENHAS
// ==========================================

async function loadPasswords() {
    if (!currentUser) return;
    
    const loader = document.getElementById('passwordLoader');
    const emptyState = document.getElementById('emptyState');
    
    loader.style.display = 'block';
    
    try {
        const stored = await chrome.storage.local.get(['passwords']);
        const allStoredPasswords = stored.passwords || [];
        
        // Filtrar senhas do usuário atual
        allPasswords = allStoredPasswords.filter(p => p.userEmail === currentUser.email);
        
        renderPasswords(allPasswords);
        
        if (allPasswords.length === 0) {
            emptyState.style.display = 'block';
        } else {
            emptyState.style.display = 'none';
        }
    } catch (error) {
        console.error('Erro ao carregar senhas:', error);
        showToast('Erro ao carregar senhas.');
    } finally {
        loader.style.display = 'none';
    }
}

function renderPasswords(passwords) {
    const passwordList = document.getElementById('passwordList');
    passwordList.innerHTML = '';
    
    passwords.forEach((pwd, index) => {
        const item = document.createElement('div');
        item.className = 'password-item';
        item.innerHTML = `
            <div class="password-info">
                <span class="site-name">${escapeHtml(pwd.site)}</span>
                <span class="username">${escapeHtml(pwd.username)}</span>
            </div>
            <button class="copy-btn" title="Copiar senha" data-index="${index}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
            </button>
        `;
        
        item.querySelector('.copy-btn').addEventListener('click', async (e) => {
            e.stopPropagation();
            await copyPassword(index);
        });
        
        item.addEventListener('click', () => fillPassword(index));
        
        passwordList.appendChild(item);
    });
}

async function savePassword(site, username, password) {
    if (!currentUser) return;
    
    try {
        const stored = await chrome.storage.local.get(['passwords']);
        const passwords = stored.passwords || [];
        
        // Verificar se já existe
        const existingIndex = passwords.findIndex(p => 
            p.userEmail === currentUser.email && 
            p.site === site && 
            p.username === username
        );
        
        const encryptedPassword = await encryptPassword(password);
        
        const passwordData = {
            userEmail: currentUser.email,
            site,
            username,
            password: encryptedPassword,
            createdAt: new Date().toISOString()
        };
        
        if (existingIndex >= 0) {
            passwords[existingIndex] = passwordData;
        } else {
            passwords.push(passwordData);
        }
        
        await chrome.storage.local.set({ passwords });
        await loadPasswords();
        
        showToast('Senha salva com sucesso!');
    } catch (error) {
        console.error('Erro ao salvar senha:', error);
        showToast('Erro ao salvar senha.');
    }
}

async function copyPassword(index) {
    if (!allPasswords[index]) return;
    
    try {
        const decryptedPassword = await decryptPassword(allPasswords[index].password);
        await navigator.clipboard.writeText(decryptedPassword);
        showToast('Senha copiada!');
    } catch (error) {
        console.error('Erro ao copiar senha:', error);
        showToast('Erro ao copiar senha.');
    }
}

async function fillPassword(index) {
    if (!allPasswords[index]) return;
    
    try {
        const password = allPasswords[index];
        const decryptedPassword = await decryptPassword(password.password);
        
        // Enviar mensagem para content script
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        await chrome.tabs.sendMessage(tab.id, {
            type: 'fillPassword',
            data: {
                username: password.username,
                password: decryptedPassword
            }
        });
        
        showToast('Formulário preenchido!');
        window.close();
    } catch (error) {
        console.error('Erro ao preencher:', error);
        showToast('Erro ao preencher formulário.');
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
    if (!currentUser) return;
    
    try {
        let csv = 'Site,Usuário,Senha\n';
        
        for (const pwd of allPasswords) {
            const decryptedPassword = await decryptPassword(pwd.password);
            csv += `"${pwd.site}","${pwd.username}","${decryptedPassword}"\n`;
        }
        
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        
        await chrome.downloads.download({
            url: url,
            filename: 'maindug-passwords.csv',
            saveAs: true
        });
        
        showToast('Dados exportados com sucesso!');
    } catch (error) {
        console.error('Erro ao exportar:', error);
        showToast('Erro ao exportar dados.');
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
// UTILITÁRIOS DE SEGURANÇA
// ==========================================

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function verifyPassword(password, hash) {
    const passwordHash = await hashPassword(password);
    return passwordHash === hash;
}

async function encryptPassword(password) {
    // Implementação simplificada - em produção, usar AES-256
    return btoa(password);
}

async function decryptPassword(encryptedPassword) {
    // Implementação simplificada - em produção, usar AES-256
    return atob(encryptedPassword);
}

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
        if (settings.autoSave && currentUser) {
            savePassword(message.site, message.username, message.password);
        }
    }
    
    sendResponse({ success: true });
    return true;
});