// Dados mockados do usuário
const userData = {
    email: 'maria.silva@email.com',
    name: 'Maria Silva'
};

// Credenciais mockadas
const mockPasswords = [
    { site: 'google.com', username: 'maria.silva@gmail.com', password: '••••••••' },
    { site: 'facebook.com', username: 'maria.silva', password: '••••••••' },
    { site: 'instagram.com', username: '@maria_silva', password: '••••••••' },
    { site: 'linkedin.com', username: 'maria.silva@email.com', password: '••••••••' },
    { site: 'netflix.com', username: 'maria.silva@email.com', password: '••••••••' },
    { site: 'amazon.com', username: 'maria.silva123', password: '••••••••' },
    { site: 'github.com', username: 'mariasilva', password: '••••••••' }
];

let allPasswords = [...mockPasswords];

// Função para mostrar toast
function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Função para renderizar a lista de senhas
function renderPasswords(passwords) {
    const passwordList = document.getElementById('passwordList');
    const emptyState = document.getElementById('emptyState');
    
    passwordList.innerHTML = '';
    
    if (passwords.length === 0) {
        emptyState.style.display = 'block';
        return;
    }
    
    emptyState.style.display = 'none';
    
    passwords.forEach((pwd, index) => {
        const item = document.createElement('div');
        item.className = 'password-item';
        item.innerHTML = `
            <div class="password-info">
                <span class="site-name">${pwd.site}</span>
                <span class="username">${pwd.username}</span>
            </div>
            <button class="copy-btn" title="Copiar senha" data-index="${index}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
            </button>
        `;
        passwordList.appendChild(item);
    });

    // Adicionar eventos de clique aos botões de copiar
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            showToast('Senha copiada para a área de transferência!');
        });
    });
}

// Busca de senhas
document.getElementById('searchPasswords').addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    const filtered = allPasswords.filter(pwd => 
        pwd.site.toLowerCase().includes(searchTerm) || 
        pwd.username.toLowerCase().includes(searchTerm)
    );
    renderPasswords(filtered);
});

// Sistema de navegação por abas
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        
        // Remove active de todas as abas
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        // Adiciona active na aba clicada
        tab.classList.add('active');
        document.getElementById(targetTab).classList.add('active');
    });
});

// Fazer os labels clicáveis para ativar os switches
document.querySelectorAll('.settings-list label').forEach(label => {
    label.addEventListener('click', () => {
        const inputId = label.getAttribute('for');
        const input = document.getElementById(inputId);
        if (input) {
            input.click();
        }
    });
});

// Login
document.getElementById('loginForm').addEventListener('submit', (e) => {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    // Simulação de validação
    if (email && password) {
        // Atualizar dados do usuário
        document.getElementById('userEmail').textContent = email;
        document.getElementById('accountEmail').textContent = email;
        
        // Atualizar foto de perfil com base no nome
        const name = email.split('@')[0].replace(/[._]/g, ' ');
        document.getElementById('profilePic').src = 
            `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=667eea&color=fff&size=160`;
        
        // Mostrar interface principal
        document.getElementById('mainHeader').style.display = 'flex';
        document.getElementById('mainNav').style.display = 'flex';
        document.getElementById('userInfo').style.display = 'flex';
        
        // Mudar para aba de senhas
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        document.querySelector('[data-tab="passwords"]').classList.add('active');
        document.getElementById('passwords').classList.add('active');
        
        // Renderizar senhas
        renderPasswords(allPasswords);
        
        showToast('Login realizado com sucesso!');
    } else {
        const statusMsg = document.getElementById('loginStatus');
        statusMsg.className = 'status-message error';
        statusMsg.textContent = 'Por favor, preencha todos os campos.';
        setTimeout(() => {
            statusMsg.className = 'status-message';
        }, 3000);
    }
});

// Botão de registro
document.getElementById('registerBtn').addEventListener('click', () => {
    showToast('Redirecionando para o site oficial...');
});

// Logout do cabeçalho
document.getElementById('logoutBtn').addEventListener('click', () => {
    logout();
});

// Logout da página de conta
document.getElementById('logoutAccountBtn').addEventListener('click', () => {
    logout();
});

// Função de logout
function logout() {
    // Ocultar interface principal
    document.getElementById('mainHeader').style.display = 'none';
    document.getElementById('mainNav').style.display = 'none';
    document.getElementById('userInfo').style.display = 'none';
    
    // Voltar para tela de login
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('login').classList.add('active');
    
    // Limpar formulário
    document.getElementById('loginForm').reset();
    
    showToast('Você saiu da sua conta.');
}

// Editar conta
document.getElementById('editAccountBtn').addEventListener('click', () => {
    showToast('Redirecionando para edição de conta no site oficial...');
});

// Modo escuro
document.getElementById('darkMode').addEventListener('change', (e) => {
    if (e.target.checked) {
        document.body.classList.add('dark-mode');
        showToast('Modo escuro ativado');
    } else {
        document.body.classList.remove('dark-mode');
        showToast('Modo claro ativado');
    }
});

// Configurações
document.getElementById('autoFill').addEventListener('change', (e) => {
    showToast(e.target.checked ? 'Preenchimento automático ativado' : 'Preenchimento automático desativado');
});

document.getElementById('autoSave').addEventListener('change', (e) => {
    showToast(e.target.checked ? 'Salvamento automático ativado' : 'Salvamento automático desativado');
});

document.getElementById('notifications').addEventListener('change', (e) => {
    showToast(e.target.checked ? 'Notificações ativadas' : 'Notificações desativadas');
});

// Exportar dados
document.getElementById('exportData').addEventListener('click', () => {
    // Criar CSV
    let csv = 'Site,Usuário,Senha\n';
    allPasswords.forEach(pwd => {
        csv += `${pwd.site},${pwd.username},${pwd.password}\n`;
    });
    
    // Criar blob e download
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'maindug-passwords.csv';
    a.click();
    window.URL.revokeObjectURL(url);
    
    showToast('Dados exportados com sucesso!');
});