
// --- Monolith Navigation & State ---
let currentUserRole = 'guest'; // 'guest', 'user', 'sysadmin'
let currentUserName = '';

function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    const targetPage = document.getElementById(pageId);
    if (targetPage) {
        targetPage.classList.add('active');
    }
    
    if (pageId === 'page-index') {
        updateDashboardView();
    }
    
    const navbarOffcanvas = document.getElementById('offcanvasNavbar');
    if (navbarOffcanvas) {
        const bsOffcanvas = bootstrap.Offcanvas.getOrCreateInstance(navbarOffcanvas);
        if (bsOffcanvas) {
            bsOffcanvas.hide();
        }
    }
}

function updateDashboardView() {
    const userDashboard = document.getElementById('dashboard-user');
    const adminDashboard = document.getElementById('dashboard-admin');
    
    if (currentUserRole === 'sysadmin') {
        userDashboard.style.display = 'none';
        adminDashboard.style.display = 'block';
    } else {
        adminDashboard.style.display = 'none';
        userDashboard.style.display = 'block';
    }
}

function updateNavbar() {
    const isGuest = (currentUserRole === 'guest');
    
    document.getElementById('nav-guest-login').style.display = isGuest ? 'block' : 'none';
    document.getElementById('nav-guest-register').style.display = isGuest ? 'block' : 'none';

    document.getElementById('nav-user-dashboard').style.display = isGuest ? 'none' : 'block';
    document.getElementById('nav-user-stats').style.display = isGuest ? 'none' : 'block';
    document.getElementById('nav-user-account').style.display = isGuest ? 'none' : 'block';
    document.getElementById('nav-user-separator').style.display = isGuest ? 'none' : 'block';
    document.getElementById('nav-user-logout').style.display = isGuest ? 'none' : 'block';

    if (!isGuest) {
        document.getElementById('nav-username').textContent = currentUserName;
    }
}

function handleLogin(event) {
    event.preventDefault();
    const login = document.getElementById('login').value;
    const pass = document.getElementById('password').value;
    // MUDANÇA: Feedback de erro inline
    const feedbackEl = document.getElementById('login-feedback');
    feedbackEl.textContent = ''; // Limpa

    if (login === 'admin' && pass === 'admin') {
        currentUserRole = 'sysadmin';
        currentUserName = 'Admin';
    } else if (login === 'user' && pass === 'user') {
        currentUserRole = 'user';
        currentUserName = 'Usuário Comum';
    } else if (login) {
        currentUserRole = 'user'; 
        currentUserName = login;
    } else {
        // MUDANÇA: Substitui alert()
        feedbackEl.textContent = 'Usuário ou senha inválidos. (Tente "user"/"user" ou "admin"/"admin")';
        return;
    }
    
    updateNavbar();
    showPage('page-index');
    document.getElementById('password').value = '';
}

function logout() {
    currentUserRole = 'guest';
    currentUserName = '';
    updateNavbar();
    showPage('page-login');
}

// --- Lógica dos Componentes (main.js) ---
document.addEventListener('DOMContentLoaded', function () {
    
    const root = document.documentElement;
    const THEME_KEY = 'theme';
    const COLOR_KEY = 'primaryColor';
    
    // --- Funções Helper de Cor (precisam estar disponíveis para os listeners) ---
    function hexToRgb(hex) {
        let r = 0, g = 0, b = 0;
        if (hex.length == 4) { // #f03
            r = parseInt(hex[1] + hex[1], 16);
            g = parseInt(hex[2] + hex[2], 16);
            b = parseInt(hex[3] + hex[3], 16);
        } else if (hex.length == 7) { // #ff0033
            r = parseInt(hex.substring(1, 3), 16);
            g = parseInt(hex.substring(3, 5), 16);
            b = parseInt(hex.substring(5, 7), 16);
        }
        return `${r}, ${g}, ${b}`;
    }

    function hexToHsl(hex) {
        let r = 0, g = 0, b = 0;
        if (hex.length == 4) {
            r = parseInt(hex[1] + hex[1], 16);
            g = parseInt(hex[2] + hex[2], 16);
            b = parseInt(hex[3] + hex[3], 16);
        } else if (hex.length == 7) {
            r = parseInt(hex.substring(1, 3), 16);
            g = parseInt(hex.substring(3, 5), 16);
            b = parseInt(hex.substring(5, 7), 16);
        }
        r /= 255; g /= 255; b /= 255;
        let max = Math.max(r, g, b), min = Math.min(r, g, b);
        let h, s, l = (max + min) / 2;
        if (max == min) {
            h = s = 0; // grayscale
        } else {
            let d = max - min;
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            switch (max) {
                case r: h = (g - b) / d + (g < b ? 6 : 0); break;
                case g: h = (b - r) / d + 2; break;
                case b: h = (r - g) / d + 4; break;
            }
            h /= 6;
        }
        return [Math.round(h * 360), Math.round(s * 100), Math.round(l * 100)];
    }
    
    // Função de aplicar tema
    function applyAppTheme(hexColor, theme) {
        const [h, s, l] = hexToHsl(hexColor);
        const rgb = hexToRgb(hexColor);

        root.style.setProperty('--primary-color', hexColor);
        root.style.setProperty('--primary-color-rgb', rgb);
        root.style.setProperty('--primary-hue', h); 
        root.style.setProperty('--primary-sat', s + '%');

        const bgSat = s * 0.15; 
        const borderSat = s * 0.2; 

        if (theme === 'dark') {
            root.style.setProperty('--page-bg', `hsl(${h}, ${bgSat}%, 10%)`);
            root.style.setProperty('--card-bg', `hsl(${h}, ${bgSat}%, 15%)`);
            root.style.setProperty('--input-bg', `hsl(${h}, ${bgSat}%, 12%)`);
            root.style.setProperty('--custom-border-color', `hsl(${h}, ${borderSat}%, 25%)`);
            root.style.setProperty('--text-primary', `hsl(${h}, ${bgSat}%, 95%)`);
            root.style.setProperty('--text-secondary', `hsl(${h}, ${bgSat}%, 65%)`);
            root.style.setProperty('--table-striped-bg', `hsl(${h}, ${bgSat}%, 12%)`);
            root.style.setProperty('--table-hover-bg', `hsl(${h}, ${bgSat}%, 20%)`);
        } else { // light
            root.style.setProperty('--page-bg', `hsl(${h}, ${bgSat}%, 98%)`);
            root.style.setProperty('--card-bg', `hsl(${h}, ${bgSat}%, 100%)`);
            root.style.setProperty('--input-bg', `hsl(${h}, ${bgSat}%, 100%)`);
            root.style.setProperty('--custom-border-color', `hsl(${h}, ${borderSat}%, 90%)`);
            root.style.setProperty('--text-primary', `hsl(${h}, ${bgSat}%, 10%)`);
            root.style.setProperty('--text-secondary', `hsl(${h}, ${bgSat}%, 40%)`);
            root.style.setProperty('--table-striped-bg', `hsl(${h}, ${bgSat}%, 95%)`);
            root.style.setProperty('--table-hover-bg', `hsl(${h}, ${bgSat}%, 92%)`);
        }
    }

    // --- Lógica do Seletor de Tema ---
    const themeSwitcher = document.getElementById('theme-switcher');

    function updateThemeIcon(theme) {
        if (!themeSwitcher) return;
        const icon = themeSwitcher.querySelector('i');
        const text = themeSwitcher.querySelector('span');
        if (theme === 'dark') {
            icon.className = 'bi bi-sun-fill';
            text.textContent = 'Tema Claro';
            themeSwitcher.title = "Mudar para tema claro";
        } else {
            icon.className = 'bi bi-moon-fill';
            text.textContent = 'Tema Escuro';
            themeSwitcher.title = "Mudar para tema escuro";
        }
    }
    
    function toggleTheme() {
        const currentTheme = root.getAttribute('data-bs-theme');
        const newTheme = (currentTheme === 'dark') ? 'light' : 'dark';
        root.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem(THEME_KEY, newTheme);
        updateThemeIcon(newTheme);
        
        const currentColor = localStorage.getItem(COLOR_KEY) || '#0d6efd';
        applyAppTheme(currentColor, newTheme);
    }

    updateThemeIcon(root.getAttribute('data-bs-theme'));
    themeSwitcher.addEventListener('click', function(e) {
        e.preventDefault();
        toggleTheme();
    });

    // --- Lógica do Seletor de Cor ---
    const colorPicker = document.getElementById('accent-color-picker');
    if (colorPicker) {
        colorPicker.value = localStorage.getItem(COLOR_KEY) || '#0d6efd';
        colorPicker.addEventListener('input', function(e) {
            const newColor = e.target.value;
            const currentTheme = root.getAttribute('data-bs-theme');
            applyAppTheme(newColor, currentTheme);
        });
        colorPicker.addEventListener('change', function(e) {
            localStorage.setItem(COLOR_KEY, e.target.value);
        });
    }


    // --- Lógica do Componente _passwordInput ---
    document.body.addEventListener('click', function(event) {
        const button = event.target.closest('.toggle-password');
        if (button) {
            const targetId = button.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            
            // CORREÇÃO: Altera apenas o ícone, não o botão inteiro
            const icon = button.querySelector('i');
            if (passwordInput && passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.className = 'bi bi-eye-slash-fill';
            } else if (passwordInput) {
                passwordInput.type = 'password';
                icon.className = 'bi bi-eye-fill';
            }
        }
    });


    // --- Lógica do Componente _imageInput ---
    document.querySelectorAll('.image-input-container').forEach(container => {
        const input = container.querySelector('input[type="file"]');
        const preview = container.querySelector('.image-input-preview');
        const previewPlaceholder = container.querySelector('.image-input-placeholder');
        const previewImg = container.querySelector('img');

        if (preview) {
            preview.addEventListener('click', () => input.click());
        }

        if (input) {
            input.addEventListener('change', function () {
                const file = this.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = function (e) {
                        if (previewImg) {
                            previewImg.src = e.target.result;
                        }
                    }
                    reader.readAsDataURL(file);
                }
            });
        }
    });

    // --- Lógica do Componente _regexText ---
    document.querySelectorAll('input[data-regex]').forEach(input => {
        input.addEventListener('blur', function () {
            try {
                const regex = new RegExp(this.getAttribute('data-regex'));
                const condition = this.getAttribute('data-regex-condition');
                let isValid = regex.test(this.value);

                if (condition === 'must-not-match') {
                    isValid = !isValid;
                }

                if (!isValid && this.value) {
                    this.classList.add('is-invalid');
                    let errorFeedback = this.nextElementSibling;
                    if (!errorFeedback || !errorFeedback.classList.contains('invalid-feedback')) {
                        errorFeedback = document.createElement('div');
                        errorFeedback.classList.add('invalid-feedback');
                        this.parentNode.appendChild(errorFeedback);
                    }
                    errorFeedback.textContent = this.getAttribute('data-regex-message') || 'Entrada inválida.';
                } else {
                    this.classList.remove('is-invalid');
                    this.classList.add('is-valid');
                    let errorFeedback = this.nextElementSibling;
                    if (errorFeedback && errorFeedback.classList.contains('invalid-feedback')) {
                        errorFeedback.remove();
                    }
                }
            } catch(e) {
                console.error("Regex inválido:", this.getAttribute('data-regex'), e);
            }
        });
    });
    
    // --- Lógica de Exclusão de Logs (moreInfo) ---
        document.getElementById('deleteLogsBtn')?.addEventListener('click', function() {
            alert('Simulação de exclusão de logs selecionados.');
        });
        document.getElementById('checkAllLogs')?.addEventListener('change', function() {
            document.querySelectorAll('.log-checkbox').forEach(checkbox => {
                checkbox.checked = this.checked;
            });
        });

    // --- Lógica para preencher Modais de View/Edit ---
    const viewPasswordModal = document.getElementById('viewPasswordModal');
    if (viewPasswordModal) {
        viewPasswordModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const site = button.getAttribute('data-site');
            const user = button.getAttribute('data-user');
            const pass = button.getAttribute('data-pass');

            viewPasswordModal.querySelector('.modal-title').textContent = 'Visualizar: ' + site;
            viewPasswordModal.querySelector('#view-site').value = site;
            viewPasswordModal.querySelector('#view-username').value = user;
            
            const passInput = viewPasswordModal.querySelector('#view-password');
            passInput.value = pass;
            passInput.type = 'password'; // Reseta
            viewPasswordModal.querySelector('.toggle-password i').className = 'bi bi-eye-fill'; 
        });
    }

    const editPasswordModal = document.getElementById('editPasswordModal');
    if (editPasswordModal) {
        editPasswordModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const site = button.getAttribute('data-site');
            const user = button.getAttribute('data-user');
            const pass = button.getAttribute('data-pass');
            // MUDANÇA: Puxar flags
            const flags = button.getAttribute('data-flags');

            editPasswordModal.querySelector('.modal-title').textContent = 'Editar: ' + site;
            editPasswordModal.querySelector('#edit-site').value = site;
            editPasswordModal.querySelector('#edit-username').value = user;
            editPasswordModal.querySelector('#edit-flags').value = flags; // Seta as flags
            
            const passInput = editPasswordModal.querySelector('#edit-password');
            passInput.value = pass;
            passInput.type = 'password'; // Reseta
            editPasswordModal.querySelector('.toggle-password i').className = 'bi bi-eye-fill'; 
        });
    }
    
    // Simula o salvamento do formulário de Edição
    const editForm = document.getElementById('editPasswordForm');
    if(editForm) {
        editForm.addEventListener('submit', function(e) {
            e.preventDefault();
            alert('Credenciais salvas (simulação)!');
            const modalInstance = bootstrap.Modal.getInstance(document.getElementById('editPasswordModal'));
            modalInstance.hide();
        });
    }
    
    // MUDANÇA: Lógica do Modal de Deletar
    const deletePasswordModal = document.getElementById('deletePasswordModal');
    if (deletePasswordModal) {
        deletePasswordModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const site = button.getAttribute('data-site');
            
            deletePasswordModal.querySelector('#delete-site-name').textContent = site;
            // Passa o ID/site para o botão de confirmação para saber o que deletar
            deletePasswordModal.querySelector('#confirmDeleteBtn').setAttribute('data-delete-id', site);
        });
        
        // Listener para o botão de confirmação
        document.getElementById('confirmDeleteBtn').addEventListener('click', function() {
            const site = this.getAttribute('data-delete-id');
            alert(`Simulando exclusão da credencial para: ${site}`);
            
            // Simula a remoção da linha da tabela
            const rowToRemove = document.querySelector(`#credentialsTable tbody tr[data-site="${site}"]`);
            if(rowToRemove) {
                rowToRemove.remove();
            }
            
            const modalInstance = bootstrap.Modal.getInstance(deletePasswordModal);
            modalInstance.hide();
        });
    }
    
    // MUDANÇA: Lógica de feedback do formulário "Minha Conta"
    const accountForm = document.querySelector('#page-account form');
    if (accountForm) {
        accountForm.addEventListener('submit', function(e) {
            handleAccountSave(e); // Chama a função nova
        });
    }

    // MUDANÇA: Lógica de Filtro/Busca da Tabela
    const searchInput = document.getElementById('credentialSearchInput');
    if(searchInput) {
        searchInput.addEventListener('keyup', function() {
            const filter = searchInput.value.toLowerCase();
            const tableRows = document.querySelectorAll("#credentialsTable tbody tr");
            
            tableRows.forEach(row => {
                const site = row.getAttribute('data-site').toLowerCase();
                const user = row.getAttribute('data-user').toLowerCase();
                
                if (site.includes(filter) || user.includes(filter)) {
                    row.style.display = ""; // Mostra
                } else {
                    row.style.display = "none"; // Esconde
                }
            });
        });
    }
    
    // MUDANÇA: Lógica de Gerenciamento de Flags
    const manageFlagsModal = document.getElementById('manageFlagsModal');
    const flagList = document.getElementById('flag-management-list');
    const flagCarousel = document.getElementById('flagFilterCarousel');
    let availableFlags = ['trabalho', 'social', 'jogos', 'finanças']; // Simulação de DB

    function renderFlags() {
        // Limpa listas
        flagList.innerHTML = '';
        
        // Limpa e recria carrossel (mantendo o "Todas")
        const allButton = flagCarousel.querySelector('button[onclick*="all"]');
        flagCarousel.innerHTML = '';
        flagCarousel.appendChild(allButton);

        availableFlags.forEach(flag => {
            // Adiciona ao Modal
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex justify-content-between align-items-center';
            li.textContent = flag;
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn-close';
            deleteBtn.setAttribute('aria-label', 'Remover');
            deleteBtn.onclick = () => removeFlag(flag);
            li.appendChild(deleteBtn);
            flagList.appendChild(li);
            
            // Adiciona ao Carrossel
            const carouselBtn = document.createElement('button');
            carouselBtn.className = 'btn btn-xs btn-outline-primary';
            carouselBtn.textContent = flag.charAt(0).toUpperCase() + flag.slice(1); // Capitaliza
            carouselBtn.onclick = () => filterByFlag(carouselBtn, flag);
            flagCarousel.appendChild(carouselBtn);
        });
    }

    function removeFlag(flagToRemove) {
        availableFlags = availableFlags.filter(f => f !== flagToRemove);
        renderFlags();
    }

    // Adiciona nova flag
    document.getElementById('addFlagForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const input = document.getElementById('newFlagInput');
        const newFlag = input.value.trim().toLowerCase();
        if (newFlag && !availableFlags.includes(newFlag)) {
            availableFlags.push(newFlag);
            renderFlags();
            input.value = '';
        }
    });

    // Renderiza flags ao abrir o modal
    manageFlagsModal.addEventListener('show.bs.modal', renderFlags);


    // --- Configuração Inicial ---
    updateNavbar();
    showPage('page-login'); // Começa na tela de login
});

// --- Funções Globais (para 'onclick' e JS interativo) ---

// MUDANÇA: Feedback de salvar conta
function handleAccountSave(event) {
    event.preventDefault();
    const saveBtn = event.target.querySelector('button[type="submit"]');
    if (!saveBtn) return;
    
    const originalHtml = saveBtn.innerHTML;
    
    // 1. Mostrar loading
    saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Salvando...';
    saveBtn.disabled = true;

    // 2. Simular salvamento
    setTimeout(() => {
        // 3. Mostrar sucesso
        saveBtn.innerHTML = '<i class="bi bi-check-circle-fill"></i> Salvo com Sucesso!';
        
        // 4. Voltar ao normal
        setTimeout(() => {
            saveBtn.innerHTML = originalHtml;
            saveBtn.disabled = false;
        }, 2000); // Mostra "Salvo" por 2s
        
    }, 1500); // Simula 1.5s de loading
}

// MUDANÇA: Simulação de ordenação
function sortCredentials(event, column) {
    event.preventDefault();
    // Reseta ícones
    document.querySelectorAll('.sortable-link i').forEach(icon => {
        icon.className = 'bi'; 
    });
    
    // Adiciona ícone ao clicado
    const icon = event.target.querySelector('i');
    if (icon) {
            // Lógica simples de toggle (não implementa a ordenação real)
        if (icon.classList.contains('bi-sort-alpha-down')) {
            icon.className = 'bi bi-sort-alpha-up';
        } else {
            icon.className = 'bi bi-sort-alpha-down';
        }
    }
    alert(`Simulando ordenação por: ${column} (requer backend)`);
}

// MUDANÇA: Simulação de filtro de flag
function filterByFlag(buttonElement, flag) {
    // Estilo do botão
    document.querySelectorAll('#flagFilterCarousel .btn').forEach(btn => {
        btn.classList.remove('btn-primary', 'active');
        btn.classList.add('btn-outline-primary');
    });
    buttonElement.classList.add('btn-primary', 'active');
    buttonElement.classList.remove('btn-outline-primary');
    
    // Lógica de filtro (Frontend)
    const tableRows = document.querySelectorAll("#credentialsTable tbody tr");
    tableRows.forEach(row => {
        if (flag === 'all') {
            row.style.display = ""; // Mostra todas
        } else {
            const rowFlags = row.getAttribute('data-flags').split(',');
            if (rowFlags.includes(flag)) {
                row.style.display = ""; // Mostra
            } else {
                row.style.display = "none"; // Esconde
            }
        }
    });
}