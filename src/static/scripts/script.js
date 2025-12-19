let currentUserRole = "{{ current_user.role if current_user.is_authenticated else 'guest' }}";
let currentUserName = "{{ current_user.login if current_user.is_authenticated else '' }}";

function updateDashboardView() {
  const userDashboard = document.getElementById("dashboard-user");
  const adminDashboard = document.getElementById("dashboard-admin");

  if (currentUserRole === "sysadmin") {
    if (userDashboard) userDashboard.style.display = "none";
    if (adminDashboard) adminDashboard.style.display = "block";
  } else {
    if (adminDashboard) adminDashboard.style.display = "none";
    if (userDashboard) userDashboard.style.display = "block";
  }
}

function updateNavbar() {
  // Define o estado baseado nos dados do servidor
  const isAuthenticated = currentUserRole !== "guest" && currentUserRole !== "";
  
  // Atualiza o nome do usuário se estiver autenticado
  const usernameSpan = document.getElementById("nav-username");
  if (usernameSpan && isAuthenticated) {
    usernameSpan.textContent = currentUserName;
  }
}

// --- Lógica dos Componentes (main.js) ---
document.addEventListener("DOMContentLoaded", function () {
  const root = document.documentElement;
  const THEME_KEY = "theme";
  const COLOR_KEY = "primaryColor";

  // --- Funções Helper de Cor ---
  function hexToRgb(hex) {
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
    r /= 255;
    g /= 255;
    b /= 255;
    let max = Math.max(r, g, b), min = Math.min(r, g, b);
    let h, s, l = (max + min) / 2;
    if (max == min) {
      h = s = 0;
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

    root.style.setProperty("--primary-color", hexColor);
    root.style.setProperty("--primary-color-rgb", rgb);
    root.style.setProperty("--primary-hue", h);
    root.style.setProperty("--primary-sat", s + "%");

    const bgSat = s * 0.15;
    const borderSat = s * 0.2;

    if (theme === "dark") {
      root.style.setProperty("--page-bg", `hsl(${h}, ${bgSat}%, 10%)`);
      root.style.setProperty("--card-bg", `hsl(${h}, ${bgSat}%, 15%)`);
      root.style.setProperty("--input-bg", `hsl(${h}, ${bgSat}%, 12%)`);
      root.style.setProperty("--custom-border-color", `hsl(${h}, ${borderSat}%, 25%)`);
      root.style.setProperty("--text-primary", `hsl(${h}, ${bgSat}%, 95%)`);
      root.style.setProperty("--text-secondary", `hsl(${h}, ${bgSat}%, 65%)`);
      root.style.setProperty("--table-striped-bg", `hsl(${h}, ${bgSat}%, 12%)`);
      root.style.setProperty("--table-hover-bg", `hsl(${h}, ${bgSat}%, 20%)`);
    } else {
      root.style.setProperty("--page-bg", `hsl(${h}, ${bgSat}%, 98%)`);
      root.style.setProperty("--card-bg", `hsl(${h}, ${bgSat}%, 100%)`);
      root.style.setProperty("--input-bg", `hsl(${h}, ${bgSat}%, 100%)`);
      root.style.setProperty("--custom-border-color", `hsl(${h}, ${borderSat}%, 90%)`);
      root.style.setProperty("--text-primary", `hsl(${h}, ${bgSat}%, 10%)`);
      root.style.setProperty("--text-secondary", `hsl(${h}, ${bgSat}%, 40%)`);
      root.style.setProperty("--table-striped-bg", `hsl(${h}, ${bgSat}%, 95%)`);
      root.style.setProperty("--table-hover-bg", `hsl(${h}, ${bgSat}%, 92%)`);
    }
  }

  // Torna applyAppTheme global para uso em account.html
  window.applyAppTheme = applyAppTheme;

  // --- Lógica do Seletor de Tema ---
  const themeSwitcher = document.getElementById("theme-switcher");
  
  if (themeSwitcher) {
    function updateThemeIcon(theme) {
      const icon = themeSwitcher.querySelector("i");
      const text = themeSwitcher.querySelector("span");
      if (theme === "dark") {
        icon.className = "bi bi-sun-fill";
        text.textContent = "Tema Claro";
        themeSwitcher.title = "Mudar para tema claro";
      } else {
        icon.className = "bi bi-moon-fill";
        text.textContent = "Tema Escuro";
        themeSwitcher.title = "Mudar para tema escuro";
      }
    }

    function toggleTheme() {
      const currentTheme = root.getAttribute("data-bs-theme");
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      root.setAttribute("data-bs-theme", newTheme);
      localStorage.setItem(THEME_KEY, newTheme);
      updateThemeIcon(newTheme);

      const currentColor = localStorage.getItem(COLOR_KEY) || "#0d6efd";
      applyAppTheme(currentColor, newTheme);
    }

    updateThemeIcon(root.getAttribute("data-bs-theme"));
    themeSwitcher.addEventListener("click", function (e) {
      e.preventDefault();
      toggleTheme();
    });
  }

  // --- Lógica do Seletor de Cor ---
  const colorPicker = document.getElementById("accent-color-picker");
  if (colorPicker) {
    colorPicker.value = localStorage.getItem(COLOR_KEY) || "#0d6efd";
    colorPicker.addEventListener("input", function (e) {
      const newColor = e.target.value;
      const currentTheme = root.getAttribute("data-bs-theme");
      applyAppTheme(newColor, currentTheme);
    });
    colorPicker.addEventListener("change", function (e) {
      localStorage.setItem(COLOR_KEY, e.target.value);
    });
  }

  // --- Lógica do Componente _passwordInput ---
  document.body.addEventListener("click", function (event) {
    const button = event.target.closest(".toggle-password");
    if (button) {
      const targetId = button.getAttribute("data-target");
      const passwordInput = document.getElementById(targetId);

      const icon = button.querySelector("i");
      if (passwordInput && passwordInput.type === "password") {
        passwordInput.type = "text";
        if (icon) icon.className = "bi bi-eye-slash-fill";
      } else if (passwordInput) {
        passwordInput.type = "password";
        if (icon) icon.className = "bi bi-eye-fill";
      }
    }
  });

  // --- Lógica do Componente _imageInput ---
  document.querySelectorAll(".image-input-container").forEach((container) => {
    const input = container.querySelector('input[type="file"]');
    const preview = container.querySelector(".image-input-preview");
    const previewImg = container.querySelector("img");

    if (preview && input) {
      preview.addEventListener("click", () => input.click());
    }

    if (input && previewImg) {
      input.addEventListener("change", function () {
        const file = this.files[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = function (e) {
            previewImg.src = e.target.result;
          };
          reader.readAsDataURL(file);
        }
      });
    }
  });

  // --- Lógica do Componente _regexText ---
  document.querySelectorAll("input[data-regex]").forEach((input) => {
    input.addEventListener("blur", function () {
      try {
        const regex = new RegExp(this.getAttribute("data-regex"));
        const condition = this.getAttribute("data-regex-condition");
        let isValid = regex.test(this.value);

        if (condition === "must-not-match") {
          isValid = !isValid;
        }

        if (!isValid && this.value) {
          this.classList.add("is-invalid");
          let errorFeedback = this.nextElementSibling;
          if (!errorFeedback || !errorFeedback.classList.contains("invalid-feedback")) {
            errorFeedback = document.createElement("div");
            errorFeedback.classList.add("invalid-feedback");
            this.parentNode.appendChild(errorFeedback);
          }
          errorFeedback.textContent = this.getAttribute("data-regex-message") || "Entrada inválida.";
        } else {
          this.classList.remove("is-invalid");
          this.classList.add("is-valid");
          let errorFeedback = this.nextElementSibling;
          if (errorFeedback && errorFeedback.classList.contains("invalid-feedback")) {
            errorFeedback.remove();
          }
        }
      } catch (e) {
        console.error("Regex inválido:", this.getAttribute("data-regex"), e);
      }
    });
  });

  // --- Lógica de Exclusão de Logs (moreInfo) ---
  const deleteLogsBtn = document.getElementById("deleteLogsBtn");
  if (deleteLogsBtn) {
    deleteLogsBtn.addEventListener("click", function () {
      const selectedLogs = Array.from(document.querySelectorAll(".log-checkbox:checked"))
        .map(checkbox => checkbox.value);
      
      if (selectedLogs.length === 0) {
        if (window.customAlert) {
          window.customAlert.warning('Selecione pelo menos um log para excluir');
        } else {
          alert('Selecione pelo menos um log para excluir');
        }
        return;
      }
      
      const confirmMsg = `Tem certeza que deseja excluir ${selectedLogs.length} log${selectedLogs.length > 1 ? 's' : ''}?`;
      
      const executeDeletion = () => {
        const loading = window.showLoading ? window.showLoading('Excluindo logs...') : null;
        
        fetch("/moreInfo", {
          method: "DELETE",
          headers: { 
            "Content-Type": "application/x-www-form-urlencoded" 
          },
          body: new URLSearchParams({
            'logs': selectedLogs.join(',')
          })
        })
        .then((response) => response.json())
        .then((data) => {
          if (loading && loading.close) loading.close();
          
          if (data.success) {
            if (window.customAlert) {
              window.customAlert.success(data.message || 'Logs excluídos com sucesso').then(() => {
                window.location.reload();
              });
            } else {
              alert(data.message || 'Logs excluídos com sucesso');
              window.location.reload();
            }
          } else {
            if (window.customAlert) {
              window.customAlert.error(data.message || 'Erro ao excluir logs');
            } else {
              alert(data.message || 'Erro ao excluir logs');
            }
          }
        })
        .catch((error) => {
          if (loading && loading.close) loading.close();
          console.error('Erro:', error);
          
          if (window.customAlert) {
            window.customAlert.error('Erro ao comunicar com o servidor');
          } else {
            alert('Erro ao comunicar com o servidor');
          }
        });
      };
      
      if (window.customAlert) {
        window.customAlert.confirm(confirmMsg, 'Confirmar Exclusão').then(confirmed => {
          if (confirmed) executeDeletion();
        });
      } else {
        if (confirm(confirmMsg)) executeDeletion();
      }
    });
  }

  const checkAllLogs = document.getElementById("checkAllLogs");
  if (checkAllLogs) {
    checkAllLogs.addEventListener("change", function () {
      document.querySelectorAll(".log-checkbox").forEach((checkbox) => {
        checkbox.checked = this.checked;
      });
    });
  }

  // --- Lógica para preencher Modais de View/Edit ---
  const viewPasswordModal = document.getElementById("viewPasswordModal");
  if (viewPasswordModal) {
    viewPasswordModal.addEventListener("show.bs.modal", function (event) {
      const button = event.relatedTarget;
      const site = button.getAttribute("data-site");
      const user = button.getAttribute("data-user");
      const pass = button.getAttribute("data-pass");

      const modalTitle = viewPasswordModal.querySelector(".modal-title");
      const siteInput = viewPasswordModal.querySelector("#view-site");
      const usernameInput = viewPasswordModal.querySelector("#view-username");
      const passInput = viewPasswordModal.querySelector("#view-password");
      const toggleIcon = viewPasswordModal.querySelector(".toggle-password i");

      if (modalTitle) modalTitle.textContent = "Visualizar: " + site;
      if (siteInput) siteInput.value = site;
      if (usernameInput) usernameInput.value = user;
      if (passInput) {
        passInput.value = pass;
        passInput.type = "password";
      }
      if (toggleIcon) toggleIcon.className = "bi bi-eye-fill";
    });
  }

  const editPasswordModal = document.getElementById("editPasswordModal");
  if (editPasswordModal) {
    editPasswordModal.addEventListener("show.bs.modal", function (event) {
      const button = event.relatedTarget;
      const site = button.getAttribute("data-site");
      const user = button.getAttribute("data-user");
      const flags = button.getAttribute("data-flags");

      const modalTitle = editPasswordModal.querySelector(".modal-title");
      const siteInput = editPasswordModal.querySelector("#edit-site");
      const usernameInput = editPasswordModal.querySelector("#edit-username");
      const flagsInput = editPasswordModal.querySelector("#edit-flags");
      const passInput = editPasswordModal.querySelector("#edit-password");
      const toggleIcon = editPasswordModal.querySelector(".toggle-password i");

      if (modalTitle) modalTitle.textContent = "Editar: " + site;
      if (siteInput) siteInput.value = site;
      if (usernameInput) usernameInput.value = user;
      
      // Limpar senha (opcional na edição)
      if (passInput) {
        passInput.value = "";
        passInput.type = "password";
      }
      if (toggleIcon) toggleIcon.className = "bi bi-eye-fill";
      
      // Não preencher flags aqui, pois agora é um select múltiplo
      // A lógica está em _modals.html
    });
  }

  // Lógica do Modal de Deletar
  const deletePasswordModal = document.getElementById("deletePasswordModal");
  
  if (deletePasswordModal) {
    deletePasswordModal.addEventListener("show.bs.modal", function (event) {
      const button = event.relatedTarget;
      const site = button.getAttribute("data-site");

      const siteNameElement = deletePasswordModal.querySelector("#delete-site-name");
      if (siteNameElement) siteNameElement.textContent = site;
    });
  }

  // Lógica de Filtro/Busca da Tabela
  const searchInput = document.getElementById("credentialSearchInput");
  if (searchInput) {
    // Debounce para evitar muitas requisições
    let searchTimeout;
    
    searchInput.addEventListener("keyup", function () {
      clearTimeout(searchTimeout);
      
      searchTimeout = setTimeout(() => {
        const filter = searchInput.value.toLowerCase();
        const tableRows = document.querySelectorAll("#credentialsTable tbody tr");
        
        // Filtro no frontend (mais rápido para pequenos datasets)
        tableRows.forEach(row => {
          const site = row.querySelector('td:first-child')?.textContent.toLowerCase() || '';
          const user = row.querySelector('td:nth-child(2)')?.textContent.toLowerCase() || '';
          
          if (site.includes(filter) || user.includes(filter)) {
            row.style.display = "";
          } else {
            row.style.display = "none";
          }
        });
      }, 300); // Aguarda 300ms após parar de digitar
    });
  }

  // Inicializa a visualização do dashboard
  updateDashboardView();
  updateNavbar();
});

// --- Funções Globais ---

// Função para filtrar por flag (chamada do HTML)
function filterByFlag(buttonElement, flag) {
  // Atualiza estilos dos botões
  document.querySelectorAll('#flagFilterCarousel .btn').forEach(btn => {
    btn.classList.remove('btn-primary', 'active');
    btn.classList.add('btn-outline-primary');
  });
  buttonElement.classList.add('btn-primary', 'active');
  buttonElement.classList.remove('btn-outline-primary');
  
  // Filtra linhas da tabela
  const tableRows = document.querySelectorAll("#credentialsTable tbody tr");
  tableRows.forEach(row => {
    if (flag === 'all') {
      row.style.display = "";
    } else {
      const rowFlags = (row.getAttribute('data-flags') || '').split(',').map(f => f.trim());
      if (rowFlags.includes(flag)) {
        row.style.display = "";
      } else {
        row.style.display = "none";
      }
    }
  });
}

// Função para ordenar tabela (chamada do HTML)
function sortTable(column, element) {
  const form = document.getElementById('searchForm');
  if (!form) return;
  
  const icon = element.querySelector('i');
  
  // Atualiza todos os ícones
  document.querySelectorAll('#credentialsTable th a i').forEach(i => {
    if (i !== icon) {
      i.className = 'bi bi-sort-alpha-down';
    }
  });
  
  // Toggle do ícone clicado
  const currentOrder = form.querySelector('input[name="sortOrder"]').value;
  if (currentOrder === 'asc') {
    icon.className = 'bi bi-sort-alpha-down-alt';
    form.querySelector('input[name="sortOrder"]').value = 'desc';
  } else {
    icon.className = 'bi bi-sort-alpha-down';
    form.querySelector('input[name="sortOrder"]').value = 'asc';
  }
  
  form.querySelector('input[name="sort"]').value = column;
  form.submit();
}

// Função para feedback de salvamento de conta
function handleAccountSave(event) {
  event.preventDefault();
  const form = event.target;
  const saveBtn = form.querySelector('button[type="submit"]');
  
  if (!saveBtn) return;
  
  const originalHtml = saveBtn.innerHTML;
  
  // Validação de senha
  const password = form.querySelector('#acc-password')?.value;
  const passwordConfirm = form.querySelector('#acc-passwordConfirm')?.value;
  
  if (password && password !== passwordConfirm) {
    if (window.customAlert) {
      window.customAlert.error('As senhas não coincidem');
    } else {
      alert('As senhas não coincidem');
    }
    return;
  }
  
  // Mostrar loading
  saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Salvando...';
  saveBtn.disabled = true;

  // Submeter formulário
  form.submit();
}