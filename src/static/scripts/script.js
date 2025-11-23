let currentUserRole = "{{ current_user.role if current_user.is_authenticated else 'guest' }}";
let currentUserName = "{{ current_user.login if current_user.is_authenticated else '' }}";

function updateDashboardView() {
  const userDashboard = document.getElementById("dashboard-user");
  const adminDashboard = document.getElementById("dashboard-admin");

  if (currentUserRole === "sysadmin") {
    userDashboard.style.display = "none";
    adminDashboard.style.display = "block";
  } else {
    adminDashboard.style.display = "none";
    userDashboard.style.display = "block";
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

  // --- Funções Helper de Cor (precisam estar disponíveis para os listeners) ---
  function hexToRgb(hex) {
    let r = 0,
      g = 0,
      b = 0;
    if (hex.length == 4) {
      // #f03
      r = parseInt(hex[1] + hex[1], 16);
      g = parseInt(hex[2] + hex[2], 16);
      b = parseInt(hex[3] + hex[3], 16);
    } else if (hex.length == 7) {
      // #ff0033
      r = parseInt(hex.substring(1, 3), 16);
      g = parseInt(hex.substring(3, 5), 16);
      b = parseInt(hex.substring(5, 7), 16);
    }
    return `${r}, ${g}, ${b}`;
  }

  function hexToHsl(hex) {
    let r = 0,
      g = 0,
      b = 0;
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
    let max = Math.max(r, g, b),
      min = Math.min(r, g, b);
    let h,
      s,
      l = (max + min) / 2;
    if (max == min) {
      h = s = 0; // grayscale
    } else {
      let d = max - min;
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
      switch (max) {
        case r:
          h = (g - b) / d + (g < b ? 6 : 0);
          break;
        case g:
          h = (b - r) / d + 2;
          break;
        case b:
          h = (r - g) / d + 4;
          break;
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
      root.style.setProperty(
        "--custom-border-color",
        `hsl(${h}, ${borderSat}%, 25%)`
      );
      root.style.setProperty("--text-primary", `hsl(${h}, ${bgSat}%, 95%)`);
      root.style.setProperty("--text-secondary", `hsl(${h}, ${bgSat}%, 65%)`);
      root.style.setProperty("--table-striped-bg", `hsl(${h}, ${bgSat}%, 12%)`);
      root.style.setProperty("--table-hover-bg", `hsl(${h}, ${bgSat}%, 20%)`);
    } else {
      // light
      root.style.setProperty("--page-bg", `hsl(${h}, ${bgSat}%, 98%)`);
      root.style.setProperty("--card-bg", `hsl(${h}, ${bgSat}%, 100%)`);
      root.style.setProperty("--input-bg", `hsl(${h}, ${bgSat}%, 100%)`);
      root.style.setProperty(
        "--custom-border-color",
        `hsl(${h}, ${borderSat}%, 90%)`
      );
      root.style.setProperty("--text-primary", `hsl(${h}, ${bgSat}%, 10%)`);
      root.style.setProperty("--text-secondary", `hsl(${h}, ${bgSat}%, 40%)`);
      root.style.setProperty("--table-striped-bg", `hsl(${h}, ${bgSat}%, 95%)`);
      root.style.setProperty("--table-hover-bg", `hsl(${h}, ${bgSat}%, 92%)`);
    }
  }


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
    const previewPlaceholder = container.querySelector(".image-input-placeholder");
    const previewImg = container.querySelector("img");

    if (preview) {
      preview.addEventListener("click", () => input.click());
    }

    if (input) {
      input.addEventListener("change", function () {
        const file = this.files[0];
        if (file && previewImg) {
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
      
      fetch("/api/log/deleteLogs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logs: selectedLogs }),
      }).then((response) => {
        if (response.ok) {
          alert("Logs excluídos com sucesso.");
        } else {
          alert("Erro ao excluir logs.");
        }
      });
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
      const pass = button.getAttribute("data-pass");
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
      if (flagsInput) flagsInput.value = flags || "";
      if (passInput) {
        passInput.value = pass;
        passInput.type = "password";
      }
      if (toggleIcon) toggleIcon.className = "bi bi-eye-fill";
    });
  }

  // Simula o salvamento do formulário de Edição
  const editForm = document.getElementById("editPasswordForm");
  if (editForm) {
    editForm.addEventListener("submit", function (e) {
      e.preventDefault();
      
      const loginInput = document.getElementById("edit-username");
      const siteInput = document.getElementById("edit-site");
      const passwordInput = document.getElementById("edit-password");
      const flagsInput = document.getElementById("edit-flags");

      if (!loginInput || !siteInput || !passwordInput || !flagsInput) {
        alert("Erro: Campos do formulário não encontrados.");
        return;
      }

      fetch("/editPassword", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          login: loginInput.value,
          site: siteInput.value,
          password: passwordInput.value,
          flags: flagsInput.value,
        }),
      }).then((response) => {
        if (response.ok) {
          alert("Credenciais salvas com sucesso.");
          const modalInstance = bootstrap.Modal.getInstance(editPasswordModal);
          if (modalInstance) modalInstance.hide();
        } else {
          alert("Erro ao salvar credenciais.");
        }
      });
    });
  }

  // Lógica do Modal de Deletar
  const deletePasswordModal = document.getElementById("deletePasswordModal");
  const confirmDeleteBtn = document.getElementById("confirmDeleteBtn");
  
  if (deletePasswordModal) {
    deletePasswordModal.addEventListener("show.bs.modal", function (event) {
      const button = event.relatedTarget;
      const site = button.getAttribute("data-site");

      const siteNameElement = deletePasswordModal.querySelector("#delete-site-name");
      if (siteNameElement) siteNameElement.textContent = site;
      
      if (confirmDeleteBtn) {
        confirmDeleteBtn.setAttribute("data-delete-id", site);
      }
    });
  }

  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener("click", function () {
      const site = this.getAttribute("data-delete-id");
      alert(`Simulando exclusão da credencial para: ${site}`);

      const rowToRemove = document.querySelector(`#credentialsTable tbody tr[data-site="${site}"]`);
      if (rowToRemove) {
        rowToRemove.remove();
      }

      if (deletePasswordModal) {
        const modalInstance = bootstrap.Modal.getInstance(deletePasswordModal);
        if (modalInstance) modalInstance.hide();
      }
    });
  }

  // Lógica de feedback do formulário "Minha Conta"
  const accountForm = document.querySelector("#page-account form");
  if (accountForm) {
    accountForm.addEventListener("submit", function (e) {
      handleAccountSave(e);
    });
  }

  // Lógica de Filtro/Busca da Tabela
  const searchInput = document.getElementById("credentialSearchInput");
  if (searchInput) {
    searchInput.addEventListener("keyup", function () {
      const filter = searchInput.value.toLowerCase();

      fetch("api/credentials/filterPasswords?query=" + encodeURIComponent(filter), {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      })
      .then((response) => response.json())
      .then((data) => {
        if (data.credentials) {
          refreshCredentials(data.credentials);
        } else {
          refreshCredentials([]);
        }
      })
      .catch(() => {
        refreshCredentials([]);
      });
    });
  }

  // Lógica de Gerenciamento de Flags
  const manageFlagsModal = document.getElementById("manageFlagsModal");
  const flagList = document.getElementById("flag-management-list");
  const flagCarousel = document.getElementById("flagFilterCarousel");
  const addFlagForm = document.getElementById("addFlagForm");
  
  let availableFlags = [];
  
  // Tenta parsear as flags do Jinja
  try {
    const flagsString = "{{ userInfo.flags if userInfo is defined else '[]' }}";
    availableFlags = JSON.parse(flagsString.replace(/'/g, '"'));
  } catch(e) {
    availableFlags = [];
  }

  function renderFlags() {
    if (!flagList || !flagCarousel) return;
    
    flagList.innerHTML = "";
    const allButton = flagCarousel.querySelector('button[onclick*="all"]');
    flagCarousel.innerHTML = "";
    if (allButton) flagCarousel.appendChild(allButton);

    availableFlags.forEach((flag) => {
      const li = document.createElement("li");
      li.className = "list-group-item d-flex justify-content-between align-items-center";
      li.textContent = flag;
      const deleteBtn = document.createElement("button");
      deleteBtn.className = "btn-close";
      deleteBtn.setAttribute("aria-label", "Remover");
      deleteBtn.onclick = () => removeFlag(flag);
      li.appendChild(deleteBtn);
      flagList.appendChild(li);

      const carouselBtn = document.createElement("button");
      carouselBtn.className = "btn btn-xs btn-outline-primary";
      carouselBtn.textContent = flag.charAt(0).toUpperCase() + flag.slice(1);
      carouselBtn.onclick = () => filterByFlag(carouselBtn, flag);
      flagCarousel.appendChild(carouselBtn);
    });
  }

  function removeFlag(flagToRemove) {
    fetch("/api/flags/removeFlag", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ flag: flagToRemove }),
    }).then((response) => {
      if (response.ok) {
        availableFlags = availableFlags.filter((f) => f !== flagToRemove);
        renderFlags();
      } else {
        alert("Erro ao remover flag.");
      }
    });
  }

  if (addFlagForm) {
    addFlagForm.addEventListener("submit", function (e) {
      e.preventDefault();
      const input = document.getElementById("newFlagInput");
      if (!input) return;
      
      const newFlag = input.value.trim().toLowerCase();
      if (newFlag && !availableFlags.includes(newFlag)) {
        fetch("/api/flags/addFlag", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ flag: newFlag }),
        })
          .then((response) => response.json())
          .then((data) => {
            if (data.success) {
              availableFlags.push(newFlag);
              renderFlags();
              input.value = "";
            } else {
              alert(data.error || "Erro ao adicionar flag");
            }
          });
      }
    });
  }

  if (manageFlagsModal) {
    manageFlagsModal.addEventListener("show.bs.modal", renderFlags);
  }
});