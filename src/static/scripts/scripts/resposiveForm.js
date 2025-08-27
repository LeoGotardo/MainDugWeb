class FormularioDinamico {
            constructor() {
                this.activeContainers = new Map();
                this.animationQueue = [];
                this.isAnimating = false;
                this.currentSelectedStore = null; // NOVO: Track da loja atual
                this.init();
            }
            init() {
                this.setupEventListeners();
            }
            setupEventListeners() {
                // Event delegation para melhor performance
                document.addEventListener('change', (e) => {
                    if (e.target.tagName === 'SELECT') {
                        this.handleSelectChange(e);
                    } else if (e.target.type === 'checkbox') {
                        this.handleCheckboxChange(e);
                    }
                });

                // NOVO: Listener específico para mudanças na loja
                document.addEventListener('change', (e) => {
                    if (e.target.name === 'store') {
                        this.handleStoreChange(e);
                    }
                });

                // Previne múltiplas submissões
                const form = document.getElementById('form') || document.getElementById('dynamicForm');
                if (form) {
                    form.addEventListener('submit', (e) => {
                        // Permitir submissão normal do formulário
                        // e.preventDefault();
                        // this.handleFormSubmit();
                    });
                }
            }

            // NOVO: Handler específico para mudanças de loja
            handleStoreChange(event) {
                this.currentSelectedStore = event.target.value;

                // Se o campo de role está como 'user' e há campos dinâmicos visíveis, reprocessa
                const roleSelect = document.querySelector('select[name="role"]');
                if (roleSelect && roleSelect.value === 'user') {
                    const containerId = `dynamic-fields-container-${roleSelect.name}`;
                    const container = document.getElementById(containerId);
                    if (container && container.style.display !== 'none') {
                        // Reprocessa os campos de usuário com a nova loja
                        this.showUserFields(containerId);
                    }
                }
            }

            handleSelectChange(event) {
                const select = event.target;
                const value = select.value;
                const containerId = `dynamic-fields-container-${select.name}`;

                // Cancela animações pendentes para este container
                this.cancelPendingAnimations(containerId);

                if (value === 'gerent') {
                    this.showGerentFields(containerId);
                } else if (value === 'user') {
                    this.showUserFields(containerId);
                } else {
                    this.hideFields(containerId);
                }
            }

            handleCheckboxChange(event) {
                const checkbox = event.target;
                const checked = checkbox.checked;
                const containerId = `dynamic-fields-container-${checkbox.name}`;

                this.cancelPendingAnimations(containerId);

                if (checked) {
                    this.showLimitFields(containerId);
                } else {
                    this.hideFields(containerId);
                }
            }

            cancelPendingAnimations(containerId) {
                // Remove animações pendentes para este container
                this.animationQueue = this.animationQueue.filter(item => item.containerId !== containerId);
            }

            showGerentFields(containerId) {
                const fields = [
                    { type: 'text', id: 'login', label: 'Login', required: true },
                    { type: 'password', id: 'password', label: 'Senha', required: true },
                    { type: 'password', id: 'passwordConfirm', label: 'Confirme a senha', required: true },
                    {
                        type: 'select',
                        id: 'cardType',
                        label: 'Tipo de cartão',
                        required: true,
                        options: [
                            { value: '', name: 'Selecione um tipo...', disabled: true },
                            { value: 'calibracao', name: 'Calibração' },
                            { value: 'regulagem', name: 'Regulagem' }
                        ]
                    }
                ];

                this.renderFields(fields, containerId);
            }

            showUserFields(containerId) {
                // NOVO: Verifica se deve mostrar o campo de créditos baseado na loja selecionada
                const storeInfo = this.getSelectedStoreInfo();
                const shouldShowCredits = this.shouldShowCreditsField();

                const fields = [];

                if (shouldShowCredits) {
                    // NOVO: Label dinâmica baseada na loja
                    const storeLabel = storeInfo?.storeName ? ` para ${storeInfo.storeName}` : '';
                    fields.push({
                        type: 'number',
                        id: 'credits',
                        label: `Créditos${storeLabel}`,
                        required: true,
                        min: 0,
                        placeholder: `Digite a quantidade de créditos${storeLabel.toLowerCase()}`
                    });
                }

                // Se não há campos para mostrar, mostra mensagem informativa
                if (fields.length === 0) {
                    this.showNoCreditsMessage(containerId, storeInfo);
                    return;
                }

                this.renderFields(fields, containerId);
            }

            getSelectedStoreInfo() {
                const storeSelect = document.querySelector('select[name="store"]');
                if (!storeSelect || !storeSelect.value) {
                    return null;
                }

                const selectedOption = storeSelect.querySelector(`option[value="${storeSelect.value}"]`);
                if (!selectedOption) {
                    return null;
                }

                return {
                    storeId: selectedOption.value,
                    storeName: selectedOption.textContent.trim(),
                    paymentType: selectedOption.getAttribute('data-payment-type'),
                    storeIdData: selectedOption.getAttribute('data-store-id')
                };
            }

            // MELHORADO: Função para verificar se deve mostrar campo de créditos
            shouldShowCreditsField() {
                const storeInfo = this.getSelectedStoreInfo();
                if (!storeInfo) {
                    return false; // Se não há loja selecionada, não mostra créditos
                }

                // Se for pós-paga ou não especificado, não mostra créditos
                return storeInfo.paymentType && storeInfo.paymentType !== 'postpaid';
            }

            // MELHORADO: Mostra mensagem quando não há créditos para exibir
            showNoCreditsMessage(containerId, storeInfo) {
                const container = document.getElementById(containerId);
                if (!container) return;

                const storeName = storeInfo?.storeName || 'Esta loja';
                const paymentTypeText = storeInfo?.paymentType === 'postpaid' ? 'pós-pago' : 'não especificado';

                container.innerHTML = `
 <div class="alert alert-info mt-3" style="font-size: 0.9rem;">
 <i class="bi bi-info-circle me-2"></i>
 <strong>Informação:</strong> ${storeName} utiliza pagamento ${paymentTypeText}. O campo de créditos não é necessário.
 </div>
 `;
                container.style.display = 'block';
            }

            showLimitFields(containerId) {
                const fields = [
                    { type: 'number', id: 'volume', label: 'Limite de volume (ML)', required: true, min: 0, placeholder: 'Digite o limite em ml' },
                ];

                this.renderFields(fields, containerId);
            }

            async renderFields(fields, containerId) {
                const container = document.getElementById(containerId);

                if (!container) {
                    console.error(`Container não encontrado: ${containerId}`);
                    return;
                }

                // Se já há conteúdo, fade out primeiro
                if (container.innerHTML.trim()) {
                    await this.fadeOutContainer(container);
                }

                // Limpa e prepara o container
                container.innerHTML = '';
                container.style.display = 'block';

                // Adiciona os campos
                fields.forEach(field => {
                    const fieldElement = this.createFieldElement(field, containerId);
                    container.appendChild(fieldElement);
                });

                // Anima a entrada do container
                await this.fadeInContainer(container);

                // Anima os campos individualmente
                this.animateFields(container);

                this.activeContainers.set(containerId, container);
            }

            createFieldElement(field, containerId) {
                const div = document.createElement('div');
                div.className = 'form-group mb-3 dynamic-form-group';

                const label = document.createElement('label');
                label.setAttribute('for', `${field.id}_${containerId}`);
                label.textContent = field.label + (field.required ? ' *' : '');
                div.appendChild(label);

                if (field.type === 'password') {
                    // Criar wrapper para o password
                    const wrapper = document.createElement('div');
                    wrapper.className = 'password-wrapper';

                    // Criar input de password
                    const passwordInput = document.createElement('input');
                    passwordInput.type = 'password';
                    passwordInput.name = field.id;
                    passwordInput.id = field.id;
                    passwordInput.className = 'form-control';
                    passwordInput.autocomplete = 'new-password';
                    passwordInput.placeholder = field.placeholder || field.label;
                    if (field.required) passwordInput.required = true;

                    // Criar botão de toggle
                    const toggleButton = document.createElement('div');
                    toggleButton.className = 'toggle-password';
                    toggleButton.onclick = () => togglePassword(field.id, `${field.id}-icon`);

                    const iconSpan = document.createElement('span');
                    iconSpan.id = `${field.id}-icon`;

                    const icon = document.createElement('i');
                    icon.className = 'icon bi bi-eye icon';

                    iconSpan.appendChild(icon);
                    toggleButton.appendChild(iconSpan);

                    // Montar estrutura
                    wrapper.appendChild(passwordInput);
                    wrapper.appendChild(toggleButton);
                    div.appendChild(wrapper);

                } else if (field.type === 'select') {
                    const select = document.createElement('select');
                    select.id = `${field.id}_${containerId}`;
                    select.name = field.id;
                    select.className = 'form-control';
                    if (field.required) select.required = true;

                    field.options.forEach(option => {
                        const optionElement = document.createElement('option');
                        optionElement.value = option.value;
                        optionElement.textContent = option.name;
                        if (option.disabled) {
                            optionElement.disabled = true;
                            optionElement.selected = true;
                        }
                        select.appendChild(optionElement);
                    });

                    div.appendChild(select);

                } else {
                    const input = document.createElement('input');
                    input.type = field.type;
                    input.id = `${field.id}_${containerId}`;
                    input.name = field.id;
                    input.className = 'form-control';
                    if (field.required) input.required = true;
                    if (field.min !== undefined) input.min = field.min;
                    if (field.placeholder) input.placeholder = field.placeholder;
                    div.appendChild(input);
                }

                return div;
            }

            async fadeOutContainer(container) {
                return new Promise(resolve => {
                    container.classList.add('fade-out');
                    setTimeout(() => {
                        resolve();
                    }, 300);
                });
            }

            async fadeInContainer(container) {
                return new Promise(resolve => {
                    container.classList.remove('fade-out');
                    container.classList.add('show');
                    setTimeout(() => {
                        resolve();
                    }, 50);
                });
            }

            animateFields(container) {
                const fields = container.querySelectorAll('.dynamic-form-group');
                fields.forEach((field, index) => {
                    setTimeout(() => {
                        field.classList.add('show');
                    }, index * 100);
                });
            }

            async hideFields(containerId) {
                const container = document.getElementById(containerId);
                if (!container) return;

                await this.fadeOutContainer(container);

                setTimeout(() => {
                    container.innerHTML = '';
                    container.style.display = 'none';
                    container.classList.remove('show', 'fade-out');
                    this.activeContainers.delete(containerId);
                }, 300);
            }

            handleFormSubmit() {
                const form = document.getElementById('form') || document.getElementById('dynamicForm');
                if (!form) return;

                const formData = new FormData(form);
                const data = Object.fromEntries(formData.entries());
            }
        }

        // Inicialização segura
        document.addEventListener('DOMContentLoaded', function () {
            window.formularioDinamico = new FormularioDinamico();
        });

        function togglePassword(inputId, iconId) {
            const passwordField = document.getElementById(inputId);
            const toggleIcon = document.getElementById(iconId);

            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.innerHTML = `<i class="bi bi-eye-slash"></i>`;
            } else {
                passwordField.type = 'password';
                toggleIcon.innerHTML = `<i class="icon bi bi-eye"></i>`;
            }
        }