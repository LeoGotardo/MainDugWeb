(function() {
    'use strict';
    
    // Evitar carregamento duplo
    if (window.CUSTOM_ALERT_SYSTEM_LOADED) {
        return;
    }
    
    window.CUSTOM_ALERT_SYSTEM_LOADED = true;

    class CustomAlert {
        constructor() {
            this.currentAlert = null;
            this.resolveCallback = null;
            this.isReady = false;
            this.pendingAlerts = [];
            this.loadingInstances = new Set();
            this.initializeSystem();
        }

        async initializeSystem() {
            // Aguardar DOM estar pronto
            if (document.readyState === 'loading') {
                await new Promise(resolve => {
                    document.addEventListener('DOMContentLoaded', resolve);
                });
            }

            // Aguardar document.body estar disponível
            let bodyReady = false;
            let attempts = 0;
            const maxAttempts = 50;
            
            while (!bodyReady && attempts < maxAttempts) {
                if (document.body) {
                    bodyReady = true;
                    break;
                }
                await new Promise(resolve => setTimeout(resolve, 100));
                attempts++;
            }

            if (!bodyReady) {
                console.error('❌ document.body não disponível após timeout');
                return;
            }

            this.createStyles();
            this.isReady = true;
            
            // Processar alertas pendentes
            this.processPendingAlerts();
            
        }

        processPendingAlerts() {
            while (this.pendingAlerts.length > 0) {
                const pendingAlert = this.pendingAlerts.shift();
                this.show(pendingAlert.options).then(pendingAlert.resolve);
            }
        }

        createStyles() {
            // Remover estilos existentes primeiro
            const existingStyles = document.getElementById('custom-alert-styles');
            if (existingStyles) {
                existingStyles.remove();
            }

            const styles = document.createElement('style');
            styles.id = 'custom-alert-styles';
            styles.textContent = `
                .custom-alert-overlay {
                    position: fixed !important;
                    top: 0 !important;
                    left: 0 !important;
                    width: 100vw !important;
                    height: 100vh !important;
                    background: rgba(0, 0, 0, 0.5) !important;
                    display: flex !important;
                    justify-content: center !important;
                    align-items: center !important;
                    z-index: 2147483647 !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                    pointer-events: auto !important;
                    margin: 0 !important;
                    padding: 20px !important;
                    border: none !important;
                    transform: none !important;
                    animation: fadeIn 0.3s ease !important;
                    backdrop-filter: blur(5px) !important;
                    box-sizing: border-box !important;
                }

                .custom-alert {
                    background: white !important;
                    border: 2px solid #007bff !important;
                    border-radius: 15px !important;
                    padding: 2rem !important;
                    max-width: 450px !important;
                    width: 100% !important;
                    max-height: 90vh !important;
                    overflow-y: auto !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3) !important;
                    text-align: center !important;
                    color: #333 !important;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
                    position: relative !important;
                    z-index: 2147483648 !important;
                    margin: 0 !important;
                    transform: scale(1) !important;
                    animation: alertSlideIn 0.3s ease !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                    box-sizing: border-box !important;
                    line-height: 1.5 !important;
                }

                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }

                @keyframes alertSlideIn {
                    from { 
                        transform: scale(0.7) translateY(-50px);
                        opacity: 0;
                    }
                    to { 
                        transform: scale(1) translateY(0);
                        opacity: 1;
                    }
                }

                .custom-alert-icon {
                    font-size: 3rem !important;
                    margin-bottom: 1rem !important;
                    display: block !important;
                    line-height: 1 !important;
                }

                .custom-alert-icon.success { color: #28a745 !important; }
                .custom-alert-icon.error { color: #dc3545 !important; }
                .custom-alert-icon.warning { color: #ffc107 !important; }
                .custom-alert-icon.info { color: #17a2b8 !important; }
                .custom-alert-icon.question { color: #6f42c1 !important; }

                .custom-alert-title {
                    font-size: 1.25rem !important;
                    font-weight: 600 !important;
                    margin-bottom: 0.5rem !important;
                    color: #333 !important;
                    word-wrap: break-word !important;
                    line-height: 1.3 !important;
                }

                .custom-alert-message {
                    color: #666 !important;
                    margin-bottom: 1.5rem !important;
                    line-height: 1.5 !important;
                    word-wrap: break-word !important;
                    text-align: left !important;
                    white-space: pre-line !important;
                    font-size: 0.95rem !important;
                }

                .custom-alert-buttons {
                    display: flex !important;
                    gap: 0.5rem !important;
                    justify-content: center !important;
                    flex-wrap: wrap !important;
                    margin-top: 1rem !important;
                }

                .custom-alert-btn {
                    padding: 0.75rem 1.5rem !important;
                    border: none !important;
                    border-radius: 8px !important;
                    font-weight: 500 !important;
                    cursor: pointer !important;
                    min-width: 80px !important;
                    font-size: 0.9rem !important;
                    transition: all 0.2s ease !important;
                    text-decoration: none !important;
                    display: inline-flex !important;
                    align-items: center !important;
                    justify-content: center !important;
                }

                .custom-alert-btn.primary { background: #007bff !important; color: white !important; }
                .custom-alert-btn.danger { background: #dc3545 !important; color: white !important; }
                .custom-alert-btn.secondary { background: #6c757d !important; color: white !important; }
                .custom-alert-btn.success { background: #28a745 !important; color: white !important; }

                .custom-alert-btn:hover:not(:disabled) {
                    transform: translateY(-1px) !important;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2) !important;
                    filter: brightness(1.1) !important;
                }

                .custom-alert-btn:active {
                    transform: translateY(0) !important;
                }

                .custom-alert-btn:disabled {
                    opacity: 0.6 !important;
                    cursor: not-allowed !important;
                    transform: none !important;
                }

                .loading-spinner-custom {
                    border: 3px solid #f3f3f3 !important;
                    border-top: 3px solid #007bff !important;
                    border-radius: 50% !important;
                    width: 24px !important;
                    height: 24px !important;
                    animation: spin 1s linear infinite !important;
                    display: inline-block !important;
                    margin-right: 0.5rem !important;
                }

                .loading-spinner {
                    border: 2px solid #f3f3f3 !important;
                    border-top: 2px solid #007bff !important;
                    border-radius: 50% !important;
                    width: 16px !important;
                    height: 16px !important;
                    animation: spin 1s linear infinite !important;
                    display: inline-block !important;
                    margin-right: 0.5rem !important;
                }

                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }

                /* Responsividade */
                @media (max-width: 768px) {
                    .custom-alert-overlay {
                        padding: 10px !important;
                    }
                    
                    .custom-alert {
                        padding: 1.5rem !important;
                        max-width: none !important;
                        width: 100% !important;
                    }
                    
                    .custom-alert-buttons {
                        flex-direction: column !important;
                    }
                    
                    .custom-alert-btn {
                        width: 100% !important;
                    }
                }
            `;

            document.head.appendChild(styles);
        }

        show(options = {}) {
            return new Promise((resolve) => {
                // Se o sistema não estiver pronto, adicionar à fila
                if (!this.isReady) {
                    this.pendingAlerts.push({ options, resolve });
                    return;
                }

                // Fechar alert anterior se existir
                this.close();

                const {
                    type = 'info',
                    title = '',
                    message = '',
                    buttons = [{ text: 'OK', type: 'primary' }],
                    allowBackdropClose = true
                } = options;

                const icons = {
                    success: '✅',
                    error: '❌',
                    warning: '⚠️',
                    info: 'ℹ️',
                    question: '❓'
                };

                // Criar overlay
                const overlay = document.createElement('div');
                overlay.className = 'custom-alert-overlay';
                overlay.id = 'custom-alert-overlay-' + Date.now();
                
                this.currentAlert = overlay;
                this.resolveCallback = resolve;

                // Criar estrutura do alert
                const alertDiv = document.createElement('div');
                alertDiv.className = 'custom-alert';

                // Ícone
                const iconDiv = document.createElement('div');
                iconDiv.className = `custom-alert-icon ${type}`;
                iconDiv.textContent = icons[type] || icons.info;
                alertDiv.appendChild(iconDiv);

                // Título (se fornecido)
                if (title) {
                    const titleDiv = document.createElement('div');
                    titleDiv.className = 'custom-alert-title';
                    titleDiv.textContent = title;
                    alertDiv.appendChild(titleDiv);
                }

                // Mensagem
                const messageDiv = document.createElement('div');
                messageDiv.className = 'custom-alert-message';
                messageDiv.textContent = message;
                alertDiv.appendChild(messageDiv);

                // Botões
                const buttonsDiv = document.createElement('div');
                buttonsDiv.className = 'custom-alert-buttons';

                buttons.forEach((btn, index) => {
                    const button = document.createElement('button');
                    button.className = `custom-alert-btn ${btn.type || 'primary'}`;
                    button.textContent = btn.text;
                    button.dataset.action = index.toString();
                    buttonsDiv.appendChild(button);
                });

                alertDiv.appendChild(buttonsDiv);
                overlay.appendChild(alertDiv);

                // Event listeners
                let isProcessing = false;
                
                const handleClick = (e) => {
                    e.stopPropagation();
                    
                    if (isProcessing) return;

                    if (e.target.classList.contains('custom-alert-btn')) {
                        isProcessing = true;
                        const action = parseInt(e.target.dataset.action);
                        this.resolveAlert(action === 0);
                    } else if (e.target === overlay && allowBackdropClose) {
                        this.resolveAlert(false);
                    }
                };

                overlay.addEventListener('click', handleClick);

                // Suporte a teclado
                const handleKeyPress = (e) => {
                    if (this.currentAlert !== overlay) return;
                    
                    if (e.key === 'Escape' && allowBackdropClose) {
                        this.resolveAlert(false);
                    } else if (e.key === 'Enter') {
                        const firstButton = overlay.querySelector('.custom-alert-btn');
                        if (firstButton && !isProcessing) {
                            firstButton.click();
                        }
                    }
                };
                
                document.addEventListener('keydown', handleKeyPress);
                overlay._keyHandler = handleKeyPress;

                // Inserir no DOM
                document.body.appendChild(overlay);

                // Focus no primeiro botão após um pequeno delay
                setTimeout(() => {
                    const firstButton = overlay.querySelector('.custom-alert-btn');
                    if (firstButton) {
                        firstButton.focus();
                    }
                }, 100);

            });
        }

        resolveAlert(result) {
            if (this.resolveCallback) {
                this.resolveCallback(result);
                this.resolveCallback = null;
            }
            this.close();
        }

        close() {
            if (!this.currentAlert) return;

            const overlay = this.currentAlert;
            
            // Remover event listener de teclado
            if (overlay._keyHandler) {
                document.removeEventListener('keydown', overlay._keyHandler);
            }
            
            // Animar saída
            overlay.style.opacity = '0';
            overlay.style.transform = 'scale(0.9)';
            
            setTimeout(() => {
                if (overlay.parentNode) {
                    overlay.parentNode.removeChild(overlay);
                }
            }, 300);

            this.currentAlert = null;
        }

        // Métodos de conveniência
        confirm(message, title = 'Confirmação', options = {}) {
            return this.show({
                type: 'question',
                title,
                message,
                buttons: [
                    { text: options.confirmText || 'Confirmar', type: 'danger' },
                    { text: options.cancelText || 'Cancelar', type: 'secondary' }
                ],
                ...options
            });
        }

        success(message, title = 'Sucesso', options = {}) {
            return this.show({
                type: 'success',
                title,
                message,
                buttons: [{ text: 'OK', type: 'success' }],
                ...options
            });
        }

        error(message, title = 'Erro', options = {}) {
            return this.show({
                type: 'error',
                title,
                message,
                buttons: [{ text: 'OK', type: 'danger' }],
                ...options
            });
        }

        warning(message, title = 'Atenção', options = {}) {
            return this.show({
                type: 'warning',
                title,
                message,
                buttons: [{ text: 'OK', type: 'primary' }],
                ...options
            });
        }

        info(message, title = 'Informação', options = {}) {
            return this.show({
                type: 'info',
                title,
                message,
                buttons: [{ text: 'OK', type: 'primary' }],
                ...options
            });
        }

        loading(message = 'Processando...', title = '') {
            // Fechar loading anterior se existir
            this.closeAllLoading();

            const overlay = document.createElement('div');
            overlay.className = 'custom-alert-overlay';
            overlay.id = 'custom-alert-loading-' + Date.now();
            
            // Adicionar à lista de loading instances
            this.loadingInstances.add(overlay);

            const alertDiv = document.createElement('div');
            alertDiv.className = 'custom-alert';
            alertDiv.style.minHeight = '120px';

            // Spinner
            const spinnerDiv = document.createElement('div');
            spinnerDiv.className = 'loading-spinner-custom';
            spinnerDiv.style.marginBottom = '1rem';

            // Mensagem
            const messageDiv = document.createElement('div');
            messageDiv.className = 'custom-alert-message';
            messageDiv.style.textAlign = 'center';
            messageDiv.style.marginBottom = title ? '0.5rem' : '0';
            messageDiv.textContent = message;

            alertDiv.appendChild(spinnerDiv);
            alertDiv.appendChild(messageDiv);

            // Título (se fornecido)
            if (title) {
                const titleDiv = document.createElement('div');
                titleDiv.className = 'custom-alert-title';
                titleDiv.style.marginTop = '1rem';
                titleDiv.textContent = title;
                alertDiv.appendChild(titleDiv);
            }

            overlay.appendChild(alertDiv);
            document.body.appendChild(overlay);

            const loadingInstance = {
                close: () => {
                    this.loadingInstances.delete(overlay);
                    if (overlay.parentNode) {
                        overlay.parentNode.removeChild(overlay);
                    }
                },
                updateMessage: (newMessage) => {
                    messageDiv.textContent = newMessage;
                }
            };

            return loadingInstance;
        }

        closeAllLoading() {
            this.loadingInstances.forEach(overlay => {
                if (overlay.parentNode) {
                    overlay.parentNode.removeChild(overlay);
                }
            });
            this.loadingInstances.clear();
        }
    }

    // =============================================================================
    // INSTÂNCIA GLOBAL E FUNÇÕES DE CONVENIÊNCIA
    // =============================================================================

    window.CustomAlert = CustomAlert;
    window.customAlert = new CustomAlert();

    // Funções globais principais
    window.showAlert = function(type, title, message, options = {}) {
        return window.customAlert[type] ? 
               window.customAlert[type](message, title, options) : 
               window.customAlert.info(message, title, options);
    };

    window.showConfirm = function(title = 'Confirmação', message = 'Tem certeza que deseja continuar?', options = {}) {
        return window.customAlert.confirm(message, title, options);
    };

    window.showLoading = function(message = 'Processando...', title = '') {
        return window.customAlert.loading(message, title);
    };

    // =============================================================================
    // FUNÇÕES WRAPPER SEGURAS (GLOBAIS)
    // =============================================================================

    window.safeAlert = function(type, title, message) {
        if (window.customAlert && window.customAlert.isReady) {
            return window.customAlert[type] ? 
                   window.customAlert[type](message, title) : 
                   window.customAlert.info(message, title);
        } else {
            alert(`${title}: ${message}`);
            return Promise.resolve();
        }
    };

    window.safeConfirm = function(title, message) {
        if (window.customAlert && window.customAlert.isReady) {
            return window.customAlert.confirm(message, title);
        } else {
            return Promise.resolve(confirm(`${title}\n\n${message}`));
        }
    };

    window.safeLoading = function(message) {
        if (window.customAlert && window.customAlert.isReady) {
            return window.customAlert.loading(message);
        } else {
            console.log('Loading:', message);
            return { 
                close: () => console.log('Loading finished'),
                updateMessage: (msg) => console.log('Loading update:', msg)
            };
        }
    };

    // =============================================================================
    // FUNÇÃO SUBMITBTN MELHORADA (GLOBAL)
    // =============================================================================

    window.submitBtn = async function(url = '', method = '', options = {}, item = '') {
        const {
            confirm = null, 
            confirmMessage = null, 
            confirmTitle = null, 
            
            loadingMessage = 'Processando...',
            buttonText = 'Processando...',
            
            successMessage = 'Ação executada com sucesso!',
            successTitle = 'Sucesso',
            errorMessage = 'Erro ao executar a ação',
            errorTitle = 'Erro',
            
            redirect = null,
            reload = false,
            
            buttonElement = null,
            
            data = null,
            
            headers = {},
            
            forceConfirm = false, 
            skipConfirm = false 
        } = options;

        let loadingModal = null;

        try {
            
            // Aguardar sistema de alertas estar pronto
            let alertsReady = false;
            let attempts = 0;
            const maxAttempts = 100;
            
            while (!alertsReady && attempts < maxAttempts) {
                if (window.customAlert && window.customAlert.isReady) {
                    alertsReady = true;
                    break;
                }
                await new Promise(resolve => setTimeout(resolve, 50));
                attempts++;
            }

            // === DETERMINAR SE PRECISA DE CONFIRMAÇÃO ===
            let needsConfirm = confirm;
            let finalConfirmMessage = confirmMessage;
            let finalConfirmTitle = confirmTitle;

            // Configuração automática baseada no método
            if (needsConfirm === null) {
                needsConfirm = ['DELETE', 'PATCH'].includes(method.toUpperCase()) || forceConfirm;
            }

            // Aplicar skipConfirm se especificado
            if (skipConfirm) {
                needsConfirm = false;
            }

            // Mensagens automáticas baseadas no método
            if (needsConfirm && !finalConfirmMessage) {
                switch (method.toUpperCase()) {
                    case 'DELETE':
                        finalConfirmMessage = 'Tem certeza que deseja excluir este item? Esta ação não pode ser desfeita.';
                        finalConfirmTitle = 'Confirmar Exclusão';
                        break;
                    case 'PATCH':
                        finalConfirmMessage = 'Tem certeza que deseja atualizar este item?';
                        finalConfirmTitle = 'Confirmar Atualização';
                        break;
                    case 'PUT':
                        finalConfirmMessage = 'Tem certeza que deseja modificar este item?';
                        finalConfirmTitle = 'Confirmar Modificação';
                        break;
                    default:
                        finalConfirmMessage = 'Tem certeza que deseja executar esta ação?';
                        finalConfirmTitle = 'Confirmar Ação';
                }
            }

            // === HANDLE REDIRECT ===
            if (method === 'redirect') {
                if (needsConfirm) {
                    const confirmed = await window.safeConfirm(
                        finalConfirmTitle || 'Confirmar Navegação',
                        finalConfirmMessage || 'Tem certeza que deseja navegar para esta página?'
                    );
                    if (!confirmed) {
                        return;
                    }
                }
                window.location.href = url;
                return;
            }

            // === CONFIRMAÇÃO (se necessária) ===
            if (needsConfirm) {
                const confirmed = await window.safeConfirm(finalConfirmTitle, finalConfirmMessage);
                if (!confirmed) {
                    return;
                }
            }

            // === OBTER ELEMENTO DO BOTÃO ===
            const button = buttonElement || (window.event && window.event.target);
            let originalContent = '';

            // === ATUALIZAR BOTÃO (loading state) ===
            if (button) {
                originalContent = button.innerHTML;
                
                // Texto do botão baseado no método
                let loadingText = buttonText;
                switch (method.toUpperCase()) {
                    case 'DELETE':
                        loadingText = 'Excluindo...';
                        break;
                    case 'POST':
                        loadingText = 'Carregando...';
                        break;
                    case 'PUT':
                    case 'PATCH':
                        loadingText = 'Atualizando...';
                        break;
                    case 'INTERNAL':
                        loadingText = 'Processando...';
                        break;
                    default:
                        loadingText = buttonText;
                }
                
                button.innerHTML = `<div class="loading-spinner"></div>${loadingText}`;
                button.disabled = true;
            }

            // === MOSTRAR LOADING MODAL ===
            // Mensagem de loading baseada no método
            let finalLoadingMessage = loadingMessage;
            if (loadingMessage === 'Processando...') {
                switch (method.toUpperCase()) {
                    case 'DELETE':
                        finalLoadingMessage = 'Excluindo item...';
                        break;
                    case 'POST':
                        finalLoadingMessage = 'Carregando solicitação...';
                        break;
                    case 'PUT':
                    case 'PATCH':
                        finalLoadingMessage = 'Atualizando item...';
                        break;
                    default:
                        finalLoadingMessage = 'Processando solicitação...';
                }
            }
            
            loadingModal = window.safeLoading(finalLoadingMessage);
            
            // === HANDLE INTERNAL METHODS ===
            if (method === 'INTERNAL') {
                if (url === 'copy') {
                    try {
                        await navigator.clipboard.writeText(item);
                        if (loadingModal && loadingModal.close) {
                            loadingModal.close();
                        }
                        await window.safeAlert('success', 'Sucesso', 'Item copiado com sucesso!');
                    } catch (err) {
                        if (loadingModal && loadingModal.close) {
                            loadingModal.close();
                        }
                        console.error('Erro ao copiar:', err);
                        await window.safeAlert('error', 'Erro', 'Erro ao copiar item');
                    }
                }
                
                // Restaurar botão
                if (button && originalContent) {
                    button.innerHTML = originalContent;
                    button.disabled = false;
                }
                return;
            }

            // === PREPARAR HEADERS ===
            const requestHeaders = {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                ...headers
            };

            // === PREPARAR BODY ===
            const requestOptions = {
                method: method.toUpperCase(),
                headers: requestHeaders
            };

            // Adicionar body para métodos que suportam
            if (data && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
                requestOptions.body = JSON.stringify(data);
            }

            // === FAZER REQUISIÇÃO ===
            const response = await fetch(url, requestOptions);

            // === FECHAR LOADING ===
            if (loadingModal && loadingModal.close) {
                loadingModal.close();
            }

            // === TRATAR RESPOSTA ===
            if (response.ok) {
                
                // Tentar obter resposta JSON
                let responseData = {};
                try {
                    responseData = await response.json();
                } catch (e) {
                    // Mensagem padrão baseada no método
                    let defaultMessage = successMessage;
                    switch (method.toUpperCase()) {
                        case 'DELETE':
                            defaultMessage = 'Item excluído com sucesso!';
                            break;
                        case 'POST':
                            defaultMessage = 'Item criado com sucesso!';
                            break;
                        case 'PUT':
                        case 'PATCH':
                            defaultMessage = 'Item atualizado com sucesso!';
                            break;
                    }
                    responseData = { message: defaultMessage };
                }

                // Título de sucesso baseado no método
                let finalSuccessTitle = successTitle;
                if (successTitle === 'Sucesso') {
                    switch (method.toUpperCase()) {
                        case 'DELETE':
                            finalSuccessTitle = 'Exclusão Realizada';
                            break;
                        case 'POST':
                            finalSuccessTitle = 'Criação Realizada';
                            break;
                        case 'PUT':
                        case 'PATCH':
                            finalSuccessTitle = 'Atualização Realizada';
                            break;
                    }
                }

                // Mostrar sucesso
                await window.safeAlert(
                    'success',
                    finalSuccessTitle,
                    responseData.message || successMessage
                );

                // Navegação pós-sucesso
                if (redirect) {
                    window.location.href = redirect;
                } else if (reload) {
                    window.location.reload();
                } else {
                    // Restaurar botão se não vai recarregar/redirecionar
                    if (button && originalContent) {
                        button.innerHTML = originalContent;
                        button.disabled = false;
                    }
                }

            } else {
                // === TRATAR ERRO ===
                console.error('❌ Resposta de erro:', response.status, response.statusText);
                
                let errorData = {};
                try {
                    errorData = await response.json();
                    console.error('❌ Dados do erro:', errorData);
                } catch (e) {
                    errorData = { 
                        message: `${errorMessage} (${response.status}: ${response.statusText})` 
                    };
                }

                // Título de erro baseado no método
                let finalErrorTitle = errorTitle;
                if (errorTitle === 'Erro') {
                    switch (method.toUpperCase()) {
                        case 'DELETE':
                            finalErrorTitle = 'Erro na Exclusão';
                            break;
                        case 'POST':
                            finalErrorTitle = 'Erro na Criação';
                            break;
                        case 'PUT':
                        case 'PATCH':
                            finalErrorTitle = 'Erro na Atualização';
                            break;
                    }
                }

                // Mostrar erro
                await window.safeAlert(
                    'error',
                    finalErrorTitle,
                    errorData.message || errorMessage
                );

                // Restaurar botão
                if (button && originalContent) {
                    button.innerHTML = originalContent;
                    button.disabled = false;
                }
            }

        } catch (error) {
            // === TRATAR ERRO DE REDE ===
            console.error('❌ Erro na execução:', error);
            
            // Fechar loading se ainda estiver aberto
            if (loadingModal && loadingModal.close) {
                loadingModal.close();
            }
            
            await window.safeAlert(
                'error',
                'Erro de Rede',
                error.message || 'Erro de conexão. Verifique sua internet e tente novamente.'
            );

            // Restaurar botão
            const button = buttonElement || (window.event && window.event.target);
            if (button) {
                // Usar originalContent ou tentar restaurar
                const originalText = button.dataset.originalText || 'Tentar Novamente';
                button.innerHTML = originalText;
                button.disabled = false;
            }
        }
    };

    // =============================================================================
    // CONFIGURAÇÃO DE BOTÕES COM DATA ATTRIBUTES
    // =============================================================================

    function setupActionButtons() {
        if (!document.body) {
            console.warn('⚠️ document.body não disponível para configurar botões');
            return;
        }

        
        document.querySelectorAll('[data-action-url]:not([data-action-configured])').forEach((button, index) => {
            // Marcar como configurado
            button.dataset.actionConfigured = 'true';
            button.dataset.originalText = button.innerHTML;
            
            button.addEventListener('click', function(e) {
                e.preventDefault();
                
                const url = this.dataset.actionUrl;
                const method = this.dataset.actionMethod || 'POST';
                const confirm = this.dataset.actionConfirm === 'true';
                const skipConfirm = this.dataset.actionSkipConfirm === 'true';
                const message = this.dataset.actionMessage;
                const title = this.dataset.actionTitle;
                const redirect = this.dataset.actionRedirect;
                const reload = this.dataset.actionReload === 'true';
                
                const options = {
                    buttonElement: this,
                    redirect,
                    reload
                };

                // Configurar confirmação
                if (confirm !== undefined) {
                    options.forceConfirm = confirm;
                }
                if (skipConfirm) {
                    options.skipConfirm = true;
                }
                if (message) {
                    options.confirmMessage = message;
                }
                if (title) {
                    options.confirmTitle = title;
                }
                
                window.submitBtn(url, method, options);
            });
        });
        
    }

    // Aguardar DOM e body estarem prontos
    async function initializeButtons() {
        // Aguardar DOM
        if (document.readyState === 'loading') {
            await new Promise(resolve => {
                document.addEventListener('DOMContentLoaded', resolve);
            });
        }

        // Aguardar body
        let bodyReady = false;
        let attempts = 0;
        const maxAttempts = 50;
        
        while (!bodyReady && attempts < maxAttempts) {
            if (document.body) {
                bodyReady = true;
                break;
            }
            await new Promise(resolve => setTimeout(resolve, 100));
            attempts++;
        }

        if (bodyReady) {
            setupActionButtons();
            
            // Observer para novos botões
            const actionButtonsObserver = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                        // Verificar se foram adicionados novos botões
                        const hasNewButtons = Array.from(mutation.addedNodes).some(node => {
                            if (node.nodeType === 1) { // Element node
                                return node.querySelector && (
                                    node.querySelector('[data-action-url]:not([data-action-configured])') || 
                                    (node.hasAttribute && node.hasAttribute('data-action-url') && !node.dataset.actionConfigured)
                                );
                            }
                            return false;
                        });
                        
                        if (hasNewButtons) {
                            setTimeout(setupActionButtons, 100);
                        }
                    }
                });
            });

            actionButtonsObserver.observe(document.body, {
                childList: true,
                subtree: true
            });
        } else {
            console.error('❌ document.body não disponível após timeout');
        }
    }

    // Inicializar botões
    initializeButtons();

    // Funções de notificação (compatibilidade com sistema SSE)
    window.showNotification = function(type = 'info', title = '', message = '', duration = 5000) {
        // Se o sistema de notificações SSE estiver disponível, usar ele
        if (window.notificationSystem && typeof window.notificationSystem.show === 'function') {
            return window.notificationSystem.show(type, title, message, duration);
        } else {
            // Fallback para alert customizado
            return window.customAlert[type] ? 
                   window.customAlert[type](message, title) : 
                   window.customAlert.info(message, title);
        }
    };

})();