// =============================================================================
// SISTEMA DE BOTÕES SIMPLIFICADO
// Este arquivo deve ser carregado APÓS o alert.js
// =============================================================================

(function() {
    'use strict';

    // Verificar se o sistema de alertas está disponível
    if (!window.submitBtn) {
        console.warn('⚠️ Sistema de alertas (alert.js) não encontrado. Carregue alert.js primeiro.');
        
        // Função fallback básica
        window.submitBtn = async function(url, method, options) {
            alert('Ocorreu um erro inesperado. Tente novamente.');
        };
    }

    // =============================================================================
    // UTILITÁRIOS ESPECÍFICOS PARA BOTÕES
    // =============================================================================

    // Função para extrair dados de formulário
    window.getFormData = function(formElement) {
        if (!formElement) return {};
        
        const formData = new FormData(formElement);
        const data = {};
        
        for (let [key, value] of formData.entries()) {
            // Tratar checkboxes e múltiplos valores
            if (data[key]) {
                if (Array.isArray(data[key])) {
                    data[key].push(value);
                } else {
                    data[key] = [data[key], value];
                }
            } else {
                data[key] = value;
            }
        }
        
        return data;
    };

    // Função para submeter formulários via AJAX
    window.submitForm = function(formElement, options = {}) {
        if (!formElement) {
            console.error('❌ Elemento de formulário não fornecido');
            return;
        }

        const url = options.url || formElement.action || window.location.href;
        const method = options.method || formElement.method || 'POST';
        const data = getFormData(formElement);

        const submitOptions = {
            data,
            buttonElement: options.buttonElement,
            ...options
        };

        return window.submitBtn(url, method, submitOptions);
    };

    // =============================================================================
    // AÇÕES ESPECÍFICAS PARA DIFERENTES TIPOS DE BOTÕES
    // =============================================================================

    // Função para botões de exclusão
    window.deleteItem = function(url, options = {}) {
        const deleteOptions = {
            forceConfirm: true,
            confirmTitle: 'Confirmar Exclusão',
            confirmMessage: 'Tem certeza que deseja excluir este item? Esta ação não pode ser desfeita.',
            successMessage: 'Item excluído com sucesso!',
            ...options
        };

        return window.submitBtn(url, 'DELETE', deleteOptions);
    };

    // Função para botões de ativação/desativação
    window.toggleStatus = function(url, options = {}) {
        const toggleOptions = {
            forceConfirm: true,
            confirmTitle: 'Confirmar Alteração',
            confirmMessage: 'Tem certeza que deseja alterar o status deste item?',
            successMessage: 'Status alterado com sucesso!',
            ...options
        };

        return window.submitBtn(url, 'PATCH', toggleOptions);
    };

    // Função para botões de duplicação
    window.duplicateItem = function(url, options = {}) {
        const duplicateOptions = {
            confirm: false,
            successMessage: 'Item duplicado com sucesso!',
            ...options
        };

        return window.submitBtn(url, 'POST', duplicateOptions);
    };

    // Função para botões de download
    window.downloadFile = function(url, filename = null) {
        const link = document.createElement('a');
        link.href = url;
        if (filename) {
            link.download = filename;
        }
        link.target = '_blank';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    // =============================================================================
    // CONFIGURAÇÃO AUTOMÁTICA DE BOTÕES ESPECIAIS
    // =============================================================================

    function setupSpecialButtons() {
        if (!document.body) return;

        // Botões de exclusão
        document.querySelectorAll('[data-delete-url]:not([data-special-configured])').forEach(button => {
            button.dataset.specialConfigured = 'true';
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const url = this.dataset.deleteUrl;
                const message = this.dataset.deleteMessage;
                const title = this.dataset.deleteTitle;
                
                deleteItem(url, {
                    buttonElement: this,
                    confirmMessage: message,
                    confirmTitle: title
                });
            });
        });

        // Botões de toggle status
        document.querySelectorAll('[data-toggle-url]:not([data-special-configured])').forEach(button => {
            button.dataset.specialConfigured = 'true';
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const url = this.dataset.toggleUrl;
                const message = this.dataset.toggleMessage;
                const title = this.dataset.toggleTitle;
                
                toggleStatus(url, {
                    buttonElement: this,
                    confirmMessage: message,
                    confirmTitle: title
                });
            });
        });

        // Botões de duplicação
        document.querySelectorAll('[data-duplicate-url]:not([data-special-configured])').forEach(button => {
            button.dataset.specialConfigured = 'true';
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const url = this.dataset.duplicateUrl;
                
                duplicateItem(url, {
                    buttonElement: this
                });
            });
        });

        // Botões de download
        document.querySelectorAll('[data-download-url]:not([data-special-configured])').forEach(button => {
            button.dataset.specialConfigured = 'true';
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const url = this.dataset.downloadUrl;
                const filename = this.dataset.downloadFilename;
                
                downloadFile(url, filename);
            });
        });

        // Botões de cópia
        document.querySelectorAll('[data-copy-text]:not([data-special-configured])').forEach(button => {
            button.dataset.specialConfigured = 'true';
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const text = this.dataset.copyText;
                
                window.submitBtn('copy', 'INTERNAL', {
                    buttonElement: this
                }, text);
            });
        });

        // Formulários com submit automático
        document.querySelectorAll('form[data-ajax-submit]:not([data-special-configured])').forEach(form => {
            form.dataset.specialConfigured = 'true';
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const submitButton = this.querySelector('[type="submit"]');
                submitForm(this, {
                    buttonElement: submitButton
                });
            });
        });
    }

    // =============================================================================
    // INICIALIZAÇÃO
    // =============================================================================

    async function initializeSpecialButtons() {
        // Aguardar DOM e body estarem prontos
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
            setupSpecialButtons();
            
            // Observer para novos botões especiais
            const specialButtonsObserver = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                        const hasNewSpecialButtons = Array.from(mutation.addedNodes).some(node => {
                            if (node.nodeType === 1) {
                                return node.querySelector && (
                                    node.querySelector('[data-delete-url]:not([data-special-configured])') ||
                                    node.querySelector('[data-toggle-url]:not([data-special-configured])') ||
                                    node.querySelector('[data-duplicate-url]:not([data-special-configured])') ||
                                    node.querySelector('[data-download-url]:not([data-special-configured])') ||
                                    node.querySelector('[data-copy-text]:not([data-special-configured])') ||
                                    node.querySelector('form[data-ajax-submit]:not([data-special-configured])')
                                );
                            }
                            return false;
                        });
                        
                        if (hasNewSpecialButtons) {
                            setTimeout(setupSpecialButtons, 100);
                        }
                    }
                });
            });

            specialButtonsObserver.observe(document.body, {
                childList: true,
                subtree: true
            });

        } else {
            console.error('❌ document.body não disponível para botões especiais');
        }
    }

    // Inicializar
    initializeSpecialButtons();

    // =============================================================================
    // UTILITÁRIOS DE VALIDAÇÃO
    // =============================================================================

    // Validar formulário antes de submeter
    window.validateForm = function(formElement) {
        if (!formElement) return false;

        const requiredFields = formElement.querySelectorAll('[required]');
        let isValid = true;
        let firstInvalidField = null;

        requiredFields.forEach(field => {
            if (!field.value.trim()) {
                isValid = false;
                field.classList.add('is-invalid');
                if (!firstInvalidField) {
                    firstInvalidField = field;
                }
            } else {
                field.classList.remove('is-invalid');
            }
        });

        // Focar no primeiro campo inválido
        if (firstInvalidField) {
            firstInvalidField.focus();
            firstInvalidField.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        return isValid;
    };

})();