class CustomAlert {
    constructor() {
        this.createStyles();
    }

    createStyles() {
        if (document.getElementById('custom-alert-styles')) return;

        const styles = `
            <style id="custom-alert-styles">
                .custom-alert-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.5);
                    backdrop-filter: blur(5px);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    z-index: 10000;
                    opacity: 0;
                    transition: opacity 0.3s ease;
                }

                .custom-alert-overlay.show {
                    opacity: 1;
                }

                .custom-alert {
                    background: white;
                    border-radius: 15px;
                    padding: 2rem;
                    max-width: 400px;
                    width: 90%;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    transform: scale(0.7);
                    transition: transform 0.3s ease;
                    text-align: center;
                }

                .custom-alert-overlay.show .custom-alert {
                    transform: scale(1);
                }

                .custom-alert-icon {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                }

                .custom-alert-icon.success { color: #28a745; }
                .custom-alert-icon.error { color: #dc3545; }
                .custom-alert-icon.warning { color: #ffc107; }
                .custom-alert-icon.info { color: #17a2b8; }
                .custom-alert-icon.question { color: #6f42c1; }

                .custom-alert-title {
                    font-size: 1.25rem;
                    font-weight: 600;
                    margin-bottom: 0.5rem;
                    color: #333;
                }

                .custom-alert-message {
                    color: #666;
                    margin-bottom: 1.5rem;
                    line-height: 1.5;
                }

                .custom-alert-buttons {
                    display: flex;
                    gap: 0.5rem;
                    justify-content: center;
                }

                .custom-alert-btn {
                    padding: 0.75rem 1.5rem;
                    border: none;
                    border-radius: 8px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    min-width: 80px;
                }

                .custom-alert-btn.primary {
                    background: #007bff;
                    color: white;
                }

                .custom-alert-btn.danger {
                    background: #dc3545;
                    color: white;
                }

                .custom-alert-btn.secondary {
                    background: #6c757d;
                    color: white;
                }

                .custom-alert-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
                }

                .loading-spinner {
                    border: 3px solid #f3f3f3;
                    border-top: 3px solid #007bff;
                    border-radius: 50%;
                    width: 20px;
                    height: 20px;
                    animation: spin 1s linear infinite;
                    display: inline-block;
                    margin-right: 0.5rem;
                }

                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;

        document.head.insertAdjacentHTML('beforeend', styles);
    }

    show(options) {
        const {
            type = 'info',
            title = '',
            message = '',
            buttons = [{ text: 'OK', type: 'primary' }],
            onConfirm = null,
            onCancel = null
        } = options;

        return new Promise((resolve) => {
            // Remover alert anterior se existir
            this.close();

            const icons = {
                success: '✅',
                error: '❌',
                warning: '⚠️',
                info: 'ℹ️',
                question: '❓'
            };

            const overlay = document.createElement('div');
            overlay.className = 'custom-alert-overlay';
            overlay.id = 'custom-alert-overlay';

            const buttonsHtml = buttons.map((btn, index) => `
                <button class="custom-alert-btn ${btn.type || 'primary'}" data-action="${index}">
                    ${btn.text}
                </button>
            `).join('');

            overlay.innerHTML = `
                <div class="custom-alert">
                    <div class="custom-alert-icon ${type}">${icons[type] || icons.info}</div>
                    ${title ? `<div class="custom-alert-title">${title}</div>` : ''}
                    <div class="custom-alert-message">${message}</div>
                    <div class="custom-alert-buttons">
                        ${buttonsHtml}
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);

            // Animação de entrada
            setTimeout(() => overlay.classList.add('show'), 10);

            // Event listeners para botões
            overlay.addEventListener('click', (e) => {
                if (e.target.classList.contains('custom-alert-btn')) {
                    const action = parseInt(e.target.dataset.action);
                    const button = buttons[action];
                    
                    if (button.action) {
                        button.action();
                    }

                    if (action === 0 && onConfirm) {
                        onConfirm();
                    } else if (action === 1 && onCancel) {
                        onCancel();
                    }

                    resolve(action === 0);
                    this.close();
                }

                if (e.target === overlay) {
                    resolve(false);
                    this.close();
                }
            });
        });
    }

    close() {
        const overlay = document.getElementById('custom-alert-overlay');
        if (overlay) {
            overlay.classList.remove('show');
            setTimeout(() => overlay.remove(), 300);
        }
    }

    confirm(message, title = 'Confirmação') {
        return this.show({
            type: 'question',
            title,
            message,
            buttons: [
                { text: 'Confirmar', type: 'danger' },
                { text: 'Cancelar', type: 'secondary' }
            ]
        });
    }

    success(message, title = 'Sucesso') {
        return this.show({
            type: 'success',
            title,
            message,
            buttons: [{ text: 'OK', type: 'primary' }]
        });
    }

    error(message, title = 'Erro') {
        return this.show({
            type: 'error',
            title,
            message,
            buttons: [{ text: 'OK', type: 'danger' }]
        });
    }

    loading(message = 'Processando...') {
        this.close();

        const overlay = document.createElement('div');
        overlay.className = 'custom-alert-overlay show';
        overlay.id = 'custom-alert-overlay';

        overlay.innerHTML = `
            <div class="custom-alert">
                <div class="loading-spinner"></div>
                <div class="custom-alert-message">${message}</div>
            </div>
        `;

        document.body.appendChild(overlay);
    }
}

// Instância global
const customAlert = new CustomAlert();