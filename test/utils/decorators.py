from functools import wraps
from flask import redirect, url_for, flash, abort
from flask_login import current_user

def login_required(f):
    """Requer que o usuário esteja autenticado"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Requer que o usuário seja admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('auth.login'))
        
        if not current_user.is_admin():
            flash('Acesso negado. Apenas administradores podem acessar esta página.', 'danger')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def active_user_required(f):
    """Requer que o usuário esteja ativo"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('auth.login'))
        
        if not current_user.is_active:
            flash('Sua conta está desativada. Contate o administrador.', 'danger')
            return redirect(url_for('auth.logout'))
        
        return f(*args, **kwargs)
    return decorated_function