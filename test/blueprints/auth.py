from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user
from app import db
from models.user import User
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('credentials.dashboard'))
    
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(login=login).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Sua conta está desativada. Contate o administrador.', 'danger')
                return redirect(url_for('auth.login'))
            
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('credentials.dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
    
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('credentials.dashboard'))
    
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        password_confirm = request.form.get('passwordConfirm')
        
        # Validações
        if User.query.filter_by(login=login).first():
            flash('Este login já está em uso.', 'danger')
            return redirect(url_for('auth.register'))
        
        if password != password_confirm:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('auth.register'))
        
        if len(password) < 8:
            flash('A senha deve ter no mínimo 8 caracteres.', 'warning')
            return redirect(url_for('auth.register'))
        
        # Criar usuário
        user = User(login=login, role='user')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Conta criada com sucesso! Faça login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')

@auth_bp.route('/logout')
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_login = request.form.get('email_login')
        # TODO: Implementar lógica de recuperação de senha
        flash('Se este email estiver cadastrado, você receberá um link de recuperação.', 'info')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')