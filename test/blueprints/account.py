from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import current_user
from werkzeug.utils import secure_filename
from app import db
import os
import re


account_bp = Blueprint('account', __name__)


def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@account_bp.route('/', methods=['GET', 'POST'])
def profile():
    """Página de perfil do usuário"""
    from utils.decorators import login_required, active_user_required
    
    @login_required
    @active_user_required
    def _profile():
        if request.method == 'POST':
            # Atualizar login
            new_login = request.form.get('login')
            if new_login and new_login != current_user.login:
                # Verificar se já existe
                from models.user import User
                existing = User.query.filter_by(login=new_login).first()
                if existing:
                    flash('Este login já está em uso.', 'danger')
                else:
                    current_user.login = new_login
            
            # Atualizar email de recuperação
            email = request.form.get('acc-email', '').strip()
            if email:
                # Validar email com regex
                email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
                if re.match(email_regex, email):
                    current_user.email_recovery = email
                else:
                    flash('Email inválido.', 'warning')
            
            # Atualizar senha
            new_password = request.form.get('password')
            password_confirm = request.form.get('passwordConfirm')
            
            if new_password:
                if new_password != password_confirm:
                    flash('As senhas não coincidem.', 'danger')
                    return redirect(url_for('account.profile'))
                
                if len(new_password) < 8:
                    flash('A senha deve ter no mínimo 8 caracteres.', 'warning')
                    return redirect(url_for('account.profile'))
                
                current_user.set_password(new_password)
                flash('Senha atualizada com sucesso!', 'success')
            
            # Foto de perfil
            if 'profilePic' in request.files:
                file = request.files['profilePic']
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(f"user_{current_user.id}_{file.filename}")
                    upload_folder = 'static/uploads/profiles'
                    os.makedirs(upload_folder, exist_ok=True)
                    
                    file_path = os.path.join(upload_folder, filename)
                    file.save(file_path)
                    
                    current_user.profile_photo = f'/static/uploads/profiles/{filename}'
            
            db.session.commit()
            flash('Perfil atualizado com sucesso!', 'success')
            return redirect(url_for('account.profile'))
        
        return render_template('account/profile.html')
    
    return _profile()


@account_bp.route('/preferences', methods=['POST'])
def update_preferences():
    """Atualiza preferências de tema e cor"""
    from utils.decorators import login_required
    
    @login_required
    def _update():
        theme = request.form.get('theme')
        color = request.form.get('accent_color')
        
        if theme in ['light', 'dark']:
            current_user.theme_preference = theme
        
        if color and color.startswith('#') and len(color) == 7:
            current_user.accent_color = color
        
        db.session.commit()
        
        flash('Preferências salvas!', 'success')
        return redirect(url_for('account.profile'))
    
    return _update()