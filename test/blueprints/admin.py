from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import current_user
from app import db
from models.user import User
from utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users')
@admin_required
def list_users():
    """Lista todos os usuários (apenas admin)"""
    users = User.query.all()
    
    stats = {
        'total': len(users),
        'active': len([u for u in users if u.is_active]),
        'admins': len([u for u in users if u.role == 'sysadmin'])
    }
    
    return render_template('admin/users.html', users=users, stats=stats)

@admin_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    """Adiciona um novo usuário"""
    login = request.form.get('login')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    is_active = request.form.get('enabled') == 'on'
    
    # Validações
    if User.query.filter_by(login=login).first():
        flash('Este login já está em uso.', 'danger')
        return redirect(url_for('admin.list_users'))
    
    if role not in ['user', 'sysadmin']:
        role = 'user'
    
    # Criar usuário
    user = User(login=login, role=role, is_active=is_active)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    flash(f'Usuário {login} criado com sucesso!', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:id>/edit', methods=['POST'])
@admin_required
def edit_user(id):
    """Edita um usuário existente"""
    user = User.query.get_or_404(id)
    
    # Não permitir que admin edite a si mesmo (prevenir lock-out)
    if user.id == current_user.id:
        flash('Você não pode editar sua própria conta por aqui.', 'warning')
        return redirect(url_for('admin.list_users'))
    
    user.login = request.form.get('login')
    user.role = request.form.get('role', 'user')
    user.is_active = request.form.get('enabled') == 'on'
    
    db.session.commit()
    
    flash(f'Usuário {user.login} atualizado com sucesso!', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:id>/reset-password', methods=['POST'])
@admin_required
def reset_password(id):
    """Reseta a senha de um usuário"""
    user = User.query.get_or_404(id)
    
    new_password = request.form.get('new_password')
    
    if not new_password or len(new_password) < 8:
        flash('A senha deve ter no mínimo 8 caracteres.', 'warning')
        return redirect(url_for('admin.list_users'))
    
    user.set_password(new_password)
    db.session.commit()
    
    flash(f'Senha do usuário {user.login} resetada com sucesso!', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:id>/toggle', methods=['POST'])
@admin_required
def toggle_user_status(id):
    """Ativa/Desativa um usuário"""
    user = User.query.get_or_404(id)
    
    if user.id == current_user.id:
        flash('Você não pode desativar sua própria conta.', 'warning')
        return redirect(url_for('admin.list_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'ativado' if user.is_active else 'desativado'
    flash(f'Usuário {user.login} {status} com sucesso!', 'success')
    return redirect(url_for('admin.list_users'))