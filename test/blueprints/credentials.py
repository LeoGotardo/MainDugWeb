from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from app import db
from models.credential import Credential
from models.flag import Flag
from utils.decorators import login_required, active_user_required
from datetime import datetime

credentials_bp = Blueprint('credentials', __name__)

@credentials_bp.route('/dashboard')
@login_required
@active_user_required
def dashboard():
    """Dashboard principal com listagem de credenciais"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Query base
    query = Credential.query.filter_by(user_id=current_user.id)
    
    # Filtro por flag
    flag_filter = request.args.get('flag')
    if flag_filter and flag_filter != 'all':
        flag = Flag.query.filter_by(user_id=current_user.id, name=flag_filter).first()
        if flag:
            query = query.filter(Credential.flags.contains(flag))
    
    # Busca
    search = request.args.get('search', '')
    if search:
        query = query.filter(
            db.or_(
                Credential.site.ilike(f'%{search}%'),
                Credential.username.ilike(f'%{search}%')
            )
        )
    
    # Ordenação
    sort_by = request.args.get('sort', 'site')
    sort_order = request.args.get('order', 'asc')
    
    if sort_by == 'site':
        query = query.order_by(Credential.site.asc() if sort_order == 'asc' else Credential.site.desc())
    elif sort_by == 'user':
        query = query.order_by(Credential.username.asc() if sort_order == 'asc' else Credential.username.desc())
    elif sort_by == 'accessed':
        query = query.order_by(Credential.last_accessed.desc() if sort_order == 'desc' else Credential.last_accessed.asc())
    
    # Paginação
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    credentials = pagination.items
    
    # Estatísticas
    total = Credential.query.filter_by(user_id=current_user.id).count()
    weak = Credential.query.filter_by(user_id=current_user.id, is_weak=True).count()
    leaked = Credential.query.filter_by(user_id=current_user.id, is_leaked=True).count()
    
    # Flags do usuário
    user_flags = Flag.query.filter_by(user_id=current_user.id).all()
    
    return render_template('credentials/dashboard.html',
                         credentials=credentials,
                         pagination=pagination,
                         stats={'total': total, 'weak': weak, 'leaked': leaked},
                         user_flags=user_flags,
                         current_flag=flag_filter)

@credentials_bp.route('/add', methods=['POST'])
@login_required
@active_user_required
def add():
    """Adiciona nova credencial"""
    site = request.form.get('site')
    username = request.form.get('username', '')
    password = request.form.get('password')
    flags_str = request.form.get('flags', '')
    
    if not site or not password:
        flash('Site e senha são obrigatórios.', 'danger')
        return redirect(url_for('credentials.dashboard'))
    
    # Criar credencial
    credential = Credential(
        user_id=current_user.id,
        site=site,
        username=username
    )
    credential.set_password(password)
    
    # Adicionar flags
    if flags_str:
        flag_names = [f.strip().lower() for f in flags_str.split(',') if f.strip()]
        for flag_name in flag_names:
            flag = Flag.query.filter_by(user_id=current_user.id, name=flag_name).first()
            if not flag:
                flag = Flag(user_id=current_user.id, name=flag_name)
                db.session.add(flag)
            credential.flags.append(flag)
    
    db.session.add(credential)
    db.session.commit()
    
    # Log
    credential.log_access(current_user.id, 'create', f'Credencial criada para {site}')
    db.session.commit()
    
    flash('Credencial adicionada com sucesso!', 'success')
    return redirect(url_for('credentials.dashboard'))

@credentials_bp.route('/<int:id>/edit', methods=['POST'])
@login_required
@active_user_required
def edit(id):
    """Edita uma credencial"""
    credential = Credential.query.get_or_404(id)
    
    # Verificar se pertence ao usuário
    if credential.user_id != current_user.id:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('credentials.dashboard'))
    
    credential.site = request.form.get('site')
    credential.username = request.form.get('username', '')
    
    new_password = request.form.get('password')
    if new_password:
        credential.set_password(new_password)
    
    # Atualizar flags
    flags_str = request.form.get('flags', '')
    credential.flags = []  # Limpar flags antigas
    
    if flags_str:
        flag_names = [f.strip().lower() for f in flags_str.split(',') if f.strip()]
        for flag_name in flag_names:
            flag = Flag.query.filter_by(user_id=current_user.id, name=flag_name).first()
            if not flag:
                flag = Flag(user_id=current_user.id, name=flag_name)
                db.session.add(flag)
            credential.flags.append(flag)
    
    credential.updated_at = datetime.utcnow()
    
    # Log
    credential.log_access(current_user.id, 'edit', 'Credencial atualizada')
    
    db.session.commit()
    
    flash('Credencial atualizada com sucesso!', 'success')
    return redirect(url_for('credentials.dashboard'))

@credentials_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
@active_user_required
def delete(id):
    """Deleta uma credencial"""
    credential = Credential.query.get_or_404(id)
    
    if credential.user_id != current_user.id:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('credentials.dashboard'))
    
    site_name = credential.site
    db.session.delete(credential)
    db.session.commit()
    
    flash(f'Credencial para {site_name} excluída com sucesso!', 'success')
    return redirect(url_for('credentials.dashboard'))

@credentials_bp.route('/<int:id>/view', methods=['GET'])
@login_required
@active_user_required
def view(id):
    """Retorna dados da credencial (para modal de visualização)"""
    credential = Credential.query.get_or_404(id)
    
    if credential.user_id != current_user.id:
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Log do acesso
    credential.log_access(current_user.id, 'view', 'Senha visualizada')
    db.session.commit()
    
    return jsonify({
        'site': credential.site,
        'username': credential.username,
        'password': credential.get_password()
    })

@credentials_bp.route('/<int:id>/logs')
@login_required
@active_user_required
def logs(id):
    """Exibe logs de uma credencial"""
    credential = Credential.query.get_or_404(id)
    
    if credential.user_id != current_user.id:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('credentials.dashboard'))
    
    logs = credential.logs.order_by(db.desc('timestamp')).all()
    
    return render_template('credentials/logs.html', credential=credential, logs=logs)