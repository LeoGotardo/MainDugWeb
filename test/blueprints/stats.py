from flask import Blueprint, render_template
from flask_login import current_user
from app import db
from models.credential import Credential
from utils.decorators import login_required, active_user_required

stats_bp = Blueprint('stats', __name__)

@stats_bp.route('/')
@login_required
@active_user_required
def security_stats():
    """Página de estatísticas de segurança"""
    
    # Senhas fracas
    weak_credentials = Credential.query.filter_by(
        user_id=current_user.id,
        is_weak=True
    ).all()
    
    # Senhas vazadas
    leaked_credentials = Credential.query.filter_by(
        user_id=current_user.id,
        is_leaked=True
    ).all()
    
    # Senhas reutilizadas (detectar duplicatas)
    all_credentials = Credential.query.filter_by(user_id=current_user.id).all()
    password_map = {}
    reused_passwords = []
    
    for cred in all_credentials:
        pwd = cred.get_password()
        if pwd in password_map:
            password_map[pwd].append(cred)
        else:
            password_map[pwd] = [cred]
    
    for pwd, creds in password_map.items():
        if len(creds) > 1:
            reused_passwords.append({
                'password_masked': pwd[:3] + '*' * (len(pwd) - 3),
                'sites': [c.site for c in creds],
                'count': len(creds)
            })
    
    stats = {
        'weak_count': len(weak_credentials),
        'leaked_count': len(leaked_credentials),
        'reused_count': len(reused_passwords)
    }
    
    return render_template('stats/security.html',
                         stats=stats,
                         weak_credentials=weak_credentials,
                         leaked_credentials=leaked_credentials,
                         reused_passwords=reused_passwords)