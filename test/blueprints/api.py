from flask import Blueprint, request, jsonify, session
from utils.decorators import login_required
from datetime import datetime, timedelta
from models.credential import Credential
from flask_login import current_user
from urllib.parse import urlparse
from models.flag import Flag
from functools import wraps
from config import Config
from app import db

import secrets, time

health_check_cache = {}
api_bp = Blueprint('api', __name__)

@api_bp.route('/credentials/search')
@login_required
def search_credentials():
    """Busca credenciais em tempo real"""
    query = request.args.get('q', '')
    
    if not query or len(query) < 2:
        return jsonify({'results': []})
    
    credentials = Credential.query.filter_by(user_id=current_user.id).filter(
        db.or_(
            Credential.site.ilike(f'%{query}%'),
            Credential.username.ilike(f'%{query}%')
        )
    ).limit(10).all()
    
    results = [{
        'id': c.id,
        'site': c.site,
        'username': c.username,
        'last_accessed': c.last_accessed.strftime('%d/%m/%Y %H:%M') if c.last_accessed else 'Nunca',
        'is_weak': c.is_weak,
        'is_leaked': c.is_leaked
    } for c in credentials]
    
    return jsonify({'results': results})


def generate_csrf_token():
    """Gera um token CSRF único para a sessão"""
    if 'csrf_token' not in session or session.get('csrf_token_time', 0) + SecurityConfig.CSRF_TOKEN_EXPIRY < time.time():
        session['csrf_token'] = secrets.token_urlsafe(32)
        session['csrf_token_time'] = time.time()
    return session['csrf_token']


class SecurityConfig:
    """Configurações de segurança para o endpoint testRoute"""
    
    # Lista de origens permitidas
    ALLOWED_ORIGINS = [
        'localhost',
        '127.0.0.1',
        Config.IRIS_URL,
    ]
    
    # Tempo limite para tokens CSRF (5 minutos)
    CSRF_TOKEN_EXPIRY = 300


def generate_csrf_token():
    """Gera um token CSRF único para a sessão"""
    if 'csrf_token' not in session or session.get('csrf_token_time', 0) + SecurityConfig.CSRF_TOKEN_EXPIRY < time.time():
        session['csrf_token'] = secrets.token_urlsafe(32)
        session['csrf_token_time'] = time.time()
    return session['csrf_token']


#Wrappers
def verify_origin(f):
    """
    Decorator para verificar se a requisição veio do próprio site
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 1. Verificar Referer Header
        referer = request.headers.get('Referer', '')
        origin = request.headers.get('Origin', '')
        host = request.headers.get('Host', '')
        
        # Extrair domínio do referer
        referer_domain = ''
        if referer:
            parsed = urlparse(referer)
            referer_domain = parsed.netloc.lower()
        
        # Extrair domínio do origin
        origin_domain = ''
        if origin:
            parsed = urlparse(origin)
            origin_domain = parsed.netloc.lower()
        
        # Verifica se veio de uma origem permitida
        valid_origin = False
        current_host = host.lower()
        
        # Verifica host atual
        if any(allowed in current_host for allowed in SecurityConfig.ALLOWED_ORIGINS):
            valid_origin = True
        
        if referer_domain and any(allowed in referer_domain for allowed in SecurityConfig.ALLOWED_ORIGINS):
            valid_origin = True
            
        if origin_domain and any(allowed in origin_domain for allowed in SecurityConfig.ALLOWED_ORIGINS):
            valid_origin = True
        
        if not valid_origin:
            return jsonify({
                'error': 'Access denied',
                'message': 'Request must originate from the documentation interface',
                'code': 'INVALID_ORIGIN',
                'details': {
                    'referer': referer if referer else 'missing',
                    'origin': origin if origin else 'missing',
                    'host': host
                }
            }), 403
        
        # Bot blocker
        # user_agent = request.headers.get('User-Agent', '').lower()
        # suspicious_agents = ['curl', 'wget', 'python-requests', 'postman']
        
        # if any(agent in user_agent for agent in suspicious_agents):
        #     return jsonify({
        #         'error': 'Access denied',
        #         'message': 'Automated requests are not allowed',
        #         'code': 'INVALID_USER_AGENT'
        #     }), 403
        
        return f(*args, **kwargs)
    
    return wrapper


def rate_limit_health(f):
    """
    Rate limiting simples para endpoint /health
    Permite máximo 1 requisição por segundo por IP
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        global health_check_cache
        
        client_ip = request.remote_addr
        current_time = time.time()
        
        # Verifica a última requisição deste IP
        if client_ip in health_check_cache:
            last_request = health_check_cache[client_ip]
            
            if current_time - last_request < 1.0:
                return jsonify({
                    'message': 'Rate limit exceeded',
                    'error': 'Too many health check requests',
                    'retry_after': 1
                }), 429
        
        # Atualizar cache com timestamp atual
        health_check_cache[client_ip] = current_time
        
        # Remove IPs que não fazem requisição há mais de 1 hora
        cutoff_time = current_time - 3600
        health_check_cache = {ip: timestamp for ip, timestamp in health_check_cache.items() 
                            if timestamp > cutoff_time}
        
        return f(*args, **kwargs)
    
    return wrapper


def verify_csrf_token(f):
    """
    Decorator para verificar token CSRF
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        data = request.get_json() or {}
        provided_token = data.get('csrfToken', '')
        session_token = session.get('csrf_token', '')
        token_time = session.get('csrf_token_time', 0)
        
        # Verificar se o token existe e não expirou
        if not session_token or not provided_token:
            return jsonify({
                'error': 'CSRF token required',
                'message': 'CSRF token must be provided for security',
                'code': 'MISSING_CSRF_TOKEN'
            }), 403
        
        # Verificar se o token não expirou
        if time.time() - token_time > SecurityConfig.CSRF_TOKEN_EXPIRY:
            return jsonify({
                'error': 'CSRF token expired',
                'message': 'CSRF token has expired, please refresh the page',
                'code': 'EXPIRED_CSRF_TOKEN'
            }), 403
        
        # Verificar se os tokens coincidem
        if not secrets.compare_digest(session_token, provided_token):
            return jsonify({
                'error': 'Invalid CSRF token',
                'message': 'CSRF token validation failed',
                'code': 'INVALID_CSRF_TOKEN'
            }), 403
        
        return f(*args, **kwargs)
    
    return wrapper


@api_bp.route('/credentials/filter')
@login_required
def filter_credentials():
    """Filtra credenciais por flag"""
    flag_name = request.args.get('flag', 'all')
    
    query = Credential.query.filter_by(user_id=current_user.id)
    
    if flag_name != 'all':
        flag = Flag.query.filter_by(user_id=current_user.id, name=flag_name).first()
        if flag:
            query = query.filter(Credential.flags.contains(flag))
    
    credentials = query.all()
    
    results = [{
        'id': c.id,
        'site': c.site,
        'username': c.username,
        'flags': [f.name for f in c.flags],
        'last_accessed': c.last_accessed.strftime('%d/%m/%Y %H:%M') if c.last_accessed else 'Nunca',
        'is_weak': c.is_weak,
        'is_leaked': c.is_leaked
    } for c in credentials]
    
    return jsonify({'results': results})


@api_bp.route('/flags', methods=['GET'])
@login_required
def get_flags():
    """Lista todas as flags do usuário"""
    flags = Flag.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'flags': [{'id': f.id, 'name': f.name} for f in flags]
    })


@api_bp.route('/flags', methods=['POST'])
@login_required
def add_flag():
    """Adiciona uma nova flag"""
    data = request.get_json()
    flag_name = data.get('name', '').strip().lower()
    
    if not flag_name:
        return jsonify({'error': 'Nome da flag é obrigatório'}), 400
    
    # Verificar se já existe
    existing = Flag.query.filter_by(user_id=current_user.id, name=flag_name).first()
    if existing:
        return jsonify({'error': 'Flag já existe'}), 400
    
    flag = Flag(user_id=current_user.id, name=flag_name)
    db.session.add(flag)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'flag': {'id': flag.id, 'name': flag.name}
    })


@api_bp.route('/flags/<int:id>', methods=['DELETE'])
@login_required
def delete_flag(id):
    """Deleta uma flag"""
    flag = Flag.query.get_or_404(id)
    
    if flag.user_id != current_user.id:
        return jsonify({'error': 'Acesso negado'}), 403
    
    db.session.delete(flag)
    db.session.commit()
    
    return jsonify({'success': True})


@api_bp.route('/theme', methods=['POST'])
@login_required
def save_theme():
    """Salva preferências de tema do usuário"""
    data = request.get_json()
    
    theme = data.get('theme')
    color = data.get('color')
    
    if theme in ['light', 'dark']:
        current_user.theme_preference = theme
    
    if color and color.startswith('#') and len(color) == 7:
        current_user.accent_color = color
    
    db.session.commit()
    
    return jsonify({'success': True})


@api_bp.route('/credentials/<int:id>/password')
@login_required
def get_password(id):
    """Retorna a senha descriptografada"""
    credential = Credential.query.get_or_404(id)
    
    if credential.user_id != current_user.id:
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Log do acesso
    credential.log_access(current_user.id, 'view', 'Senha visualizada via API')
    db.session.commit()
    
    return jsonify({
        'password': credential.get_password()
    })