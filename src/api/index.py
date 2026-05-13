import os, sys, secrets, string
from flask import Blueprint, request, jsonify
from functools import wraps
from datetime import datetime, timedelta

import jwt

from database import Database, User, Passwords
from cryptograph import Cryptograph

blueprint = Blueprint('blueprint', __name__)

database = Database()
cryptograph = Cryptograph()

JWT_SECRET = os.getenv('JWT_SECRET')


# ==========================================
# DECORATORS
# ==========================================

def tokenRequired(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Token malformado'}), 401

        if not token:
            return jsonify({'error': 'Token não fornecido'}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            currentUserId = data['userId']
            currentUserLogin = data['login']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 403

        return f(currentUserId, currentUserLogin, *args, **kwargs)
    return decorated


def validateRequestData(requiredFields):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Dados não fornecidos'}), 400
            missing = [field for field in requiredFields if field not in data]
            if missing:
                return jsonify({'error': f'Campos obrigatórios faltando: {", ".join(missing)}'}), 400
            return f(*args, **kwargs)
        return decorated
    return decorator


# ==========================================
# HELPERS
# ==========================================

def _generateSecurePassword(length=16, use_upper=True, use_lower=True,
                             use_digits=True, use_symbols=True, exclude_similar=False):
    charset = ''
    if use_upper:
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        if exclude_similar:
            chars = chars.replace('I', '').replace('O', '')
        charset += chars
    if use_lower:
        chars = 'abcdefghijklmnopqrstuvwxyz'
        if exclude_similar:
            chars = chars.replace('l', '').replace('o', '')
        charset += chars
    if use_digits:
        chars = '0123456789'
        if exclude_similar:
            chars = chars.replace('0', '').replace('1', '')
        charset += chars
    if use_symbols:
        charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'

    if not charset:
        charset = string.ascii_letters + string.digits

    return ''.join(secrets.choice(charset) for _ in range(length))


def _calculatePasswordStrength(password: str) -> dict:
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        score += 1

    labels = {0: 'Muito fraca', 1: 'Fraca', 2: 'Fraca', 3: 'Média',
              4: 'Boa', 5: 'Forte', 6: 'Muito forte'}
    return {'score': score, 'label': labels.get(score, 'Desconhecida')}


# ==========================================
# AUTH ROUTES
# ==========================================

@blueprint.route('/auth/login', methods=['POST'])
@validateRequestData(['login', 'password'])
def login():
    data = request.get_json()
    login_val = data.get('login')
    password_val = data.get('password')

    success, user = database.validUser(login_val, password_val)
    if not success:
        return jsonify({'error': 'Credenciais inválidas'}), 401

    token = jwt.encode({
        'userId': user.id,
        'login': user.login,
        'exp': datetime.utcnow() + timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')

    return jsonify({
        'message': 'Login realizado com sucesso',
        'token': token,
        'userId': user.id,
        'user': {'login': user.login}
    }), 200


@blueprint.route('/auth/verify', methods=['GET'])
@tokenRequired
def verifyToken(userId, userLogin):
    return jsonify({'valid': True, 'user': {'userId': userId, 'login': userLogin}}), 200


@blueprint.route('/auth/logout', methods=['POST'])
@tokenRequired
def logout(userId, userLogin):
    return jsonify({'message': 'Logout realizado com sucesso'}), 200


# ==========================================
# PASSWORD ROUTES
# ==========================================

@blueprint.route('/passwords', methods=['GET'])
@tokenRequired
def getPasswords(userId, userLogin):
    try:
        sort = request.args.get('sort', 'site')
        sort_order = request.args.get('sortOrder', 'asc')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('perPage', 50))

        success, result = database.getPasswords(
            userId=userId, pagination=True,
            sort=sort, sortOrder=sort_order,
            page=page, perPage=per_page
        )

        if not success:
            return jsonify({'error': result}), 400

        items = result.get('items', result) if isinstance(result, dict) else [p.toDict() for p in result]
        return jsonify(items), 200
    except Exception as e:
        return jsonify({'error': 'Erro ao listar senhas'}), 500


@blueprint.route('/passwords/<int:passwordId>', methods=['GET'])
@tokenRequired
def getPassword(userId, userLogin, passwordId):
    try:
        success, password = database.getPassword(str(passwordId))
        if not success:
            return jsonify({'error': 'Senha não encontrada'}), 404
        if password.userId != userId:
            return jsonify({'error': 'Acesso negado'}), 403

        data = password.toDict()
        data.pop('password', None)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': 'Erro ao buscar senha'}), 500


@blueprint.route('/passwords/<int:passwordId>/decrypt', methods=['GET'])
@tokenRequired
def decryptPassword(userId, userLogin, passwordId):
    try:
        success, password = database.getPassword(str(passwordId))
        if not success:
            return jsonify({'error': 'Senha não encontrada'}), 404
        if password.userId != userId:
            return jsonify({'error': 'Acesso negado'}), 403

        return jsonify({'password': password.password}), 200
    except Exception as e:
        return jsonify({'error': 'Erro ao descriptografar senha'}), 500


# ==========================================
# PASSWORD GENERATION
# ==========================================

@blueprint.route('/generate-password', methods=['POST'])
@tokenRequired
def generatePassword(userId, userLogin):
    data = request.get_json() or {}

    length = data.get('length', 16)
    if not isinstance(length, int) or length < 8 or length > 128:
        return jsonify({'error': 'Comprimento deve estar entre 8 e 128'}), 400

    password = _generateSecurePassword(
        length=length,
        use_upper=data.get('includeUppercase', True),
        use_lower=data.get('includeLowercase', True),
        use_digits=data.get('includeNumbers', True),
        use_symbols=data.get('includeSymbols', True),
        exclude_similar=data.get('excludeSimilar', False),
    )

    return jsonify({
        'password': password,
        'strength': _calculatePasswordStrength(password),
        'length': len(password)
    }), 200


# ==========================================
# FLAGS
# ==========================================

@blueprint.route('/flags/get', methods=['GET'])
@tokenRequired
def getFlags(userId, userLogin):
    from database import Filters, Config
    flags = Config.session.query(Filters).filter_by(userId=userId).all()
    return jsonify([{'id': f.id, 'name': f.name} for f in flags]), 200


@blueprint.route('/flags/add', methods=['POST'])
@tokenRequired
def addFlag(userId, userLogin):
    data = request.get_json() or {}
    name = data.get('name', '').strip().lower()
    if not name:
        return jsonify({'error': 'Nome da flag é obrigatório'}), 400
    success, msg = database.addFlag(id=userId, name=name)
    if success:
        return jsonify({'message': msg}), 201
    return jsonify({'error': msg}), 400


@blueprint.route('/flags/delete', methods=['DELETE'])
@tokenRequired
def deleteFlag(userId, userLogin):
    data = request.get_json() or {}
    flag_id = data.get('flagId', '')
    if not flag_id:
        return jsonify({'error': 'ID da flag é obrigatório'}), 400
    success, msg = database.deleteFlag(id=userId, flagId=str(flag_id))
    if success:
        return jsonify({'message': msg}), 200
    return jsonify({'error': msg}), 400


# ==========================================
# REDIRECT
# ==========================================

@blueprint.route('/redirect/manage', methods=['GET'])
def redirectToManage():
    site_url = os.getenv('SITE_URL', 'https://maindug.com')
    return jsonify({'url': site_url}), 200
