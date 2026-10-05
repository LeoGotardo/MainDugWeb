"""
API JSON usada pela extensão do navegador. Autenticação por JWT (Bearer), sem cookie,
por isso o blueprint fica fora da proteção CSRF (ver app.py).
"""
import secrets, string
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Blueprint, request, jsonify

import settings
from database import database, Filters, Config
from extensions import limiter

blueprint = Blueprint('blueprint', __name__)

JWT_ALGORITHM = 'HS256'
SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?'


# ==========================================
# DECORATORS
# ==========================================

def tokenRequired(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get('Authorization', '')
        scheme, _, token = header.partition(' ')
        if scheme.lower() != 'bearer' or not token:
            return jsonify({'error': 'Token não fornecido'}), 401

        try:
            data = jwt.decode(token, settings.JWT_SECRET, algorithms=[JWT_ALGORITHM], options={'require': ['exp', 'sub']})
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401

        # Relê a conta: uma conta desativada ou removida perde o acesso na hora.
        success, user = database.getUser(data['sub'])
        if success is not True or not user.enabled:
            return jsonify({'error': 'Token inválido'}), 401

        return f(user.id, user.login, *args, **kwargs)
    return decorated


def validateRequestData(requiredFields):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(silent=True)
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
    groups = []
    if use_upper:
        groups.append(string.ascii_uppercase.replace('I', '').replace('O', '') if exclude_similar else string.ascii_uppercase)
    if use_lower:
        groups.append(string.ascii_lowercase.replace('l', '').replace('o', '') if exclude_similar else string.ascii_lowercase)
    if use_digits:
        groups.append(string.digits.replace('0', '').replace('1', '') if exclude_similar else string.digits)
    if use_symbols:
        groups.append(SYMBOLS)
    if not groups:
        groups = [string.ascii_letters, string.digits]

    # Garante ao menos um caractere de cada grupo pedido, depois embaralha.
    charset = ''.join(groups)
    chars = [secrets.choice(g) for g in groups]
    chars += [secrets.choice(charset) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


def _calculatePasswordStrength(password: str) -> dict:
    score = sum((
        len(password) >= 8,
        len(password) >= 12,
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in SYMBOLS for c in password),
    ))
    labels = {0: 'Muito fraca', 1: 'Fraca', 2: 'Fraca', 3: 'Média',
              4: 'Boa', 5: 'Forte', 6: 'Muito forte'}
    return {'score': score, 'label': labels[score]}


# ==========================================
# AUTH ROUTES
# ==========================================

@blueprint.route('/auth/login', methods=['POST'])
@limiter.limit('5/minute;30/hour')
@validateRequestData(['login', 'password'])
def login():
    data = request.get_json()
    success, user = database.validUser(str(data.get('login')), str(data.get('password')))
    if success is not True:
        return jsonify({'error': 'Credenciais inválidas'}), 401

    token = jwt.encode({
        'sub': user.id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS),
    }, settings.JWT_SECRET, algorithm=JWT_ALGORITHM)

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
    # Sem lista de revogação: o token só deixa de valer quando expira. O cliente descarta.
    return jsonify({'message': 'Logout realizado com sucesso'}), 200


# ==========================================
# PASSWORD ROUTES
# ==========================================

@blueprint.route('/passwords', methods=['GET'])
@tokenRequired
def getPasswords(userId, userLogin):
    try:
        page = int(request.args.get('page', 1))
        perPage = int(request.args.get('perPage', 50))
    except ValueError:
        return jsonify({'error': 'Paginação inválida'}), 400

    success, result = database.getPasswords(
        userId=userId,
        query=request.args.get('search', ''),
        sort=request.args.get('sort', 'site'),
        sortOrder=request.args.get('sortOrder', 'asc'),
        page=page, perPage=perPage,
    )
    if success is not True:
        Config.app.logger.error(f'Erro ao listar senhas: {result}')
        return jsonify({'error': 'Erro ao listar senhas'}), 500
    return jsonify(result['items']), 200


@blueprint.route('/passwords/<int:passwordId>', methods=['GET'])
@tokenRequired
def getPassword(userId, userLogin, passwordId):
    success, password = database.getPassword(str(passwordId), userId)
    if success is not True:
        return jsonify({'error': 'Senha não encontrada'}), 404
    return jsonify(password.toDict()), 200


@blueprint.route('/passwords/<int:passwordId>/decrypt', methods=['GET'])
@tokenRequired
def decryptPassword(userId, userLogin, passwordId):
    success, password = database.getPassword(str(passwordId), userId)
    if success is not True:
        return jsonify({'error': 'Senha não encontrada'}), 404
    return jsonify({'password': password.password}), 200


# ==========================================
# PASSWORD GENERATION
# ==========================================

@blueprint.route('/generate-password', methods=['POST'])
@tokenRequired
def generatePassword(userId, userLogin):
    data = request.get_json(silent=True) or {}

    length = data.get('length', 16)
    if not isinstance(length, int) or isinstance(length, bool) or length < 8 or length > 128:
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
    flags = Config.session.query(Filters).filter_by(userId=userId).all()
    return jsonify([{'id': f.id, 'name': f.name} for f in flags]), 200


@blueprint.route('/flags/add', methods=['POST'])
@tokenRequired
def addFlag(userId, userLogin):
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip().lower()
    if not 2 <= len(name) <= 50:
        return jsonify({'error': 'Nome da flag deve ter entre 2 e 50 caracteres'}), 400
    success, msg = database.addFlag(id=userId, name=name)
    if success is True:
        return jsonify({'message': msg}), 201
    return jsonify({'error': msg if success is False else 'Erro ao adicionar flag'}), 400


@blueprint.route('/flags/delete', methods=['DELETE'])
@tokenRequired
def deleteFlag(userId, userLogin):
    data = request.get_json(silent=True) or {}
    flagId = str(data.get('flagId', ''))
    if not flagId:
        return jsonify({'error': 'ID da flag é obrigatório'}), 400
    success, msg = database.deleteFlag(id=userId, flagId=flagId)
    if success is True:
        return jsonify({'message': msg}), 200
    return jsonify({'error': msg if success is False else 'Erro ao remover flag'}), 400


# ==========================================
# REDIRECT
# ==========================================

@blueprint.route('/redirect/manage', methods=['GET'])
def redirectToManage():
    return jsonify({'url': settings.SITE_URL}), 200
