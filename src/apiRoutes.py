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
from database import database, Filters, Config, normalizeDomain, INVALID_DOMAIN_MESSAGE
from extensions import limiter

blueprint = Blueprint('blueprint', __name__)

JWT_ALGORITHM = 'HS256'
# Os campos são gravados cifrados em colunas de 500 caracteres; 200 de texto cabem com folga.
MAX_FIELD_LENGTH = 200
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


def _credentialFields(data: dict, required: tuple[str, ...]) -> tuple[dict | None, str | None]:
    """
    Extrai site/domain/login/password do JSON validando tipo e tamanho. Devolve (campos, erro).
    `domain` é opcional e pode vir vazio (= deduzir do site).
    """
    fields = {}
    for name in ('site', 'domain', 'login', 'password'):
        value = data.get(name)
        if value is None:
            if name in required:
                return None, f'Campo obrigatório: {name}'
            continue
        if not isinstance(value, str) or (name != 'domain' and not value.strip()):
            return None, f'Campo inválido: {name}'
        value = value if name == 'password' else value.strip()
        if len(value) > MAX_FIELD_LENGTH:
            return None, f'{name} excede {MAX_FIELD_LENGTH} caracteres'
        if name == 'domain' and value and normalizeDomain(value) is None:
            return None, INVALID_DOMAIN_MESSAGE
        fields[name] = value
    return fields, None


@blueprint.route('/passwords', methods=['POST'])
@limiter.limit('30/minute')
@tokenRequired
def createPassword(userId, userLogin):
    """Cria uma credencial (usado pela extensão ao salvar após um login). 409 se site+login já existem."""
    data = request.get_json(silent=True) or {}
    fields, error = _credentialFields(data, required=('site', 'login', 'password'))
    if error:
        return jsonify({'error': error}), 400

    existing = database.findCredential(userId, fields['site'], fields['login'], fields.get('domain'))
    if existing is not None:
        return jsonify({'error': 'Credencial já existe', 'id': existing.id}), 409

    flags = data.get('flags') or []
    if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
        return jsonify({'error': 'Campo inválido: flags'}), 400

    success, result = database.addPassword(userId=userId, flags=flags, **fields)
    if success is True:
        return jsonify({'id': result}), 201
    if success is False:
        return jsonify({'error': result}), 400
    Config.app.logger.error(f'Erro ao criar credencial via API: {result}')
    return jsonify({'error': 'Erro ao criar credencial'}), 500


@blueprint.route('/passwords/<int:passwordId>', methods=['PUT'])
@limiter.limit('30/minute')
@tokenRequired
def updatePassword(userId, userLogin, passwordId):
    """Atualiza senha (e opcionalmente site/domain/login). As flags e, sem `domain`, o domínio são mantidos."""
    data = request.get_json(silent=True) or {}
    fields, error = _credentialFields(data, required=('password',))
    if error:
        return jsonify({'error': error}), 400

    success, current = database.getPassword(str(passwordId), userId)
    if success is not True:
        return jsonify({'error': 'Senha não encontrada'}), 404

    success, result = database.updatePassword(
        passwordId=str(passwordId),
        userId=userId,
        site=fields.get('site', current.site),
        domain=fields.get('domain'),
        login=fields.get('login', current.login),
        password=fields['password'],
        flags=None,
    )
    if success is True:
        return jsonify({'id': passwordId}), 200
    if success is False:
        return jsonify({'error': result}), 404
    Config.app.logger.error(f'Erro ao atualizar credencial via API: {result}')
    return jsonify({'error': 'Erro ao atualizar credencial'}), 500


@blueprint.route('/passwords/<int:passwordId>/use', methods=['POST'])
@limiter.limit('60/minute')
@tokenRequired
def recordUsage(userId, userLogin, passwordId):
    """Registra que a extensão preencheu esta credencial (alimenta "Ver Logs" no site)."""
    success, result = database.recordUsage(str(passwordId), userId, request.remote_addr, request.headers.get('User-Agent'))
    if success is True:
        return jsonify({'logId': result}), 201
    if success is False:
        return jsonify({'error': 'Senha não encontrada'}), 404
    Config.app.logger.error(f'Erro ao registrar uso: {result}')
    return jsonify({'error': 'Erro ao registrar uso'}), 500


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
