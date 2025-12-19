from flask import Blueprint, request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timedelta
import os

# Importar funções do database
from database.functions import (
    getUserByEmail,
    verifyPassword,
    updateLastLogin,
    getUserPasswords,
    getPasswordById,
    decryptPasswordData,
    updatePasswordUsage,
    generateSecurePassword,
    calculatePasswordStrength,
    logSecurityEvent
)

blueprint = Blueprint('blueprint', __name__)

# Chave secreta para JWT
JWT_SECRET = os.getenv('JWT_SECRET', 'sua-chave-secreta-aqui')

# ==========================================
# DECORADORES
# ==========================================

def tokenRequired(f):
    """Decorator para proteger rotas que precisam de autenticação"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Pegar token do header Authorization
        if 'Authorization' in request.headers:
            authHeader = request.headers['Authorization']
            try:
                token = authHeader.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Token malformado'}), 401
        
        if not token:
            return jsonify({'error': 'Token não fornecido'}), 401
        
        try:
            # Decodificar token
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            currentUserId = data['userId']
            currentUserEmail = data['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 403
        
        return f(currentUserId, currentUserEmail, *args, **kwargs)
    
    return decorated

def validateRequestData(requiredFields):
    """Decorator para validar dados da requisição"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'Dados não fornecidos'}), 400
            
            missingFields = [field for field in requiredFields if field not in data]
            
            if missingFields:
                return jsonify({
                    'error': f'Campos obrigatórios faltando: {", ".join(missingFields)}'
                }), 400
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator

# ==========================================
# ROTAS DE AUTENTICAÇÃO
# ==========================================

@blueprint.route('/auth/login', methods=['POST'])
@validateRequestData(['email', 'password'])
def login():
    """
    Login de usuário
    
    Body:
        email: Email do usuário
        password: Senha
        
    Returns:
        200: Login bem-sucedido (token JWT)
        401: Credenciais inválidas
    """
    data = request.get_json()
    
    email = data.get('email')
    password = data.get('password')
    
    try:
        # Buscar usuário
        user = getUserByEmail(email)
        
        if not user:
            logSecurityEvent(None, 'LOGIN_FAILED_USER_NOT_FOUND', False, request, {'email': email})
            return jsonify({'error': 'Credenciais inválidas'}), 401
        
        # Verificar senha
        if not verifyPassword(password, user['passwordHash']):
            logSecurityEvent(user['id'], 'LOGIN_FAILED_WRONG_PASSWORD', False, request)
            return jsonify({'error': 'Credenciais inválidas'}), 401
        
        # Atualizar último login
        updateLastLogin(user['id'])
        
        # Gerar token JWT (válido por 7 dias)
        token = jwt.encode({
            'userId': user['id'],
            'email': user['email'],
            'name': user['name'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, JWT_SECRET, algorithm='HS256')
        
        # Log de segurança
        logSecurityEvent(user['id'], 'LOGIN_SUCCESS', True, request)
        
        return jsonify({
            'message': 'Login realizado com sucesso',
            'token': token,
            'userId': user['id'],
            'user': {
                'email': user['email'],
                'name': user['name']
            }
        }), 200
        
    except Exception as e:
        print(f'Erro ao fazer login: {e}')
        return jsonify({'error': 'Erro ao fazer login'}), 500

@blueprint.route('/auth/verify', methods=['GET'])
@tokenRequired
def verifyToken(userId, userEmail):
    """
    Verificar se token é válido
    
    Headers:
        Authorization: Bearer <token>
        
    Returns:
        200: Token válido
        401/403: Token inválido ou expirado
    """
    return jsonify({
        'valid': True,
        'user': {
            'userId': userId,
            'email': userEmail
        }
    }), 200

@blueprint.route('/auth/logout', methods=['POST'])
@tokenRequired
def logout(userId, userEmail):
    """
    Logout de usuário (apenas registra o evento)
    
    Headers:
        Authorization: Bearer <token>
        
    Returns:
        200: Logout registrado
    """
    try:
        logSecurityEvent(userId, 'LOGOUT', True, request)
        return jsonify({'message': 'Logout realizado com sucesso'}), 200
    except Exception as e:
        print(f'Erro ao fazer logout: {e}')
        return jsonify({'error': 'Erro ao fazer logout'}), 500

# ==========================================
# ROTAS DE SENHAS (SOMENTE LEITURA)
# ==========================================

@blueprint.route('/passwords', methods=['GET'])
@tokenRequired
def getPasswords(userId, userEmail):
    """
    Listar senhas do usuário
    
    Headers:
        Authorization: Bearer <token>
        
    Query Params:
        category: Filtrar por categoria (opcional)
        favorite: Filtrar favoritos (opcional)
        search: Buscar por site/username (opcional)
        sort: Campo para ordenação (padrão: site)
        
    Returns:
        200: Lista de senhas (sem senha descriptografada)
        401: Não autorizado
    """
    try:
        # Parâmetros de busca
        category = request.args.get('category')
        favorite = request.args.get('favorite')
        search = request.args.get('search')
        sortBy = request.args.get('sort', 'site')
        
        # Buscar senhas (sem descriptografar)
        passwords = getUserPasswords(
            userId, 
            category=category,
            favorite=favorite,
            search=search,
            sortBy=sortBy
        )
        
        return jsonify(passwords), 200
        
    except Exception as e:
        print(f'Erro ao listar senhas: {e}')
        return jsonify({'error': 'Erro ao listar senhas'}), 500

@blueprint.route('/passwords/<int:passwordId>', methods=['GET'])
@tokenRequired
def getPassword(userId, userEmail, passwordId):
    """
    Buscar senha específica (sem descriptografar)
    
    Headers:
        Authorization: Bearer <token>
        
    Params:
        passwordId: ID da senha
        
    Returns:
        200: Dados da senha
        404: Senha não encontrada
    """
    try:
        password = getPasswordById(passwordId, userId)
        
        if not password:
            return jsonify({'error': 'Senha não encontrada'}), 404
        
        return jsonify(password), 200
        
    except Exception as e:
        print(f'Erro ao buscar senha: {e}')
        return jsonify({'error': 'Erro ao buscar senha'}), 500

@blueprint.route('/passwords/<int:passwordId>/decrypt', methods=['GET'])
@tokenRequired
def decryptPassword(userId, userEmail, passwordId):
    """
    Descriptografar e retornar senha
    
    Headers:
        Authorization: Bearer <token>
        
    Params:
        passwordId: ID da senha
        
    Returns:
        200: Senha descriptografada
        404: Senha não encontrada
    """
    try:
        password = getPasswordById(passwordId, userId)
        
        if not password:
            return jsonify({'error': 'Senha não encontrada'}), 404
        
        # Descriptografar senha
        decryptedPassword = decryptPasswordData(password['encryptedPassword'])
        
        # Atualizar estatísticas de uso
        updatePasswordUsage(passwordId)
        
        # Log de segurança
        logSecurityEvent(userId, 'PASSWORD_ACCESSED', True, request, {'passwordId': passwordId})
        
        return jsonify({'password': decryptedPassword}), 200
        
    except Exception as e:
        print(f'Erro ao descriptografar senha: {e}')
        return jsonify({'error': 'Erro ao descriptografar senha'}), 500

# ==========================================
# ROTAS DE GERAÇÃO DE SENHAS
# ==========================================

@blueprint.route('/generate-password', methods=['POST'])
@tokenRequired
def generatePassword(userId, userEmail):
    """
    Gerar senha segura
    
    Headers:
        Authorization: Bearer <token>
        
    Body (opcional):
        length: Comprimento (padrão: 16)
        includeUppercase: Incluir maiúsculas (padrão: true)
        includeLowercase: Incluir minúsculas (padrão: true)
        includeNumbers: Incluir números (padrão: true)
        includeSymbols: Incluir símbolos (padrão: true)
        excludeSimilar: Excluir caracteres similares (padrão: false)
        
    Returns:
        200: Senha gerada
        400: Parâmetros inválidos
    """
    data = request.get_json() or {}
    
    length = data.get('length', 16)
    includeUppercase = data.get('includeUppercase', True)
    includeLowercase = data.get('includeLowercase', True)
    includeNumbers = data.get('includeNumbers', True)
    includeSymbols = data.get('includeSymbols', True)
    excludeSimilar = data.get('excludeSimilar', False)
    
    # Validar comprimento
    if length < 8 or length > 128:
        return jsonify({'error': 'Comprimento deve estar entre 8 e 128'}), 400
    
    try:
        password = generateSecurePassword(
            length,
            includeUppercase,
            includeLowercase,
            includeNumbers,
            includeSymbols,
            excludeSimilar
        )
        
        strength = calculatePasswordStrength(password)
        
        return jsonify({
            'password': password,
            'strength': strength,
            'length': len(password)
        }), 200
        
    except Exception as e:
        print(f'Erro ao gerar senha: {e}')
        return jsonify({'error': 'Erro ao gerar senha'}), 500

# ==========================================
# ROTA DE REDIRECIONAMENTO PARA SITE
# ==========================================

@blueprint.route('/redirect/manage', methods=['GET'])
def redirectToManage():
    """
    Redireciona para o site principal para gerenciar conta/senhas
    
    Returns:
        200: URL do site
    """
    siteUrl = os.getenv('SITE_URL', 'https://maindug.com')
    
    return jsonify({
        'message': 'Use o site para gerenciar suas senhas e conta',
        'url': siteUrl,
        'actions': {
            'addPassword': f'{siteUrl}/passwords/new',
            'editPassword': f'{siteUrl}/passwords/edit',
            'deletePassword': f'{siteUrl}/passwords',
            'accountSettings': f'{siteUrl}/account/settings',
            'changePassword': f'{siteUrl}/account/security',
            'exportData': f'{siteUrl}/account/export'
        }
    }), 200

# ==========================================
# ROTAS DE FLAGS (MANTIDAS DO ORIGINAL)
# ==========================================

@blueprint.route('/flags/delete', methods=['DELETE'])
def deleteFlag():
    """Deletar flag"""
    return jsonify({'message': 'Flag deletada'}), 200

@blueprint.route('/flags/add', methods=['POST'])
def addFlag():
    """Adicionar flag"""
    return jsonify({'message': 'Flag adicionada'}), 201

@blueprint.route('/flags/get', methods=['GET'])
def getFlags():
    """Listar flags"""
    return jsonify({'flags': []}), 200