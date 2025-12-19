from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, render_template, request, flash, jsonify
from api.index import blueprint as apiBlueprint
from database import Database, Config, User
from cryptograph import Cryptograph
from dataclasses import dataclass
from functools import wraps
from icecream import ic

import requests, json, os, traceback, sys


database = Database()
cryptograph = Cryptograph()
app = Config.app
loginManager = LoginManager(app)
loginManager.login_view = 'login'
current_user : User | None
ITEM_CONFIGS = json.load(open('./src/config.json', 'r'))
apiBlueprint = apiBlueprint
app.register_blueprint(apiBlueprint, url_prefix='/api')


def onlySys(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.role == 'sysadmin':
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
        
    return wrapper


@loginManager.user_loader
def load_user(user_id):
    db_manager = Database()
    success, user = db_manager.getUser(user_id)
    
    if success is True:
        return user
    return None

def setupErrorHandlers(app):
    """Configura todos os error handlers da aplicação"""
    
    @app.errorhandler(Exception)
    def handleException(e):
        """Handler para todas as exceções não tratadas"""
        
        # Obtém informações detalhadas do traceback
        excType, excValue, excTraceback = sys.exc_info()
        
        # Extrai informações do último frame (onde ocorreu o erro)
        if excTraceback:
            lastFrame = traceback.extract_tb(excTraceback)[-1]
            errorFile = lastFrame.filename
            errorLine = lastFrame.lineno
            errorFunction = lastFrame.name
            errorCode = lastFrame.line if lastFrame.line else "N/A"
        else:
            errorFile = "Desconhecido"
            errorLine = "N/A"
            errorFunction = "N/A"
            errorCode = "N/A"
        
        # Formata o traceback completo como string
        fullTraceback = ''.join(traceback.format_exception(excType, excValue, excTraceback))
        
        # Log completo do erro com informações extras
        app.logger.error(f'Exceção não tratada: {e}')
        app.logger.error(f'Arquivo: {errorFile}')
        app.logger.error(f'Linha: {errorLine}')
        app.logger.error(f'Função: {errorFunction}')
        app.logger.error(f'Código: {errorCode}')
        app.logger.error(f'Traceback completo:\n{fullTraceback}')
        
        # Em desenvolvimento, inclui detalhes do erro
        errorDetails = None
        debugInfo = None
        
        if app.config.get('DEBUG') or (current_user.is_authenticated and current_user.role in ['sysadmin', 'super']):
            errorDetails = str(e)
            debugInfo = {
                'file': errorFile.split('/')[-1] if errorFile else 'N/A',
                'line': errorLine,
                'function': errorFunction,
                'code': errorCode,
                'fullPath': errorFile,
                'traceback': fullTraceback
            }
        
        # Verifica se é uma exceção HTTP
        if hasattr(e, 'code'):
            return render_template('error/generic.html',
                                errorCode=e.code,
                                errorMessage=getattr(e, 'description', 'Erro desconhecido'),
                                errorDetails=errorDetails,
                                debugInfo=debugInfo), e.code
        
        # Para exceções não-HTTP, retorna erro 500
        return render_template('error/generic.html',
                            errorCode=500,
                            errorMessage="Ocorreu um erro inesperado. Nossa equipe foi notificada.",
                            errorDetails=errorDetails,
                            debugInfo=debugInfo), 500


@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        match request.method:
            case 'GET':      
                success, statistcs = database.getDashboardInfo(userId=current_user.id)
                match success:
                    case False:
                        flash(statistcs, 'danger')
                        return render_template('index.html', deashboardInfo={})
                    case -1:
                        raise Exception(statistcs)
                    case True:
                        if current_user.role == 'sysadmin':
                            users = database.getUsers(userId=current_user.id, method='get', itemType='user')
                            if users == False:
                                flash(users, 'danger')
                                return render_template('index.html', deashboardInfo=statistcs, users={})
                            elif users == True:
                                return render_template('index.html', deashboardInfo=statistcs, users=users)
                            else:
                                raise Exception(users)
                        else:
                            return render_template('index.html', deashboardInfo=statistcs)
                    case _:
                        return redirect(url_for('notFound'))
            case 'POST':
                action = request.form.get('action')
                
                if action == 'search':
                    query = request.form.get('query', '')
                    sort = request.form.get('sort', 'site')
                    sortOrder = request.form.get('sortOrder', 'asc')
                    page = int(request.form.get('page', 1))
                    perPage = int(request.form.get('perPage', 10))
                    
                    success, statistcs = database.getDashboardInfo(
                        userId=current_user.id,
                        page=page,
                        perPage=perPage,
                        sort=sort,
                        sortOrder=sortOrder,
                        query=query
                    )
                    
                    if success:
                        return render_template('index.html', deashboardInfo=statistcs)
                    else:
                        flash(statistcs, 'danger')
                        return redirect(url_for('index'))
                
                elif action == 'add':
                    # Adicionar nova credencial
                    site = request.form.get('site')
                    login = request.form.get('login')
                    password = request.form.get('password')
                    flags = request.form.getlist('flags')
                    
                    # Aqui você implementaria a lógica de adicionar
                    flash('Credencial adicionada com sucesso!', 'success')
                    return redirect(url_for('index'))
                
                elif action == 'edit':
                    # Editar credencial
                    passwordId = request.form.get('password_id')
                    # Implementar lógica de edição
                    flash('Credencial atualizada com sucesso!', 'success')
                    return redirect(url_for('index'))
                
                elif action == 'delete':
                    # Deletar credencial
                    passwordId = request.form.get('password_id')
                    # Implementar lógica de deleção
                    flash('Credencial excluída com sucesso!', 'success')
                    return redirect(url_for('index'))
                
                return redirect(url_for('index'))
            case _:
                return redirect(url_for('notFound'))
    else:
        return redirect(url_for('login'))
    
    
@app.route('/dashboard/', methods=['GET', 'POST'])
@login_required
def dashboard():
    return redirect(url_for('index'))


@app.route('/login/', methods=['GET', 'POST'])
def login():
    match request.method:
        case 'GET':
            return render_template('login.html')
        case 'POST':
            loginForm = request.form
            
            if loginForm.get('login') and loginForm.get('password'):
                success, user = database.validUser(loginForm.get('login'), loginForm.get('password'))
                
                if success:
                    login_user(user)
                    flash('Login realizado com sucesso', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Login ou senha incorretos', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Preencha todos os campos', 'danger')
                return redirect(url_for('login'))
        case _:
            return redirect(url_for('notFound'))
        

@app.route('/logout/', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/forgotPassword/', methods=['GET', 'POST'])
def forgotPassword():
    match request.method:
        case 'GET':
            return render_template('forgotPassword.html')
        case 'POST':
            login = request.form.get('login')
            
            if login:
                success, user = database.findUserLogin(login)
                
                if success == False:
                    flash(user, 'danger')
                    return redirect(url_for('forgotPassword'))
                elif success == -1:
                    raise Exception(user)
                else:
                    flash('Instruções enviadas para o email cadastrado', 'success')
                    return redirect(url_for('forgotPassword'))
            else:
                flash('Digite seu login ou email', 'danger')
                return redirect(url_for('forgotPassword'))


@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    match request.method:
        case 'GET':
            return render_template('register.html')
        case 'POST':
            login = request.form.get('login')
            password = request.form.get('password')
            passwordConfirm = request.form.get('passwordConfirm')
            
            if None not in [login, password, passwordConfirm]:
                if password == passwordConfirm:
                    success, result = database.createUser(login=login, password=password)
                    
                    if success == False:
                        flash(result, 'danger')
                        return redirect(url_for('signup'))
                    elif success == -1:
                        raise Exception(result)
                    else:
                        login_user(result, remember=True)
                        flash('Conta criada com sucesso!', 'success')
                        return redirect(url_for('index'))
                else:
                    flash('As senhas não coincidem', 'danger')
                    return redirect(url_for('signup'))
            else:
                flash('Preencha todos os campos', 'danger')
                return redirect(url_for('signup'))
                

@app.route('/account/', methods=['GET', 'POST'])
@login_required
def account():
    match request.method:
        case 'GET':
            success, user = database.getUser(current_user.id)
            if not success:
                flash('Erro ao carregar dados da conta', 'danger')
                return redirect(url_for('index'))
            
            return render_template('account.html', user=user)
        case 'POST':
            login = request.form.get('login')
            password = request.form.get('password')
            passwordConfirm = request.form.get('passwordConfirm')
            profilePic = request.form.get('profilePic')
            
            if password and password != passwordConfirm:
                flash('As senhas não coincidem', 'danger')
                return redirect(url_for('account'))
            
            success, result = database.updateUser(
                current_user.id, 
                login=login, 
                password=password if password else None, 
                profilePic=profilePic
            )
            
            if success == False:
                flash(result, 'danger')
                return redirect(url_for('account'))
            else:
                flash('Conta atualizada com sucesso!', 'success')
                return redirect(url_for('index'))


@app.route('/stats/', methods=['GET', 'POST'])
@login_required
def stats():
    match request.method:
        case 'GET':
            success, stats = database.getStats(userId=current_user.id)
            if success == False:
                flash(stats, 'danger')
                return render_template('stats.html')
            elif success == -1:
                raise Exception(stats)
            return render_template('stats.html', stats=stats)
        case 'POST':
            return render_template('stats.html')


@app.route('/moreInfo', methods=['GET', 'DELETE'])
@login_required
def moreInfo():
    match request.method:
        case 'GET':
            passwordId = request.args.get('passwordId')
            success, passwordInfo = database.getPasswordLogs(passwordId=passwordId, userId=current_user.id, itemType='password')
            if not success:
                flash('Erro ao carregar informações', 'danger')
                return redirect(url_for('index'))
            
            return render_template('moreInfo.html', passwordInfo=passwordInfo)
        case 'DELETE':
            logs = list(request.form.getlist('logs'))
            
            success, msg = database.deletePasswordLogs(logs=logs, userId=current_user.id, itemType='password')
            if not success:
                return jsonify({'success': False, 'message': msg}), 400
            
            return jsonify({'success': True, 'message': msg})
        case _:
            return redirect(url_for('notFound'))


@app.route('/flags/add', methods=['POST'])
@login_required
def addFlag():
    """Adiciona uma nova flag para o usuário"""
    try:
        flagName = request.form.get('flagName', '').strip().lower()
        
        if not flagName:
            return jsonify({'success': False, 'error': 'Nome da flag é obrigatório'}), 400
        
        if len(flagName) < 2:
            return jsonify({'success': False, 'error': 'Nome da flag deve ter pelo menos 2 caracteres'}), 400
        
        # Adiciona a flag no banco
        success, msg = database.addFlag(id=current_user.id, name=flagName)
        
        if success:
            flash('Flag adicionada com sucesso!', 'success')
            return jsonify({'success': True, 'message': 'Flag adicionada com sucesso'}), 200
        else:
            return jsonify({'success': False, 'error': msg}), 400
            
    except Exception as e:
        app.logger.error(f'Erro ao adicionar flag: {e}')
        return jsonify({'success': False, 'error': 'Erro interno ao adicionar flag'}), 500


@app.route('/flags/delete', methods=['POST'])
@login_required
def deleteFlag():
    """Remove uma flag do usuário"""
    try:
        flagId = request.form.get('flag_id', '').strip()
        
        if not flagId:
            return jsonify({'success': False, 'message': 'ID da flag é obrigatório'}), 400
        
        # Remove a flag do banco
        success, msg = database.deleteFlag(id=current_user.id, name=flagId)
        
        if success:
            return jsonify({'success': True, 'message': 'Flag removida com sucesso'}), 200
        else:
            return jsonify({'success': False, 'message': msg}), 400
            
    except Exception as e:
        app.logger.error(f'Erro ao remover flag: {e}')
        return jsonify({'success': False, 'message': 'Erro interno ao remover flag'}), 500
    
    
@app.route('/addPassword', methods=['POST'])
@login_required
def addPassword():
    site = request.form.get('site', '').strip()
    login = request.form.get('login', '').strip()
    password = request.form.get('password', '').strip()
    flags = list(request.form.getlist('flags'))

    if not site or not login or not password:
        flash('Todos os campos são obrigatórios!', 'danger')
        return redirect(url_for('index'))

    success, msg = database.addPassword(
        userId=current_user.id,
        site=site,
        login=login,
        password=password,
        flags=flags
    )

    if success == True:
        flash('Credencial adicionada com sucesso!', 'success')
    elif success == False:
        flash(msg, 'danger')
    else:
        raise Exception(msg)

    return redirect(url_for('index'))


@app.route('/editPassword', methods=['POST'])
@login_required
def editPassword():
    try:
        passwordId = request.form.get('password_id', '').strip()
        site = request.form.get('site', '').strip()
        login = request.form.get('login', '').strip()
        password = request.form.get('password', '').strip()
        flags = list(request.form.getlist('flags'))

        if not passwordId or not site or not login or not password:
            flash('Todos os campos são obrigatórios!', 'danger')
            return redirect(url_for('index'))

        success, msg = database.updatePassword(
            passwordId=passwordId,
            site=site,
            login=login,
            password=password,
            flags=flags
        )

        if success:
            flash('Credencial atualizada com sucesso!', 'success')
        else:
            flash(msg, 'danger')

    except Exception as e:
        app.logger.error(f'Erro ao atualizar credencial: {e}')
        flash('Erro interno ao atualizar credencial', 'danger')

    return redirect(url_for('index'))


@app.route('/deletePassword', methods=['POST'])
@login_required
def deletePassword():
    try:
        passwordId = request.form.get('password_id', '').strip()

        if not passwordId:
            flash('ID da credencial é obrigatório!', 'danger')
            return redirect(url_for('index'))

        success, msg = database.deletePassword(passwordId=passwordId, userId=current_user.id)

        if success:
            flash('Credencial excluída com sucesso!', 'success')
        else:
            flash(msg, 'danger')

    except Exception as e:
        app.logger.error(f'Erro ao excluir credencial: {e}')
        flash('Erro interno ao excluir credencial', 'danger')

    return redirect(url_for('index'))

# Configura os error handlers
setupErrorHandlers(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)