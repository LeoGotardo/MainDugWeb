import os, re, sys, traceback
from functools import wraps

_src_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _src_dir)

from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, render_template, request, flash, jsonify
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

import settings
from apiRoutes import blueprint as apiBlueprint
from database import database, Config, User
from extensions import csrf, limiter

app = Config.app
if settings.TRUSTED_PROXY_HOPS:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.TRUSTED_PROXY_HOPS, x_proto=settings.TRUSTED_PROXY_HOPS, x_host=settings.TRUSTED_PROXY_HOPS)

csrf.init_app(app)
limiter.init_app(app)
csrf.exempt(apiBlueprint)
app.register_blueprint(apiBlueprint, url_prefix='/api')

loginManager = LoginManager(app)
loginManager.login_view = 'login'
loginManager.login_message = 'Faça login para continuar'
loginManager.login_message_category = 'warning'
current_user: User | None

MIN_PASSWORD_LENGTH = 8
PROFILE_PIC_PATTERN = re.compile(r'^(https://\S+|data:image/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+/=]+)$')


def onlySys(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role == 'sysadmin':
            return f(*args, **kwargs)
        return redirect(url_for('index'))
    return wrapper


@loginManager.user_loader
def load_user(user_id):
    success, user = database.getUser(user_id)
    return user if success is True else None


@app.teardown_appcontext
def shutdownSession(exception=None):
    Config.session.remove()


@app.errorhandler(Exception)
def handleException(e):
    if isinstance(e, HTTPException):
        code, message = e.code, e.description
    else:
        code, message = 500, 'Ocorreu um erro inesperado.'
        app.logger.error(f'Exceção não tratada: {e}\n{traceback.format_exc()}')

    if request.path.startswith('/api/'):
        return jsonify({'error': message}), code

    # Detalhes técnicos só em desenvolvimento. Em produção ficam apenas no log.
    debugInfo = None
    if app.debug and not isinstance(e, HTTPException):
        lastFrame = traceback.extract_tb(e.__traceback__)[-1] if e.__traceback__ else None
        debugInfo = {
            'file': os.path.basename(lastFrame.filename) if lastFrame else 'N/A',
            'line': lastFrame.lineno if lastFrame else 'N/A',
            'function': lastFrame.name if lastFrame else 'N/A',
            'code': lastFrame.line if lastFrame else 'N/A',
            'fullPath': lastFrame.filename if lastFrame else 'N/A',
            'traceback': traceback.format_exc(),
        }

    return render_template('error/generic.html',
                           errorCode=code,
                           errorMessage=message,
                           errorDetails=str(e) if debugInfo else None,
                           debugInfo=debugInfo), code


@app.route('/', methods=['GET'])
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    try:
        page = int(request.args.get('page', 1))
        perPage = int(request.args.get('perPage', 10))
    except ValueError:
        page, perPage = 1, 10

    success, info = database.getDashboardInfo(
        userId=current_user.id,
        page=page,
        perPage=perPage,
        sort=request.args.get('sort', 'site'),
        sortOrder=request.args.get('sortOrder', 'asc'),
        query=request.args.get('query', ''),
    )
    if success is False:
        flash(info, 'danger')
        return render_template('index.html', deashboardInfo={})
    if success is not True:
        raise Exception(info)

    users = []
    if current_user.role == 'sysadmin':
        usersOk, users = database.getUsers()
        if usersOk is not True:
            app.logger.error(f'Erro ao carregar usuários: {users}')
            flash('Erro ao carregar usuários', 'danger')
            users = []

    return render_template('index.html',
                           deashboardInfo=info,
                           filters=info.get('filters'),
                           pagination=info.get('pagination'),
                           users=users)


@app.route('/dashboard/', methods=['GET'])
@login_required
def dashboard():
    return redirect(url_for('index'))


@app.route('/login/', methods=['GET', 'POST'])
@limiter.limit('5/minute;30/hour', methods=['POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        return render_template('login.html')

    loginValue = request.form.get('login', '').strip()
    password = request.form.get('password', '')
    if not loginValue or not password:
        flash('Preencha todos os campos', 'danger')
        return redirect(url_for('login'))

    success, user = database.validUser(loginValue, password)
    if success is not True:
        flash('Login ou senha incorretos', 'danger')
        return redirect(url_for('login'))

    login_user(user)
    flash('Login realizado com sucesso', 'success')
    return redirect(url_for('index'))


@app.route('/logout/', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/forgotPassword/', methods=['GET', 'POST'])
@limiter.limit('5/hour', methods=['POST'])
def forgotPassword():
    if request.method == 'GET':
        return render_template('forgotPassword.html')

    # Não há envio de e-mail implementado. A resposta é a mesma para qualquer login,
    # para não revelar quais contas existem.
    flash('A recuperação automática de senha ainda não está disponível. Fale com o administrador.', 'warning')
    return redirect(url_for('forgotPassword'))


@app.route('/signup/', methods=['GET', 'POST'])
@limiter.limit('5/hour', methods=['POST'])
def signup():
    if request.method == 'GET':
        return render_template('register.html')

    loginValue = request.form.get('login', '').strip()
    password = request.form.get('password', '')
    passwordConfirm = request.form.get('passwordConfirm', '')

    if not loginValue or not password or not passwordConfirm:
        flash('Preencha todos os campos', 'danger')
        return redirect(url_for('signup'))
    if not 3 <= len(loginValue) <= 100:
        flash('O login deve ter entre 3 e 100 caracteres', 'danger')
        return redirect(url_for('signup'))
    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f'A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres', 'danger')
        return redirect(url_for('signup'))
    if password != passwordConfirm:
        flash('As senhas não coincidem', 'danger')
        return redirect(url_for('signup'))

    success, result = database.createUser(login=loginValue, password=password)
    if success is False:
        flash(result, 'danger')
        return redirect(url_for('signup'))
    if success is not True:
        raise Exception(result)

    login_user(result, remember=True)
    flash('Conta criada com sucesso!', 'success')
    return redirect(url_for('index'))


@app.route('/account/', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'GET':
        return render_template('account.html', user=current_user)

    password = request.form.get('password', '')
    passwordConfirm = request.form.get('passwordConfirm', '')
    profilePic = request.form.get('profilePic', '').strip()

    if password:
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f'A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres', 'danger')
            return redirect(url_for('account'))
        if password != passwordConfirm:
            flash('As senhas não coincidem', 'danger')
            return redirect(url_for('account'))
    if profilePic and (len(profilePic) > 500 or not PROFILE_PIC_PATTERN.match(profilePic)):
        flash('Imagem de perfil inválida (use uma URL https ou uma imagem pequena)', 'danger')
        return redirect(url_for('account'))

    success, result = database.updateUser(current_user.id, password=password or None, profilePic=profilePic)
    if success is False:
        flash(result, 'danger')
        return redirect(url_for('account'))
    if success is not True:
        raise Exception(result)

    flash('Conta atualizada com sucesso!', 'success')
    return redirect(url_for('index'))


@app.route('/stats/', methods=['GET'])
@login_required
def stats():
    success, statsData = database.getStats(userId=current_user.id)
    if success is False:
        flash(statsData, 'danger')
        return render_template('stats.html')
    if success is not True:
        raise Exception(statsData)
    return render_template('stats.html', stats=statsData)


@app.route('/moreInfo', methods=['GET', 'DELETE'])
@login_required
def moreInfo():
    if request.method == 'GET':
        success, passwordInfo = database.getPasswordLogs(passwordId=request.args.get('passwordId', ''), userId=current_user.id)
        if success is not True:
            flash('Erro ao carregar informações', 'danger')
            return redirect(url_for('index'))
        return render_template('moreInfo.html', passwordInfo=passwordInfo)

    logs = [l.strip() for l in request.form.get('logs', '').split(',') if l.strip().isdigit()]
    success, msg = database.deletePasswordLogs(logs=logs, userId=current_user.id)
    if success is not True:
        return jsonify({'success': False, 'message': msg if success is False else 'Erro ao excluir logs'}), 400
    return jsonify({'success': True, 'message': msg})


@app.route('/flags/add', methods=['POST'])
@login_required
def addFlag():
    flagName = request.form.get('flagName', '').strip().lower()
    if not 2 <= len(flagName) <= 50:
        return jsonify({'success': False, 'error': 'Nome da flag deve ter entre 2 e 50 caracteres'}), 400

    success, msg = database.addFlag(id=current_user.id, name=flagName)
    if success is True:
        flash('Flag adicionada com sucesso!', 'success')
        return jsonify({'success': True, 'message': 'Flag adicionada com sucesso'}), 200
    if success is False:
        return jsonify({'success': False, 'error': msg}), 400
    app.logger.error(f'Erro ao adicionar flag: {msg}')
    return jsonify({'success': False, 'error': 'Erro interno ao adicionar flag'}), 500


@app.route('/flags/delete', methods=['POST'])
@login_required
def deleteFlag():
    flagId = request.form.get('flag_id', '').strip()
    if not flagId:
        return jsonify({'success': False, 'message': 'ID da flag é obrigatório'}), 400

    success, msg = database.deleteFlag(id=current_user.id, flagId=flagId)
    if success is True:
        return jsonify({'success': True, 'message': 'Flag removida com sucesso'}), 200
    if success is False:
        return jsonify({'success': False, 'message': msg}), 400
    app.logger.error(f'Erro ao remover flag: {msg}')
    return jsonify({'success': False, 'message': 'Erro interno ao remover flag'}), 500


@app.route('/addPassword', methods=['POST'])
@login_required
def addPassword():
    site = request.form.get('site', '').strip()
    loginValue = request.form.get('login', '').strip()
    password = request.form.get('password', '')

    if not site or not loginValue or not password:
        flash('Todos os campos são obrigatórios!', 'danger')
        return redirect(url_for('index'))

    success, msg = database.addPassword(
        userId=current_user.id,
        site=site,
        login=loginValue,
        password=password,
        flags=request.form.getlist('flags'),
    )
    if success is True:
        flash('Credencial adicionada com sucesso!', 'success')
    elif success is False:
        flash(msg, 'danger')
    else:
        raise Exception(msg)
    return redirect(url_for('index'))


@app.route('/editPassword', methods=['POST'])
@login_required
def editPassword():
    passwordId = request.form.get('password_id', '').strip()
    site = request.form.get('site', '').strip()
    loginValue = request.form.get('login', '').strip()
    password = request.form.get('password', '')

    if not passwordId or not site or not loginValue or not password:
        flash('Todos os campos são obrigatórios!', 'danger')
        return redirect(url_for('index'))

    success, msg = database.updatePassword(
        passwordId=passwordId,
        userId=current_user.id,
        site=site,
        login=loginValue,
        password=password,
        flags=request.form.getlist('flags'),
    )
    if success is True:
        flash('Credencial atualizada com sucesso!', 'success')
    elif success is False:
        flash(msg, 'danger')
    else:
        app.logger.error(f'Erro ao atualizar credencial: {msg}')
        flash('Erro interno ao atualizar credencial', 'danger')
    return redirect(url_for('index'))


@app.route('/deletePassword', methods=['POST'])
@login_required
def deletePassword():
    passwordId = request.form.get('password_id', '').strip()
    if not passwordId:
        flash('ID da credencial é obrigatório!', 'danger')
        return redirect(url_for('index'))

    success, msg = database.deletePassword(passwordId=passwordId, userId=current_user.id)
    if success is True:
        flash('Credencial excluída com sucesso!', 'success')
    elif success is False:
        flash(msg, 'danger')
    else:
        app.logger.error(f'Erro ao excluir credencial: {msg}')
        flash('Erro interno ao excluir credencial', 'danger')
    return redirect(url_for('index'))


@app.route('/password/view', methods=['POST'])
@login_required
@limiter.limit('60/minute')
def viewPassword():
    passwordId = request.form.get('password_id', '').strip()
    if not passwordId:
        return jsonify({'success': False, 'message': 'ID inválido'}), 400

    success, result = database.getPassword(credId=passwordId, userId=current_user.id)
    if success is True:
        return jsonify({'success': True, 'password': result.password})
    if success is False:
        return jsonify({'success': False, 'message': 'Credencial não encontrada'}), 404
    app.logger.error(f'Erro ao buscar credencial: {result}')
    return jsonify({'success': False, 'message': 'Erro interno'}), 500


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.getenv('PORT', '5000')), debug=settings.DEBUG)
