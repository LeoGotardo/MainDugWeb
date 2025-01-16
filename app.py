from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, render_template, request, flash
from database import Database, Config
from cryptograph import Cryptograph
from functools import wraps

import requests

database = Database()
cryptograph = Cryptograph()
app = Config.app
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def onlyUser(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            # Verifica se o current_user está autenticado e se NÃO é admin
            if not current_user.is_authenticated:
                return render_template('404.html'), 404
            if not current_user.admin:  # Usuário não é admin
                return f(*args, **kwargs)
            else:
                return render_template('404.html'), 404
        except Exception as e:
            # Log do erro para depuração
            print(f"Erro no onlyUser: {e}")
            return render_template('404.html'), 404
    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.admin:
            return f(*args, **kwargs)
        else:
            return render_template('404.html'), 404
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    user = database.getUser(user_id)

    if user[0] != True:
        flash(user[1])
        return None
    else:
        return user[1]


@app.errorhandler(404)
def pageNotFound(error):
    return render_template('404.html'), 404


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.admin:
            response = database.getUsersByGerent(current_user.id)
            if response[0] == True:
                users = response[1]
                query = request.args.get('search')
                if query:
                    response = database.sortUsers(current_user, query)
                    if response[0] == True:
                        users = response[1]
                    else:
                        users = []
                        flash(response[1])
            else:
                users = []
                flash(response[1])
            users = [user.to_dict() for user in users]
            return render_template('gerent/index.html', users=users )
        else:
            response = database.updatePasswordStatus(current_user.id)
            if response[0] == False:
                flash(response[1])
            passwords = database.getPasswords(current_user.id)
            if passwords[0] == False:
                flash(passwords[1])
                return render_template('user/index.html', user=current_user, passwords=[])
            else:
                passwords = passwords[1]
                passwords = [password.to_dict() for password in passwords]
            return render_template('user/index.html', user=current_user, passwords=passwords)
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        
        response = database.validUser(login, password)
        if response[0] == True:
            login_user(response[1])
            if current_user.admin:
                response = database.getUsersByGerent(current_user.id)
                if response[0] == True:
                    users = response[1]
                else:
                    users = []
                    flash(response[1])
                users = [user.to_dict() for user in users]
                respose = database.checkPasswordPwned(password)
                if respose[0] == True:
                    if respose[1] != "0":
                        if current_user.passwordPwned == False:
                            rasponse = database.pwned(current_user.id)
                            if rasponse[0] != True:
                                flash(rasponse[1])
                else:
                    flash(respose[1])
                return render_template('gerent/index.html', users=users)
            else:
                respose = database.checkPasswordPwned(password)
                if respose[0] == True:
                    if respose[1] != "0":
                        if current_user.passwordPwned == False:
                            rasponse = database.pwned(current_user.id)
                            if rasponse[0] != True:
                                flash(rasponse[1])
                else:
                    flash(respose[1])
                response = database.updatePasswordStatus(current_user.id)
                if response[0] == False:
                    flash(response[1])
                passwords = database.getPasswords(current_user.id)
                if passwords[0] == False:
                    flash(f"teste {passwords[1]}")
                    return render_template('user/index.html', user=current_user, passwords=[])
                else:
                    passwords = passwords[1]
                    passwords = [password.to_dict() for password in passwords]
                return render_template('user/index.html', user=current_user, passwords=passwords)
        else:
            flash(response[1])
            return render_template('login.html')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        passwordConfirm = request.form['password-confirm']
        
        if password != passwordConfirm:
            flash('Passwords do not match')
            return render_template('register.html')

        response = database.createUser(login, password, True, None)
           
        if response[0] == True:
            flash(f'Usuario {login} criado com sucesso')
            return redirect(url_for('login'))
        else:
            flash(response[1])
            return render_template('register.html')
    return render_template('register.html')


@app.route('/account/<string:id>/', defaults={'id': 'user'}, methods=['GET', 'POST'])
@login_required
def account(id: str = 'user'):
    if not current_user.admin and id != 'user':
        return render_template('404.html'),404
    if request.method == 'POST':
        login = request.form['login']
        currentPassword = request.form['current-password']
        password = request.form['password']
        passwordConfirm = request.form['password-confirm']

        if password != passwordConfirm:
            flash('Passwords do not match')
            return redirect(url_for('account', id=id))

        response = database.findUserLogin(login)
        if response[0] == False:
            flash(response[1])
            return redirect(url_for('login'))
        if response[1] != None:
            flash(f'Usuário {login} já existe')
            return redirect(url_for('account', id=id))

        if id == 'user':
            user = current_user
        else:
            user = database.getUser(id)
            if user[0] == False:
                flash(user[1])
                return redirect(url_for('login'))
            else:
                user = user[1]

        response = cryptograph.isValidPass(currentPassword, user.password)
        if response[0] == False:
            flash(response[1])
            return redirect(url_for('account', id=id))
            
        if database.updateUser(id, login=login, password=password)[0] == True:
            flash('Usuário atualizado com sucesso')
            return redirect(url_for('login'))
        else:
            flash('Erro ao atualizar usuário, por favor, tente novamente')
            return redirect(url_for('account', id=id))

    if id == 'user':
        return render_template('account.html', user=current_user)
    else:
        user = database.getUser(id)
        if user[0] == False:
            flash(user[1])
            return redirect(url_for('login'))
        else:
            return render_template('account.html', user=user)


@app.route('/logout/', methods=['GET'])
def logout():
    logout_user()
    return render_template('login.html')
    

@app.route('/add_user/', methods=['GET', 'POST'])
@login_required
@require_admin
def add_user():
    if request.method == 'POST':
        login = request.form['login']
        password = Config.DEFAULT_PASSWORD

        response = database.createUser(login, password, False,current_user.id)
           
        if response[0] == True:
            flash(f'Usuário {login} criado com sucesso')
            return redirect(url_for('login'))
        else:
            flash(response[1])
            return render_template('gerent/add_user.html')
    return render_template('gerent/add_user.html')


@app.route('/delete_user/<string:id>/', methods=['POST'])
@login_required
@require_admin
def delete_user(id: str = 'user'):
    user = database.getUser(id)
    if user[0] == False:
        flash(user[1])
        return redirect(url_for('login'))
    else:
        user = user[1]
    
    response = database.deleteUser(user.id)
    if response[0] == True:
        flash(f'Usuário {user.login} deletado com sucesso')
        return redirect(url_for('login'))
    else:
        flash(f"Falha ao deletar usuário. {response[1]}")
        return redirect(url_for('login'))


@app.route('/reset_password/<string:id>/', methods=['GET', 'POST'])
def reset_password(id: str):
    if request.referrer != f"{url_for('account')}" or f"{url_for('account')}/{id}":
        return render_template('404.html'), 404
    if request.method == 'POST':
        user = database.getUser(id)
        if user[0] == False:
            flash(user[1])
            return redirect(url_for('login'))
        else:
            user = user[1]

        response = database.updateUser(user.id, password=Config.DEFAUT_PASSWORD)
        if response[0] == True:
            flash('Senha resetada com sucesso. Sua nova senha é a senha padrão.')
            return redirect(url_for('account', id=id))
        else:
            flash(f"Falha ao resetar senha. {response[1]}")
            return redirect(url_for('account', id=id))


@app.route('/user_info/<string:id>/', methods=['GET'])
@login_required
@require_admin
def user_info(id: str = 'user'):
    user = database.getUser(id)
    response = database.updatePasswordStatus(id)
    if response[0] == False:
        flash(response[1])
    if user[0] == False:
        flash(user[1])
        return redirect(url_for('login'))
    else:
        user = user[1]
        response = database.updatePasswordStatus(user.id)
        if response[0] == False:
            flash(response[1])
        passwords = database.getPasswords(user.id)
        if passwords[0] == False:
            flash(passwords[1])
            return redirect(url_for('login'))
        else:
            passwords = passwords[1]
            return render_template('gerent/user_info.html', user=user, passwords=passwords)


@app.route('/edit_user/<string:id>/', methods=['POST'])
@login_required
@require_admin    
def edit_user(id: str = 'user'):
    user = database.getUser(id)

    if user[0] == False:
        flash(user[1])
        return redirect(url_for('login'))
    else:
        user = user[1]

    enable = request.form['enable']

    response = database.updateUser(user.id, enabled=enable)
    if response[0] == True:
        flash(f'Usuário {user.login} atualizado com sucesso')
        return redirect(url_for('login'))
    else:
        flash(f"Falha ao atualizar usuário. {response[1]}")
        return redirect(url_for('login'))


@app.route('/add_credentials/<string:id>/', methods=['GET', 'POST'])
@login_required
@require_admin
def add_credentials(id: str):
    if request.method == 'POST':
        site = request.form['site']
        login = request.form['login']
        password = request.form['password']

        response = requests.get(f"{site}")
        if response.status_code == 200:
            print(id)
            response = database.addPassword(current_user.id, id, login, site, password)
            if response[0] == True:
                flash(f'Credencial adicionada com sucesso')
                response = database.getPasswords(id)
                if response[0] == False:
                    flash(response[1])
                passwords = response[1]
                return redirect(url_for('user_info', id=id, passwords=passwords))
            else:
                flash(response[1])
                return redirect(url_for('add_credentials', id=id))
        else:
            flash(f"Falha ao adicionar credencial. Site invalido ou fora do ar.")
            return redirect(url_for('user_info', id=id))
    return render_template('gerent/add_credentials.html', id=id)


@app.route('/statistic_painel/', methods=['GET'], endpoint='statisticPainel')
@login_required
@onlyUser
def statisticPainel():
    response = database.getLeakedPasswords(current_user.id)
    if response[0] == False:
        flash(response[1])
        leakedPasswords = []
    else:
        leakedPasswords = response[1]
    
    response = database.getMostUsedPasswords(current_user.id)
    if response[0] == False:
        flash(response[1])
        mostUsedPasswords= []
    else:
        mostUsedPasswords = response[1]
        
    response = database.getGoodPasswords(current_user.id)
    if response[0] == False:
        flash(response[1])
        goodPasswords = []
    else:
        goodPasswords = response[1]
        
    return render_template('user/statisticPainel.html', leakedPasswords=leakedPasswords, mostUsedPasswords=mostUsedPasswords, goodPasswords=goodPasswords)


@app.route('/pass_info/<string:credId>', methods=['GET', 'POST'], endpoint='pass_info')
@login_required
@onlyUser
def pass_info(credId: str):
    response = database.getPassword(credId)
    render_template('user/pass_info.html', password=response[1])


@app.route('/api/check-login', methods=['POST'])
def check_login():
    data = request.json
    response = database.validUser(data['login'], data['password'])
    if response[0]:
        return {"status": "success", "message": "Login válido!"}, 200
    else:
        return {"status": "error", "message": "Login inválido."}, 401

if __name__ == '__main__':    
    app.run(debug=True)
