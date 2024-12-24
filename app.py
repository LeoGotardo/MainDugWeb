from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, render_template, request, flash
from database import Database, Config
from cryptograph import Cryptograph

database = Database()
cryptograph = Cryptograph()
app = Config.app
login_manager = LoginManager(app)
login_manager.login_view = 'login'


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
            else:
                users = []
                flash(response[1])
            return render_template('gerent/index.html', user=users)
        else:
            return render_template('user/index.html', user=current_user)
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        
        response = database.validUser(login, password)
        if response[0] == True:
            login_user(response[1])
            flash(current_user.admin)
            if current_user.admin:
                response = database.getUsersByGerent(current_user.id)
                if response[0] == True:
                    users = response[1]
                else:
                    users = []
                    flash(response[1])
                return render_template('gerent/index.html', user=users)
            else:
                return render_template('user/index.html', user=current_user)
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
            return redirect(url_for('index'))
        else:
            flash(response[1])
            return render_template('register.html')
    return render_template('register.html')


@app.route('/account/<string:id>', defaults={'id': 'user'}, methods=['GET', 'POST'])
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


@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    return render_template('login.html')


@app.route('/passwords_status', methods=['GET'])
@login_required
def passwords_status():
    if not current_user.admin:
        return render_template('user/passwords_status.html', user=current_user)
    else:
        return render_template('404.html'), 404
    

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        login = request.form['login']
        password = Config.DEFAULT_PASSWORD

        response = database.createUser(login, password, False, current_user.id)
           
        if response[0] == True:
            flash(f'Usuário {login} criado com sucesso')
            return redirect(url_for('login'))
        else:
            flash(response[1])
            return render_template('gerent/add_user.html')
    return render_template('gerent/add_user.html')


@app.route('/delete_user/<string:id>', defaults={'id': 'user'}, methods=['POST'])
@login_required
def delete_user(id: str = 'user'):
    if not current_user.admin and id != 'user':
        return render_template('404.html'),404
    if request.method == 'POST':
        user = database.getUser(id)

        if user[0] == False:
            flash(user[1])
            return redirect(url_for('login'))
        else:
            user = user[1]
        
        if user.menegedBy != current_user.id:
            return render_template('404.html'), 404

        if database.deleteUser(user.id)[0] == True:
            flash(f'Usuário {user.login} deletado com sucesso')
            return redirect(url_for('login'))
        else:
            flash(f"Falha ao deletar usuário. {database.deleteUser(user.id)[1]}")
            return redirect(url_for('login'))


@app.route('/reset_password/<string:id>', methods=['GET', 'POST'])
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
        

if __name__ == '__main__':    
    app.run(debug=True)