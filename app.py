from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, render_template, request, flash
from flask_admin import expose
from database import Database, Config
from cryptograph import Cryptograph

import json, datetime, threading

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


@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        if current_user.admin:
            return render_template('gerent/index.html', user=current_user)
        else:
            return render_template('user/index.html', user=current_user)
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        
        response = database.validUser(login, password)
        if response[0] == True:
            login_user(response[1])
            if current_user.admin:
                return render_template('gerent/index.html', user=current_user)
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


@app.route('/account', methods=['GET'])
@login_required
def account():
    if current_user.admin:
        return render_template('gerent/index.html', user=current_user)
    else:
        return render_template('user/index.html', user=current_user)


@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    return render_template('login.html')


if __name__ == '__main__':    
    app.run(debug=True)