from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, render_template, request, flash
from database import Database, Config, User, Passwords
from cryptograph import Cryptograph
from notfy import notifications_bp
from dataclasses import dataclass
from functools import wraps

import requests, json, os

try:
    from werkzeug.urls import url_parse
except ImportError:
    from urllib.parse import urlparse as url_parse


database = Database()
cryptograph = Cryptograph()
app = Config.app
login_manager = LoginManager(app)
login_manager.login_view = 'login'
current_user : User | None
ITEM_CONFIGS = json.load(open('./src/config.json', 'r'))


app.register_blueprint(notifications_bp)


def onlySys(f) -> function:
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'sysadmin' in [current_user.gerentBy.role, current_user.role]:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
        
    return wrapper

def onlyAdmin(f) -> function:
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'sysadmin' in [current_user.menager.role, current_user.role] or current_user.role == 'admin':
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
        
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    success, user = database.getUserById(user_id)
    if success == False:
        return None
    return user


@app.errorhandler(404)
def pageNotFound(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internalServerError(error):
    return render_template('500.html', error=error), 500


@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.route('/404', methods=['GET'])
def notFound():
    return render_template('404.html'), 404

@app.route('/500', methods=['GET'])
def notFound():
    return render_template('500.html', error=request.args.get('error')), 500
    
@app.route('/403', methods=['GET'])
def notFound():
    return render_template('403.html'), 403


@app.route('/', methods=['GET', 'POST'])
def index():
    match request.method:
        case 'GET':
            if current_user.is_authenticated:
                return render_template('index.html')
            else:
                return redirect(url_for('login'))
        case 'POST':
            pass
        case _:
            return redirect(url_for('notFound'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    match request.method:
        case 'GET':
            return render_template('login.html')
        case 'POST':
            login_form = request.form
            
            if login_form.get('login') and login_form.get('password'):
                success, user = database.validUser(login_form.get('login'), login_form.get('password'))
                
                if success:
                    login_user(user)
                    flash('Login sucesso', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Login falhou', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Login falhou', 'danger')
                return redirect(url_for('login'))
        case _:
            return redirect(url_for('notFound'))