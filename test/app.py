from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from config import config
import os

# Inicialização de extensões
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_name=None):
    app = Flask(__name__)
    
    # Configuração
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config[config_name])
    
    # Inicializar extensões
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Configurar Flask-Login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor, faça login para acessar esta página.'
    login_manager.login_message_category = 'warning'
    
    # Registrar Blueprints
    from blueprints.auth import auth_bp
    from blueprints.credentials import credentials_bp
    from blueprints.account import account_bp
    from blueprints.stats import stats_bp
    from blueprints.admin import admin_bp
    from blueprints.api import api_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(credentials_bp, url_prefix='/credentials')
    app.register_blueprint(account_bp, url_prefix='/account')
    app.register_blueprint(stats_bp, url_prefix='/stats')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Rota principal
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('credentials.dashboard'))
        return redirect(url_for('auth.login'))
    
    # Criar tabelas
    with app.app_context():
        db.create_all()
        # Criar usuário admin padrão se não existir
        from models.user import User
        admin = User.query.filter_by(login='admin').first()
        if not admin:
            admin = User(login='admin', role='sysadmin')
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)