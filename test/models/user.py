from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' ou 'sysadmin'
    enabled = db.Column(db.Boolean, default=True)
    passwordPwned = db.Column(db.Boolean, default=False)
    
    # Perfil
    email_recovery = db.Column(db.String(120))
    profile_photo = db.Column(db.String(255))
    theme_preference = db.Column(db.String(10), default='light')
    accent_color = db.Column(db.String(7), default='#0d6efd')
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)
    
    # Relacionamentos
    credentials = db.relationship('Credential', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    flags = db.relationship('Flag', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    logs = db.relationship('AccessLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash da senha com bcrypt"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verifica a senha"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Verifica se é admin"""
        return self.role == 'sysadmin'
    
    def get_id(self):
        """Necessário para Flask-Login"""
        return str(self.id)
    
    def to_dict(self):
        return {
            'id': self.id,
            'login': self.login,
            'role': self.role,
            'enabled': self.enabled,
            'passwordPwned': self.passwordPwned,
        }
        
    
    def __repr__(self):
        return f'<User {self.login}>'

@login_manager.user_loader
def load_user(user_id):
    """Callback necessário para Flask-Login"""
    return User.query.get(int(user_id))