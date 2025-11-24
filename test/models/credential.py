from app import db
from datetime import datetime
from utils.encryption import encrypt_password, decrypt_password
import re

class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    site = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255))
    password_encrypted = db.Column(db.Text, nullable=False)
    
    # Status de segurança
    is_weak = db.Column(db.Boolean, default=False)
    is_leaked = db.Column(db.Boolean, default=False)
    strength_score = db.Column(db.Integer, default=0)  # 0-100
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    last_accessed = db.Column(db.DateTime)
    
    # Relacionamentos
    flags = db.relationship('Flag', secondary='credential_flags', backref='credentials', lazy='dynamic')
    logs = db.relationship('AccessLog', backref='credential', lazy='dynamic', cascade='all, delete-orphan')
    
        
    def to_dict(self):
        return {
            'id': self.id,
            'site': self.site,
            'username': self.username,
            'is_weak': self.is_weak,
            'is_leaked': self.is_leaked,
            'strength_score': self.strength_score,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_accessed': self.last_accessed,
            'password': self.get_password(),
            'flags': [f.name for f in self.flags]
        }
    
    def set_password(self, plain_password):
        """Criptografa e salva a senha"""
        self.password_encrypted = encrypt_password(plain_password)
        self.analyze_strength(plain_password)
    
    def get_password(self):
        """Retorna a senha descriptografada"""
        return decrypt_password(self.password_encrypted)
    
    def analyze_strength(self, password):
        """Analisa a força da senha"""
        score = 0
        
        # Comprimento
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        
        # Complexidade
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 15
        if re.search(r'\d', password):
            score += 15
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        
        self.strength_score = min(score, 100)
        self.is_weak = score < 60
    
    def log_access(self, user_id, action, details=None):
        """Registra acesso à credencial"""
        from models.log import AccessLog
        log = AccessLog(
            credential_id=self.id,
            user_id=user_id,
            action=action,
            details=details
        )
        db.session.add(log)
        
        if action == 'view':
            self.last_accessed = datetime.utcnow()
    
    def __repr__(self):
        return f'<Credential {self.site}>'


# Tabela associativa para Credential <-> Flag (many-to-many)
credential_flags = db.Table('credential_flags',
    db.Column('credential_id', db.Integer, db.ForeignKey('credentials.id'), primary_key=True),
    db.Column('flag_id', db.Integer, db.ForeignKey('flags.id'), primary_key=True)
)