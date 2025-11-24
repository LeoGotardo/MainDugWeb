from app import db
from datetime import datetime

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.Integer, db.ForeignKey('credentials.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    action = db.Column(db.String(20), nullable=False)  # 'view', 'create', 'edit', 'delete'
    ip = db.Column(db.String(15), nullable=False)
    cidade = db.Column(db.String(50))
    estado = db.Column(db.String(2))
    pais = db.Column(db.String(2))
    ASN = db.Column(db.String(10))
    os = db.Column(db.String(10))
    browser = db.Column(db.String(10))
    version = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    
    
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'ip': self.ip,
            'cidade': self.cidade,
            'estado': self.estado,
            'pais': self.pais,
            'ASN': self.ASN,
            'os': self.os,
            'browser': self.browser,
            'version': self.version,
            'timestamp': self.timestamp.isoformat()
        }
    
    def __repr__(self):
        return f'<Log {self.action} at {self.timestamp}>'