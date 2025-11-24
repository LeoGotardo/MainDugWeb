from app import db
from datetime import datetime

class Flag(db.Model):
    __tablename__ = 'flags'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Constraint para não ter flags duplicadas por usuário
    __table_args__ = (
        db.UniqueConstraint('user_id', 'name', name='unique_user_flag'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Flag {self.name}>'