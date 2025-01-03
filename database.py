import locale, sys, os, uuid, hashlib, requests, datetime

from flask_sqlalchemy import SQLAlchemy
from cryptograph import Cryptograph
from flask_login import UserMixin
from dotenv import load_dotenv
from flask import Flask

class Config:
    locale.setlocale(locale.LC_TIME, 'pt_BR.UTF-8')
    load_dotenv()
    SECRET_KEY = os.getenv('SecretKey') 
    DEFAULT_PASSWORD = os.getenv('DefaultPassword')
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SECRET_KEY'] = SECRET_KEY
    db = SQLAlchemy(app)
    session = db.session

class User(UserMixin, Config.db.Model):
    __tablename__ = 'Users'
    id = Config.db.Column(Config.db.String(36), default=lambda: str(uuid.uuid4()), primary_key=True, nullable=False)
    login = Config.db.Column(Config.db.String(80), unique=True, nullable=False)
    password = Config.db.Column(Config.db.String(80), nullable=False)
    admin = Config.db.Column(Config.db.Boolean, default=False, nullable=False)
    enabled = Config.db.Column(Config.db.Boolean, default=True, nullable=False)
    gerentBy = Config.db.Column(Config.db.String(36), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'login': self.login,
            'admin': self.admin,
            'enabled': self.enabled,
        }

class Passwords(UserMixin, Config.db.Model):
    __tablename__ = 'Passwords'
    id = Config.db.Column(Config.db.Integer, primary_key=True, nullable=False, autoincrement=True)  
    user_id = Config.db.Column(Config.db.String(36), Config.db.ForeignKey('Users.id'), nullable=False)
    login = Config.db.Column(Config.db.String(80), nullable=False)
    password = Config.db.Column(Config.db.String(80), nullable=False)
    site = Config.db.Column(Config.db.String(80), nullable=False)
    status = Config.db.Column(Config.db.Boolean, nullable=False, default=False)
    lastUse = Config.db.Column(Config.db.DateTime, nullable=True)
    
    def to_dict(self):
        key = Cryptograph.keyGenerator(self.user_id)
        if key[0] == False:
            return False, key[1]
        key = key[1]
        password =Cryptograph.decryptSentence(self.password, key)
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site': self.site,
            'login': self.login,
            'password': password,
            'status': self.status,
            'lastUse': self.lastUse,
        }

class Database:
    def __init__(self) -> None:
        self.db = Config.db
        self.session = Config.session
        self.cryptograph = Cryptograph
        self.iscryptograph = Cryptograph()
        
        self.createTables()
        
        
    def createTables(self) -> None:
        with Config.app.app_context():
            self.db.create_all()

    
    def getUser(self, id: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            
            if user is not None:
                return True, user
            else:
                return False, 'Invalid user'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


    def validUser(self, login: str, password: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(login=login).first()
            
            if user is not None:
                if self.iscryptograph.isValidPass(user.password, password):
                    return True, user
                else:
                    return False, 'Invalid credentials'
            else:
                return False, 'Invalid credentials'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


    def createUser(self, login: str, password: str, admin: bool = False, menagedBy: str = None) -> tuple[bool, User | str]:
        try:
            if User.query.filter_by(login=login).first() is None:
                user = User(login=login, password=self.iscryptograph.encryptPass(password), admin=admin, gerentBy=menagedBy)
                self.session.add(user)
                self.session.commit()
                
                return True, user
            else:
                return False, 'User already exists'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def deleteUser(self, id: str) -> tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            
            if user is not None:
                self.session.delete(user)
                self.session.commit()
                
                return True, 'User deleted'
            else:
                return False, 'User not found'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
    def updateUser(self, id: str, login: str = None, password: str = None, admin: bool = None, menagedBy: str = None) -> tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()

            if login is None:
                login = user.login
            if password is None:
                password = user.password
            else:
                password = self.iscryptograph.encryptPass(password)
            if admin is None:
                admin = user.admin
            if menagedBy is None:
                menagedBy = user.gerentBy
            
            if user is not None:
                user.login = login
                user.password = password
                user.admin = admin
                user.gerentBy = menagedBy
                    
                self.session.commit()
                    
                return True, 'User updated'
            else:
                return False, 'Invalid id'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def deleteUserByGerent(self, gerentID: str, userID: str) -> tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=userID).first()
            
            if user is not None:
                if user.gerentBy == gerentID:
                    self.session.delete(user)
                    self.session.commit()
                    
                    return True, 'User deleted'
                else:
                    return False, 'User not found'
            else:
                return False, 'User not found'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def createUserByGerent(self, gerentID: str, login: str, password: str) -> tuple[bool, User | str]:
        try:
            if User.query.filter_by(login=login).first() is None:
                user = User(login=login, password=self.iscryptograph.encryptPass(password), gerentBy=gerentID)
                self.session.add(user)
                self.session.commit()
                
                return True, user
            else:
                return False, 'This login already exists'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def getUsersByGerent(self, gerentID: str) -> tuple[bool, list[User]] | tuple[bool, str]:
        try:
            users = self.session.query(User).filter_by(gerentBy=gerentID).all()
            
            if users is not None:
                return True, users
            else:
                return False, 'Dident find any user'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def addPassword(self, id: str, site: str, login: str,password: str ) -> tuple[bool, str]:
        try:
            response = self.cryptograph.keyGenerator(id)
            if response[0] == False:
                return False, response[1]
            key = response[1]
            response = self.cryptograph.encryptSentence(password, key)
            if response[0] == False:
                return False, response[1]  
            password = response[1]
            password = Passwords(user_id=id, password=password, site=site, login=login, lastUse=datetime.datetime.now())
            self.session.add(password)
            self.session.commit()
            
            return True, 'Password added'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


    def getPasswords(self, id: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).all()
            
            if passwords is not None:
                for password in passwords:
                    response = self.cryptograph.keyGenerator(id)
                    if response[0] == False:
                        return False, response[1]
                    key = response[1]
                    response = self.cryptograph.decryptSentence(password.password, key)
                    if response[0] == False:
                        return False, response[1]
                    password.password = response[1]
                return True, passwords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def deletePassword(self, passwordID: str, userID: str) -> tuple[bool, str]:
        try:
            password = self.session.query(Passwords).filter_by(id=passwordID).first()
            
            if password is not None:
                if password.user_id == userID:
                    self.session.delete(password)
                    self.session.commit()
                    
                    return True, 'Password deleted'
                else:
                    return False, 'Password not found'
            else:
                return False, 'Password not found'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def getPasswordsStatus(self, id: str, status: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).filter_by(status=status).all()
            
            if passwords is not None:
                for password in passwords:
                    response = self.cryptograph.keyGenerator(id)
                    if response[0] == False:
                        return False, response[1]
                    key = response[1]
                    response = self.cryptograph.decryptSentence(password.password, key)
                    if response[0] == False:
                        return False, response[1]
                    password.password = response[1]
                return True, passwords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def updatePasswordStatus(self, passwordID: str, userID: str, status: str) -> tuple[bool, str]:
        try:
            passwordRec = self.session.query(Passwords).filter_by(id=passwordID).first()

            if passwordRec is not None:
                if passwordRec.user_id == userID:
                    passwordRec.status = status
                    
                    self.session.commit()
                    
                    return True, 'Password updated'
                else:
                    return False, 'Password not found'
            else:
                return False, 'Password not found'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def checkPasswordPwned(self, password: str) -> tuple[bool, str]:
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url)
            
            if response.status_code != 200:
                return False, f"Erro ao acessar a API: {response.status_code}"
            
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return True, count
            
            return False, "A senha não foi encontrada em violações conhecidas."
        except Exception as e:
            return f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def findUserLogin(self, login: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(login=login).first()
            
            if user is not None:
                return True, user
            else:
                return False, 'Invalid user'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def updatePasswordsStatus(self, id: str) -> tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id, status=False).all()
            
            if passwords is not None:
                for password in passwords:
                    response = self.cryptograph.keyGenerator(id)
                    if response[0] == False:
                        return False, response[1]
                    key = response[1]
                    response = self.cryptograph.decryptSentence(password.password, key)
                    if response[0] == False:
                        return False, response[1]
                    password = response[1]
                    response = self.checkPasswordPwned(password)
                    if response[0] == True:
                        password.status = True
                    else:
                        password.status = False
                self.session.commit()
                
                return True, 'Passwords updated'
            else:
                return True, 'Passwords updated'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def sortUsers(self, user: User, query: str) -> tuple[bool, list[User]] | tuple[bool, str] | tuple[bool,  list[Passwords]]:
        try:
            if user.admin:
                items = self.session.query(User).filter_by(gerentBy=user.id).filter(User.login.like(f'%{query}%')).all()
            else:
                items = self.session.query(Passwords).filter_by(user_id=user.id).filter(Passwords.site.like(f'%{query}%')).all()  
            return True, items
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def getPassword(self, credId: str) -> tuple[bool, Passwords] | tuple[bool, str]:
        try:
            password = self.session.query(Passwords).filter_by(id=credId).first()
            
            if password is not None:
                return True, password
            else:
                return False, 'Invalid password'
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'