import locale, sys, os, uuid, hashlib, requests, datetime

from flask_sqlalchemy import SQLAlchemy
from cryptograph import Cryptograph
from flask_login import UserMixin
from dotenv import load_dotenv
from functools import wraps
from flask import Flask
from collections import Counter

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
    password = Config.db.Column(Config.db.String(255), nullable=False)
    role = Config.db.Column(Config.db.String(80), nullable=False)
    enabled = Config.db.Column(Config.db.Boolean, default=True, nullable=False)
    passwordPwned = Config.db.Column(Config.db.Boolean, default=False, nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'login': self.login,
            'role': self.role,
            'enabled': self.enabled,
            'passwordPwned': self.passwordPwned,
        }
        
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)

class Passwords(UserMixin, Config.db.Model):
    __tablename__ = 'Passwords'
    id = Config.db.Column(Config.db.Integer, primary_key=True, nullable=False, autoincrement=True)  
    user_id = Config.db.Column(Config.db.String(36), Config.db.ForeignKey('Users.id'), nullable=False)
    login = Config.db.Column(Config.db.String(80), nullable=False)
    password = Config.db.Column(Config.db.String(80), nullable=False)
    site = Config.db.Column(Config.db.String(80), nullable=False)
    status = Config.db.Column(Config.db.Boolean, nullable=False, default=False)
    lastUse = Config.db.Column(Config.db.DateTime, nullable=True)
    whereUsed = Config.db.Column(Config.db.String(80), nullable=True)

    
    def to_dict(self):
         
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site': self.site,
            'login': self.login,
            'password': self.password,
            'status': self.status,
            'lastUse': self.lastUse,
        }
      
    @property  
    def is_authenticated(self):
        return True
    
    @property
    def is_active(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    @property
    def get_id(self):
        return str(self.id)

class Database:
    def __init__(self) -> None:
        self.db = Config.db
        self.session = Config.session
        self.cryptograph = Cryptograph
        self.iscryptograph = Cryptograph()
        
        self.createTables()
        self.createSysadmin()
        
    
    def canHandle(f):
        @wraps(f)
        def wrapper(self, userId: str, itemType: str, method: str, item: Passwords | User = None, *args, **kwargs):
            current_user = Config.session.query(User).filter_by(id=userId).first()
            if not current_user:
                return False, 'Invalid user'
            match method:
                case 'get':
                    match itemType:
                        case 'user':
                            success, users = f(self, userId, *args, **kwargs)
                            if not success:
                                return False, users
                            if current_user.role == 'sysadmin':
                                return True, users
                            else:
                                return False, 403
                        case 'password':
                            success, passwords = f(self, userId, *args, **kwargs)
                            if not success:
                                return False, passwords
                            if current_user.role == 'sysadmin':
                                return True, passwords
                            else:
                                passwords = [password for password in passwords if password.user_id == current_user.id]
                                return True, passwords
                        case _:
                            return False, f'Invalid itemType'
                case 'post':
                    if item:
                        match itemType:
                            case 'user':
                                if current_user.role == 'sysadmin':
                                    success, msg = f(self, userId, item, *args, **kwargs)
                                    if not success:
                                        return False, msg
                                    return True, msg
                            case 'password':
                                owner = Config.session.query(User).filter_by(id=item.user_id).first()
                                if owner or current_user.role == 'sysadmin':
                                    success, msg = f(self, userId, item, *args, **kwargs)
                                    if not success:
                                        return False, msg
                                    return True, msg
                                else:
                                    return False, 'Invalid user'
                    return False, 'For post requests you need an item.'
                case _:
                    return False, f'Invalid method'
        
        return wrapper
        
    def createTables(self) -> None:
        with Config.app.app_context():
            self.db.create_all()
            
    
    def createSysadmin(self) -> None:
        with Config.app.app_context():
            try:
                user = User(login='sysadmin', password=self.iscryptograph.encryptPass('sysadmin'), role='sysadmin')
                self.session.add(user)
                self.session.commit()
            except Exception as e:
                self.session.rollback()
                return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
    
    
    def getDashboardInfo(self, id: str, headers: dict ,userId: str, page: int = 1, perPage: int = 10, sort: str = 'date', sortOrder: str = 'asc', query: str = '') -> tuple[bool, list[User]] | tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=userId).first()
            if user is None:
                return False, 'Invalid user'
            
            
            
            
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
            
    
    
    def getUser(self, id: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            
            if user:
                return True, user
            else:
                return False, 'Invalid user'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


    def validUser(self, login: str, password: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(login=login).first()
            
            if user is not None:
                success, msg = self.iscryptograph.isValidPass(user.password, password)
                print(success)
                if success:
                    return True, user
                else:
                    return False, 'Invalid credentials'
            else:
                return False, 'Invalid credentials'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


    def createUser(self, login: str, password: str) -> tuple[bool, User | str]:
        try:
            if User.query.filter_by(login=login).first() is None:
                user = User(login=login, password=self.iscryptograph.encryptPass(password))
                self.session.add(user)
                self.session.commit()
                
                return True, user
            else:
                return False, 'User already exists'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

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
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
    def updateUser(self, id: str, login: str = None, password: str = None, role: str = None) -> tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()

            if login is None:
                login = user.login
            if password is None:
                password = user.password
            else:
                password = self.iscryptograph.encryptPass(password)
            if role is None:
                role = user.role
            
            if user is not None:
                user.login = login
                user.password = password
                user.role = role
                    
                self.session.commit()
                    
                return True, 'User updated'
            else:
                return False, 'Invalid id'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def addPassword(self, gerentId, id: str, site: str, login: str, password: str ) -> tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            if user is None:
                return False, 'Invalid user'
            response = self.cryptograph.keyGenerator(id)
            if response[0] == False:
                return False, response[1]
            key = response[1]
            response = self.cryptograph.encryptSentence(password, key)
            if response[0] == False:
                return False, response[1]  
            password = response[1]
            cred = Passwords(user_id=id, password=password, site=site, login=login, lastUse=datetime.datetime.now())
            self.session.add(cred)
            self.session.commit()
            
            return True, 'Password added'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


    def getPasswords(self, id: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).all()
            response = self.cryptograph.keyGenerator(id)
            
            if passwords is not None:
                if response[0] == False:
                    return False, response[1]
                key = response[1]
                for password in passwords:
                    response = self.cryptograph.decryptSentence(password.password, key)
                    if response[0] == False:
                        return False, response[1]
                    password.password = response[1]
                return True, passwords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
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
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
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
            return f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def findUserLogin(self, login: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(login=login).first()
            
            if user is not None:
                return True, user
            else:
                return False, 'Invalid user'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def updatePasswordStatus(self, id: str) -> tuple[bool, str]:
        try:
            credentials = self.session.query(Passwords).filter_by(user_id=id, status=False).all()
            if credentials is not None:
                response = self.cryptograph.keyGenerator(id)
                if response[0] == False:
                    return False, response[1]
                key = response[1]
                for credential in credentials:
                    response = self.cryptograph.decryptSentence(credential.password, key)
                    if response[0] == False:
                        return False, response[1]
                    userPassword = response[1]
                    response = self.checkPasswordPwned(userPassword)
                    if response[0] == True:
                        credential.status = True
                        credential.timesLeaked = int(response[1])
                    else:
                        credential.status = False
                self.session.commit()
                
                return True, 'Passwords updated'
            else:
                return True, 'Passwords updated'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def getPassword(self, credId: str) -> tuple[bool, Passwords] | tuple[bool, str]:
        try:
            password = self.session.query(Passwords).filter_by(id=credId).first()
            
            if password is not None:
                return True, password
            else:
                return False, 'Invalid password'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def pwned(self, id: str) -> tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            
            if user is not None:
                user.passwordPwned = True
                self.session.commit()
                
                return True, 'Senha atualizada'
            else:
                return False, 'Invalid user'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
    def getLeakedPasswords(self, id: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).filter(Passwords.status == True).all()
            
            if passwords is not None:
                return True, passwords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
    def getMostUsedPasswords(self, id: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).all()
            
            if passwords is not None:
                passwordList = [Cryptograph.decryptSentence(password.password, id)[1] for password in passwords]
                
                passwordCounter = Counter(passwordList)
                
                mostUsedPasswords = passwordCounter.most_common(10)
                
                return True, mostUsedPasswords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def getGoodPasswords(self, id: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).filter(Passwords.status == False).all()
            
            if passwords is not None:
                return True, passwords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
    def getInfoByIP(self, passwordID: str, ip: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            password = self.session.query(Passwords).filter_by(id=passwordID).first()
            
            if password is not None:
                response = requests.get(f"https://ipapi.co/{ip}/json")
                if response.status_code == 200:
                    locationData = response.json()
                    Location = {
                    "city": locationData["city"],
                    "country": locationData["country_name"],
                    "lat": locationData["latitude"],
                    "lon": locationData["longitude"],
                    "region": locationData["region"],
                    "postal": locationData["postal"],
                    "timezone": locationData["timezone"],
                    "languages": locationData["languages"],
                    "asn": locationData["asn"],
                    "org": locationData["org"]
                }
                    
                    password.whereUsed = Location
                    self.session.commit()
                    return True, 'log added successfully'
                else:
                    return False, response.text
            else:
                return False, 'Invalid password'
            
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
''