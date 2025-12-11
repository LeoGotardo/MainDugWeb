import locale, sys, os, uuid, hashlib, requests, datetime, hashlib, base64

from sqlalchemy.ext.hybrid import hybrid_property, Comparator
from flask_sqlalchemy import SQLAlchemy
from cryptograph import Cryptograph
from flask_login import UserMixin
from collections import Counter
from dotenv import load_dotenv
from functools import wraps
from flask import Flask
from icecream import ic

class Config:
    locale.setlocale(locale.LC_TIME, 'pt_BR.UTF-8')
    load_dotenv()
    SECRET_KEY = os.getenv('SecretKey') 
    DEFAULT_PASSWORD = os.getenv('DefaultPassword')
    ENCRYPT_KEY = os.getenv('SecretKey')
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SECRET_KEY'] = SECRET_KEY
    db = SQLAlchemy(app)
    session = db.session



class User(UserMixin, Config.db.Model):
    __tablename__ = 'tbl_0'
    
    id = Config.db.Column('col_a0', Config.db.String(36), default=lambda: str(uuid.uuid4()), primary_key=True, nullable=False)
    
    _login_encrypted = Config.db.Column('col_a1', Config.db.String(500), unique=True, nullable=False)
    _login_hash = Config.db.Column('col_a1_hash', Config.db.String(64), unique=True, nullable=False, index=True)
    password = Config.db.Column('col_a2', Config.db.String(255), nullable=False)
    
    _role_encrypted = Config.db.Column('col_a3', Config.db.String(500), nullable=False, default=lambda: base64.b64encode(Cryptograph.encryptSentence('user', Cryptograph.keyGenerator(Config.ENCRYPT_KEY)[1])[1]).decode('utf-8'))
    enabled = Config.db.Column('col_a4', Config.db.Boolean, default=True, nullable=False)
    passwordPwned = Config.db.Column('col_a5', Config.db.Boolean, default=False, nullable=False)
    
    @hybrid_property
    def login(self):
        if self._login_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._login_encrypted) if isinstance(self._login_encrypted, str) else self._login_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting login: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @login.setter
    def login(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._login_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                    self._login_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()
                else:
                    raise ValueError(f'Error encrypting login: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._login_encrypted = None
            self._login_hash = None
    
    @login.expression
    def login(cls):
        return cls._login_hash
    
    @login.comparator
    class LoginComparator(Comparator):
        def __eq__(self, other):
            if other is None:
                return self.__clause_element__().is_(None)
            otherHash = hashlib.sha256(other.encode('utf-8')).hexdigest()
            return self.__clause_element__() == otherHash
        
        def __ne__(self, other):
            if other is None:
                return self.__clause_element__().isnot(None)
            otherHash = hashlib.sha256(other.encode('utf-8')).hexdigest()
            return self.__clause_element__() != otherHash
            
    @hybrid_property
    def role(self):
        if self._role_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                # Converte de base64 string para bytes antes de decriptar
                encrypted_bytes = base64.b64decode(self._role_encrypted) if isinstance(self._role_encrypted, str) else self._role_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting role: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        else:
            return None
    
    @role.setter
    def role(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    # Converte bytes para base64 string
                    self._role_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting role: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key') 
        else:
            self._role_encrypted = None
    
    def toDict(self):
        return {
            'id': self.id,
            'login': self.login,  
            'role': self.role,    
            'enabled': self.enabled,
            'passwordPwned': self.passwordPwned,
        }
        
    def isAuthenticated(self):
        return True
    
    def isActive(self):
        return True
    
    def isAnonymous(self):
        return False
    
    def getId(self):
        return str(self.id)


class Passwords(UserMixin, Config.db.Model):
    __tablename__ = 'tbl_1'
    id = Config.db.Column('col_b0', Config.db.Integer, primary_key=True, nullable=False, autoincrement=True)  
    userId = Config.db.Column('col_b1', Config.db.String(36), Config.db.ForeignKey('tbl_0.col_a0'), nullable=False)
    
    # MUDANÇA: LargeBinary → String (armazena base64)
    _login_encrypted = Config.db.Column('col_b2', Config.db.String(500), nullable=False)
    _login_hash = Config.db.Column('col_b2_hash', Config.db.String(64), nullable=False, index=True)
    _password_encrypted = Config.db.Column('col_b3', Config.db.String(500), nullable=False)
    _site_encrypted = Config.db.Column('col_b4', Config.db.String(500), nullable=False)
    _site_hash = Config.db.Column('col_b4_hash', Config.db.String(64), nullable=False, index=True)
    status = Config.db.Column('col_b5', Config.db.Boolean, nullable=False, default=False)
    _lastUse_encrypted = Config.db.Column('col_b6', Config.db.String(500), nullable=True)
    _whereUsed_encrypted = Config.db.Column('col_b7', Config.db.String(500), nullable=True)
    
    @hybrid_property
    def login(self):
        if self._login_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._login_encrypted) if isinstance(self._login_encrypted, str) else self._login_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting login: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @login.setter
    def login(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._login_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                    self._login_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()
                else:
                    raise ValueError(f'Error encrypting login: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._login_encrypted = None
            self._login_hash = None
    
    @login.expression
    def login(cls):
        return cls._login_hash
    
    @login.comparator
    class LoginComparator(Comparator):
        def __eq__(self, other):
            if other is None:
                return self.__clause_element__().is_(None)
            otherHash = hashlib.sha256(other.encode('utf-8')).hexdigest()
            return self.__clause_element__() == otherHash
        
        def __ne__(self, other):
            if other is None:
                return self.__clause_element__().isnot(None)
            otherHash = hashlib.sha256(other.encode('utf-8')).hexdigest()
            return self.__clause_element__() != otherHash
            
    @hybrid_property
    def password(self):
        if self._password_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._password_encrypted) if isinstance(self._password_encrypted, str) else self._password_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting password: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @password.setter
    def password(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._password_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting password: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._password_encrypted = None
            
    @hybrid_property
    def site(self):
        if self._site_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._site_encrypted) if isinstance(self._site_encrypted, str) else self._site_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting site: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @site.setter
    def site(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._site_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                    self._site_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()
                else:
                    raise ValueError(f'Error encrypting site: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._site_encrypted = None
            self._site_hash = None
    
    @site.expression
    def site(cls):
        return cls._site_hash
    
    @site.comparator
    class SiteComparator(Comparator):
        def __eq__(self, other):
            if other is None:
                return self.__clause_element__().is_(None)
            otherHash = hashlib.sha256(other.encode('utf-8')).hexdigest()
            return self.__clause_element__() == otherHash
        
        def __ne__(self, other):
            if other is None:
                return self.__clause_element__().isnot(None)
            otherHash = hashlib.sha256(other.encode('utf-8')).hexdigest()
            return self.__clause_element__() != otherHash
            
    @hybrid_property
    def lastUse(self):
        encrypted_value = self._lastUse_encrypted 
        
        if encrypted_value is None or encrypted_value == "":
            return None
        
        try:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._lastUse_encrypted) if isinstance(self._lastUse_encrypted, str) else self._lastUse_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting lastUse: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        except Exception as e:
           raise(f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}')
    
    @lastUse.setter
    def lastUse(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._lastUse_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting lastUse: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._lastUse_encrypted = None
            
    @hybrid_property
    def whereUsed(self):
        if self._whereUsed_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._whereUsed_encrypted) if isinstance(self._whereUsed_encrypted, str) else self._whereUsed_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting whereUsed: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @whereUsed.setter
    def whereUsed(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._whereUsed_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting whereUsed: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._whereUsed_encrypted = None

    def toDict(self):  
        return {
            'id': self.id,
            'user_id': self.userId,
            'site': self.site,
            'login': self.login,
            'password': self.password,
            'status': self.status,
            'lastUse': self.lastUse,
            'whereUsed': self.whereUsed,
        }
      
    @property  
    def isAuthenticated(self):
        return True
    
    @property
    def isActive(self):
        return True
    
    @property
    def isAnonymous(self):
        return False
    
    @property
    def getId(self):
        return str(self.id)


class Logs(UserMixin, Config.db.Model):
    __tablename__ = 'tbl_2'
    id = Config.db.Column('col_c0', Config.db.Integer, primary_key=True, nullable=False, autoincrement=True)  
    passwordId = Config.db.Column('col_c1', Config.db.Integer, Config.db.ForeignKey('tbl_1.col_b0'), nullable=False)
    lastUse = Config.db.Column('col_c2', Config.db.DateTime, nullable=True)
    
    # MUDANÇA: LargeBinary → String (armazena base64)
    _ip_encrypted = Config.db.Column('col_c3', Config.db.String(500), nullable=True)
    _cidade_encrypted = Config.db.Column('col_c4', Config.db.String(500), nullable=True)
    _estado_encrypted = Config.db.Column('col_c5', Config.db.String(500), nullable=True)
    _pais_encrypted = Config.db.Column('col_c6', Config.db.String(500), nullable=True)
    _asn_encrypted = Config.db.Column('col_c7', Config.db.String(500), nullable=True)
    _os_encrypted = Config.db.Column('col_c8', Config.db.String(500), nullable=True)
    _browser_encrypted = Config.db.Column('col_c9', Config.db.String(500), nullable=True)
    _version_encrypted = Config.db.Column('col_c10', Config.db.String(500), nullable=True)
    
    @hybrid_property    
    def ip(self):    
        if self._ip_encrypted:    
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)    
            if response == True:
                encrypted_bytes = base64.b64decode(self._ip_encrypted) if isinstance(self._ip_encrypted, str) else self._ip_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting ip: {decrypted}')
            else:    
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @ip.setter
    def ip(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._ip_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting ip: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._ip_encrypted = None
            
    @hybrid_property
    def cidade(self):
        if self._cidade_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._cidade_encrypted) if isinstance(self._cidade_encrypted, str) else self._cidade_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting cidade: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @cidade.setter
    def cidade(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._cidade_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting cidade: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._cidade_encrypted = None
            
    @hybrid_property
    def estado(self):
        if self._estado_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._estado_encrypted) if isinstance(self._estado_encrypted, str) else self._estado_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting estado: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @estado.setter
    def estado(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._estado_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting estado: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._estado_encrypted = None
            
    @hybrid_property
    def pais(self):
        if self._pais_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._pais_encrypted) if isinstance(self._pais_encrypted, str) else self._pais_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting pais: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @pais.setter
    def pais(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._pais_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting pais: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._pais_encrypted = None
            
    @hybrid_property
    def asn(self):
        if self._asn_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._asn_encrypted) if isinstance(self._asn_encrypted, str) else self._asn_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting asn: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @asn.setter
    def asn(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._asn_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting asn: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._asn_encrypted = None
            
    @hybrid_property
    def os(self):
        if self._os_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._os_encrypted) if isinstance(self._os_encrypted, str) else self._os_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting os: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @os.setter
    def os(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._os_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting os: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._os_encrypted = None
            
    @hybrid_property
    def browser(self):
        if self._browser_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._browser_encrypted) if isinstance(self._browser_encrypted, str) else self._browser_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting browser: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @browser.setter
    def browser(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._browser_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting browser: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._browser_encrypted = None
            
    @hybrid_property
    def version(self):
        if self._version_encrypted:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                encrypted_bytes = base64.b64decode(self._version_encrypted) if isinstance(self._version_encrypted, str) else self._version_encrypted
                success, decrypted = Cryptograph.decryptSentence(encrypted_bytes, key)
                if success:
                    return decrypted
                else:
                    raise ValueError(f'Error decrypting version: {decrypted}')
            else:
                raise ValueError(f'{response} \nError generating decryption key')
        return None
    
    @version.setter
    def version(self, value):
        if value:
            response, key = Cryptograph.keyGenerator(Config.ENCRYPT_KEY)
            if response == True:
                success, encrypted = Cryptograph.encryptSentence(value, key)
                if success:
                    self._version_encrypted = base64.b64encode(encrypted).decode('utf-8') if isinstance(encrypted, bytes) else encrypted
                else:
                    raise ValueError(f'Error encrypting version: {encrypted}')
            else:
                raise ValueError(f'{response} \nError generating encryption key')
        else:
            self._version_encrypted = None
                   
    def toDict(self):
        return {
            'id': self.id,
            'password_id': self.passwordId,
            'lastUse': self.lastUse,
            'ip': self.ip,
            'cidade': self.cidade,
            'estado': self.estado,
            'pais': self.pais,
            'ASN': self.asn,
            'OS': self.os,
            'browser': self.browser,
            'version': self.version,
        }   
    
    @property  
    def isAuthenticated(self):
        return True
    
    @property
    def isActive(self):
        return True
    
    @property
    def isAnonymous(self):
        return False
    
    @property
    def getId(self):
        return str(self.id)


class Filters(UserMixin, Config.db.Model):
    __tablename__ = 'tbl_3'
    id = Config.db.Column('col_d0', Config.db.Integer, primary_key=True)
    name = Config.db.Column('col_d1', Config.db.String(50), nullable=False)
    userId = Config.db.Column('col_d2', Config.db.String(36), Config.db.ForeignKey('tbl_0.col_a0'), nullable=False)
    
    def toDict(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.userId,
            'passwords_id': [r.id for r in self.passwordsId]
        }

    @property
    def isAuthenticated(self):
        return True

    @property
    def isActive(self):
        return True

    @property
    def isAnonymous(self):
        return False

    @property
    def getId(self):
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
            # ...
            match method:
                case 'get':
                    match itemType:
                        case 'user':
                            success, users = f(self, userId, *args, **kwargs)
                            if success is not True:
                                return False, users
                            if current_user.role == 'sysadmin':
                                return True, users
                            else:
                                return False, 403
                        case 'password':
                            success, passwords = f(self, userId, *args, **kwargs)
                            if success is not True:
                                return False, passwords
                            if current_user.role == 'sysadmin':
                                return True, passwords
                            else:
                                passwords = [password for password in passwords if password['user_id'] == current_user.id]
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
                return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
    
    
    def getDashboardInfo(self, userId: str, page: int =1, perPage: int = 10, sort: str = 'date', sortOrder: str = 'asc', query: str = '') -> tuple[bool, dict]:
        """
        Gera estatísticas do dashboard baseadas no perfil do usuário.
        Para super users: estatísticas globais. Para outros: estatísticas da loja.

        Args:
            storeId (str): ID da loja para filtrar estatísticas
            page (int): Página atual para paginação de logs
            rowsPerPage (int): Quantidade de logs por página
            userId (str): ID do usuário solicitante (determina nível de acesso)

        Returns:
            tuple[bool, dict]: (True, dados_estatisticas) com contadores e rankings,
                            (False, mensagem_erro) se falha
        """
        try:
            perPage = int(perPage)
            page = int(page)
            sort = str(sort)
            sortOrder = str(sortOrder)
            query = str(query)
            
            
            user: User | None = self.session.query(User).filter_by(id=userId).first()
            if user:
                if user.role == 'super':
                    with Config.app.app_context():
                        
                        

                            
                        return True, {

                        }
                else:
                    baseQuery = self.session.query(Passwords).filter(Passwords.userId == userId)
                    flags = self.session.query(Filters).filter(Filters.userId == userId).all()
                    
                    # Executa a query paginada
                    paginatedPasswords = baseQuery.paginate(
                        page=page, 
                        per_page=perPage, 
                        error_out=False
                    )
                    
                    # 1. Gera a lista de navegação (Ex: [1, 2, None, 4, 5, 6, None, 10])
                    # O iter_pages já cria a lógica inteligente de "..." (None)
                    iter_pages_list = list(paginatedPasswords.iter_pages())
                    
                    # 2. Cria uma lista apenas com números para fazer as validações de lógica (sem None)
                    visible_numbers = [x for x in iter_pages_list if x is not None]

                    # Contagens para estatísticas (mantive sua lógica original aqui)
                    # Nota: Se tiver muitos dados, fazer .all() aqui pode ser pesado. 
                    # O ideal seria usar count() no banco, mas mantive sua lógica:
                    all_passwords_for_stats = baseQuery.all() 
                    passwordCount = len(all_passwords_for_stats)
                    leakedCount = sum(1 for p in all_passwords_for_stats if p.status)
                    decrypted_pass_list = [p.password for p in all_passwords_for_stats if p.password is not None]
                    counts = Counter(decrypted_pass_list)
                    repeatedCount = sum(1 for count in counts.values() if count > 1)

                    return True, {
                        'passwordCount': passwordCount,
                        'leakedCount': leakedCount,
                        'repeatedCount': repeatedCount,
                        'flags': flags,
                        'passwords': paginatedPasswords.items, 
                        'pagination': {
                            'currentPage': paginatedPasswords.page,
                            'totalPages': paginatedPasswords.pages,
                            'total': paginatedPasswords.total,
                            'perPage': paginatedPasswords.per_page,
                            'hasPrev': paginatedPasswords.has_prev,
                            'hasNext': paginatedPasswords.has_next,
                            'prevPage': paginatedPasswords.prev_num if paginatedPasswords.has_prev else None,
                            'nextPage': paginatedPasswords.next_num if paginatedPasswords.has_next else None,
                            
                            
                            'visiblePages': iter_pages_list, 
                            
                            'showFirst': 1 not in visible_numbers, 
                            
                            'showLast': paginatedPasswords.pages not in visible_numbers,
                            
                            'showLeftEllipsis': visible_numbers[0] > 2 if visible_numbers else False,
                            
                            'showRightEllipsis': (visible_numbers[-1] < paginatedPasswords.pages - 1) if visible_numbers else False
                        }
                    }
            else:
                return False, 'Invalid user'
                
        except Exception as e:
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
            
    
    def getUser(self, id: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            
            if user:
                return True, user
            else:
                return False, 'Invalid user'
        except Exception as e:
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
    @canHandle
    def getUsers(self, headers: list[dict[str, str]] = [], pagination: bool = False, query: str = None, page: int = 1, perPage: int = 10, sort: str = 'name', sortOrder: str = 'asc') -> tuple[bool, list[dict[User]]] | tuple[bool, str]:
        try:
            sortOptions = {
                'login': User.login,
                'enabled': User.enabled,
                'passwordPwned': User.passwordPwned,
                'role': User.role,
            }
            
            sortColumn = sortOptions.get(sort, User.login)
            
            with Config.app.app_context():
                base_query = self.session.query(User)
                    
                if query:
                    base_query = base_query.filter(User.login.ilike(f'%{query}%'))
                
                # Aplicar ordenação
                if sortOrder == 'desc':
                    base_query = base_query.order_by(sortColumn.desc())
                else:
                    base_query = base_query.order_by(sortColumn.asc())
                
                if pagination:
                    # Usar paginate diretamente na query
                    paginated_result = base_query.paginate(
                        page=page, 
                        per_page=perPage, 
                        error_out=False
                    )
                    o = base_query.all()
                    
                    if paginated_result.items:
                        # Converter items para dicionário
                        items_dict = [user.to_dict() for user in paginated_result.items]
                        
                        # Calcular informações de navegação
                        current_page = paginated_result.page
                        total_pages = paginated_result.pages
                        
                        # Páginas visíveis
                        start_page = max(1, current_page - 5)
                        end_page = min(total_pages, current_page + 5)
                        visible_pages = list(range(start_page, end_page + 1))
                        
                        pag = {
                            'items': items_dict,
                            'headers': headers,
                            'pagination': {
                                'currentPage': current_page,
                                'totalPages': total_pages,
                                 'total': paginated_result.total,
                                'perPage': paginated_result.per_page,
                                'hasPrev': paginated_result.has_prev,
                                'hasNext': paginated_result.has_next,
                                'prevPage': current_page - 1 if paginated_result.has_prev else None,
                                'nextPage': current_page + 1 if paginated_result.has_next else None,
                                'visiblePages': visible_pages,
                                'showFirst': 1 not in visible_pages,
                                'showLast': total_pages not in visible_pages,
                                'showLeftEllipsis': start_page > 2,
                                'showRightEllipsis': end_page < total_pages - 1
                            },
                            'filters': {
                                'query': query,
                                'sort': sort,
                                'sortOrder': sortOrder,
                            }
                        }
                        return True, pag
                    else:
                        # Retornar estrutura vazia mas consistente
                        return True, {
                            'items': [],
                            'headers': headers,
                            'pagination': {
                                'currentPage': 1,
                                'totalPages': 0,
                                'total': 0,
                                'perPage': perPage,
                                'hasPrev': False,
                                'hasNext': False,
                                'prevPage': None,
                                'nextPage': None,
                                'visiblePages': [],
                                'showFirst': False,
                                'showLast': False,
                                'showLeftEllipsis': False,
                                'showRightEllipsis': False
                            },
                            'filters': {
                                'query': query,
                                'sort': sort,
                                'sortOrder': sortOrder,
                            }
                        }
                else:
                    # Sem paginação - retornar lista simples
                    users = base_query.all()
                    if users:
                        return True, [user.to_dict() for user in users]
                    else:
                        return True, []
        except Exception as e:
            self.session.rollback()  # Garante que a transação não fique quebrada
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


    @canHandle
    def getPasswords(self, userId, headers: list[dict[str, str]] = [], pagination: bool = False, query: str = None, page: int = 1, perPage: int = 10, sort: str = 'pewed', sortOrder: str = 'asc') -> tuple[bool, list[dict[User]]] | tuple[bool, str]:
        try:
            sortOptions = {
                'lastUse': Passwords.lastUse,
                'site': Passwords.site,
                'login': Passwords.login,
                'strength': Passwords.strength,
                'status': Passwords.status,
            }
            
            sortColumn = sortOptions.get(sort, Passwords.name)
            
            with Config.app.app_context():
                base_query = self.session.query(Passwords).filter(Passwords.userId == userId)
                    
                if query:
                    base_query = base_query.filter(Passwords.name.ilike(f'%{query}%'))
                
                # Aplicar ordenação
                if sortOrder == 'desc':
                    base_query = base_query.order_by(sortColumn.desc())
                else:
                    base_query = base_query.order_by(sortColumn.asc())
                
                if pagination:
                    # Usar paginate diretamente na query
                    paginated_result = base_query.paginate(
                        page=page, 
                        per_page=perPage, 
                        error_out=False
                    )
                    o = base_query.all()
                    
                    if paginated_result.items:
                        # Converter items para dicionário
                        items_dict = [password.to_dict() for password in paginated_result.items]
                        
                        # Calcular informações de navegação
                        current_page = paginated_result.page
                        total_pages = paginated_result.pages
                        
                        # Páginas visíveis
                        start_page = max(1, current_page - 5)
                        end_page = min(total_pages, current_page + 5)
                        visible_pages = list(range(start_page, end_page + 1))
                        
                        pag = {
                            'items': items_dict,
                            'headers': headers,
                            'pagination': {
                                'currentPage': current_page,
                                'totalPages': total_pages,
                                 'total': paginated_result.total,
                                'perPage': paginated_result.per_page,
                                'hasPrev': paginated_result.has_prev,
                                'hasNext': paginated_result.has_next,
                                'prevPage': current_page - 1 if paginated_result.has_prev else None,
                                'nextPage': current_page + 1 if paginated_result.has_next else None,
                                'visiblePages': visible_pages,
                                'showFirst': 1 not in visible_pages,
                                'showLast': total_pages not in visible_pages,
                                'showLeftEllipsis': start_page > 2,
                                'showRightEllipsis': end_page < total_pages - 1
                            },
                            'filters': {
                                'query': query,
                                'sort': sort,
                                'sortOrder': sortOrder,
                                'userId': userId
                            }
                        }
                        return True, pag
                    else:
                        # Retornar estrutura vazia mas consistente
                        return True, {
                            'items': [],
                            'headers': headers,
                            'pagination': {
                                'currentPage': 1,
                                'totalPages': 0,
                                'total': 0,
                                'perPage': perPage,
                                'hasPrev': False,
                                'hasNext': False,
                                'prevPage': None,
                                'nextPage': None,
                                'visiblePages': [],
                                'showFirst': False,
                                'showLast': False,
                                'showLeftEllipsis': False,
                                'showRightEllipsis': False
                            },
                            'filters': {
                                'query': query,
                                'sort': sort,
                                'sortOrder': sortOrder,
                                'userId': userId
                            }
                        }
                else:
                    # Sem paginação - retornar lista simples
                    users = base_query.all()
                    if users:
                        return True, [user.to_dict() for user in users]
                    else:
                        return True, []
        except Exception as e:
            self.session.rollback()  # Garante que a transação não fique quebrada
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        

    def getPassword(self, credId: str) -> tuple[bool, Passwords] | tuple[bool, str]:
        try:
            password = self.session.query(Passwords).filter_by(id=credId).first()
            
            if password is not None:
                return True, password
            else:
                return False, 'Invalid password'
        except Exception as e:
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
    def getLeakedPasswords(self, id: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).filter(Passwords.status == True).all()
            
            if passwords is not None:
                return True, passwords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
    
    def getGoodPasswords(self, id: str) -> tuple[bool, list[Passwords]] | tuple[bool, str]:
        try:
            passwords = self.session.query(Passwords).filter_by(user_id=id).filter(Passwords.status == False).all()
            
            if passwords is not None:
                return True, passwords
            else:
                return False, 'Cant find any passwords'
        except Exception as e:
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
        
        
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
            return -1, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'