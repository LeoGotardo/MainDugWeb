import locale, sys, os, uuid, datetime, hashlib, math, requests
from types import SimpleNamespace

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from collections import Counter
from flask import Flask

import settings
from cryptograph import Cryptograph, encryptField, decryptField, lookupHash


class Config:
    try:
        locale.setlocale(locale.LC_TIME, 'pt_BR.UTF-8')
    except locale.Error:
        pass
    _src_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(__name__,
                template_folder=os.path.join(_src_dir, 'templates'),
                static_folder=os.path.join(_src_dir, 'static'))
    app.config.update(
        SECRET_KEY=settings.SECRET_KEY,
        SQLALCHEMY_DATABASE_URI=settings.DATABASE_URL,
        SQLALCHEMY_ENGINE_OPTIONS={'pool_pre_ping': True},
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=settings.IS_PROD,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE='Lax',
        REMEMBER_COOKIE_SECURE=settings.IS_PROD,
        REMEMBER_COOKIE_DURATION=datetime.timedelta(days=7),
        MAX_CONTENT_LENGTH=1024 * 1024,
        DEBUG=settings.DEBUG,
    )
    db = SQLAlchemy(app)
    session = db.session


def _errorMsg(e: Exception) -> str:
    return f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'


def encryptedProperty(columnAttr: str, hashAttr: str | None = None) -> property:
    """
    Atributo que cifra ao gravar e decifra ao ler a coluna `columnAttr`.
    Com `hashAttr`, também mantém o hash de busca (HMAC) daquela coluna.
    Para filtrar por esses campos, compare a coluna de hash com `lookupHash(valor)`.
    """
    def getter(self):
        return decryptField(getattr(self, columnAttr))

    def setter(self, value):
        if value:
            value = str(value)
            setattr(self, columnAttr, encryptField(value))
            if hashAttr:
                setattr(self, hashAttr, lookupHash(value))
        else:
            setattr(self, columnAttr, None)
            if hashAttr:
                setattr(self, hashAttr, None)

    return property(getter, setter)


def buildPagination(page: int, perPage: int, total: int, window: int = 2) -> dict:
    totalPages = max(1, math.ceil(total / perPage)) if total else 0
    page = min(max(1, page), totalPages or 1)
    start = max(1, page - window)
    end = min(totalPages, page + window)
    visible = list(range(start, end + 1)) if totalPages else []
    return {
        'currentPage': page,
        'totalPages': totalPages,
        'total': total,
        'perPage': perPage,
        'hasPrev': page > 1,
        'hasNext': page < totalPages,
        'prevPage': page - 1 if page > 1 else None,
        'nextPage': page + 1 if page < totalPages else None,
        'visiblePages': visible,
        'showFirst': bool(visible) and 1 not in visible,
        'showLast': bool(visible) and totalPages not in visible,
        'showLeftEllipsis': start > 2,
        'showRightEllipsis': end < totalPages - 1,
    }


def _paginate(items: list, page: int, perPage: int) -> tuple[list, dict]:
    pagination = buildPagination(page, perPage, len(items))
    offset = (pagination['currentPage'] - 1) * perPage
    return items[offset:offset + perPage], pagination


def _parseLastUse(value: str | None) -> datetime.datetime:
    try:
        return datetime.datetime.strptime(value, '%d/%m/%Y %H:%M:%S')
    except (TypeError, ValueError):
        return datetime.datetime.min


class User(UserMixin, Config.db.Model):
    __tablename__ = 'tbl_0'

    id = Config.db.Column('col_a0', Config.db.String(36), default=lambda: str(uuid.uuid4()), primary_key=True, nullable=False)
    _login_encrypted = Config.db.Column('col_a1', Config.db.String(500), unique=True, nullable=False)
    _login_hash = Config.db.Column('col_a1_hash', Config.db.String(64), unique=True, nullable=False, index=True)
    password = Config.db.Column('col_a2', Config.db.String(255), nullable=False)
    _role_encrypted = Config.db.Column('col_a3', Config.db.String(500), nullable=False, default=lambda: encryptField('user'))
    enabled = Config.db.Column('col_a4', Config.db.Boolean, default=True, nullable=False)
    passwordPwned = Config.db.Column('col_a5', Config.db.Boolean, default=False, nullable=False)
    profilePic = Config.db.Column('col_a6', Config.db.String(500), nullable=True, default=None)

    login = encryptedProperty('_login_encrypted', '_login_hash')
    role = encryptedProperty('_role_encrypted')

    @property
    def is_active(self):
        # Conta desativada não autentica e perde a sessão no próximo request.
        return bool(self.enabled)

    def toDict(self):
        return {
            'id': self.id,
            'login': self.login,
            'role': self.role,
            'enabled': self.enabled,
            'passwordPwned': self.passwordPwned,
            'profilePic': self.profilePic,
        }


class Passwords(Config.db.Model):
    __tablename__ = 'tbl_1'
    id = Config.db.Column('col_b0', Config.db.Integer, primary_key=True, nullable=False, autoincrement=True)
    userId = Config.db.Column('col_b1', Config.db.String(36), Config.db.ForeignKey('tbl_0.col_a0'), nullable=False)
    _login_encrypted = Config.db.Column('col_b2', Config.db.String(500), nullable=False)
    _login_hash = Config.db.Column('col_b2_hash', Config.db.String(64), nullable=False, index=True)
    _password_encrypted = Config.db.Column('col_b3', Config.db.String(500), nullable=False)
    _site_encrypted = Config.db.Column('col_b4', Config.db.String(500), nullable=False)
    _site_hash = Config.db.Column('col_b4_hash', Config.db.String(64), nullable=False, index=True)
    status = Config.db.Column('col_b5', Config.db.Boolean, nullable=False, default=False)
    _lastUse_encrypted = Config.db.Column('col_b6', Config.db.String(500), nullable=True, default=None)
    _whereUsed_encrypted = Config.db.Column('col_b7', Config.db.String(500), nullable=True, default=None)

    login = encryptedProperty('_login_encrypted', '_login_hash')
    password = encryptedProperty('_password_encrypted')
    site = encryptedProperty('_site_encrypted', '_site_hash')
    lastUse = encryptedProperty('_lastUse_encrypted')
    whereUsed = encryptedProperty('_whereUsed_encrypted')

    @property
    def flags(self) -> list[str]:
        return [f.name for f in self.filters]

    def toDict(self, includePassword: bool = False):
        data = {
            'id': self.id,
            'user_id': self.userId,
            'site': self.site,
            'login': self.login,
            'status': self.status,
            'lastUse': self.lastUse,
            'whereUsed': self.whereUsed,
            'flags': self.flags,
        }
        if includePassword:
            data['password'] = self.password
        return data


class Logs(Config.db.Model):
    __tablename__ = 'tbl_2'
    id = Config.db.Column('col_c0', Config.db.Integer, primary_key=True, nullable=False, autoincrement=True)
    passwordId = Config.db.Column('col_c1', Config.db.Integer, Config.db.ForeignKey('tbl_1.col_b0', ondelete='CASCADE'), nullable=False)
    lastUse = Config.db.Column('col_c2', Config.db.DateTime, nullable=True)
    _ip_encrypted = Config.db.Column('col_c3', Config.db.String(500), nullable=True)
    _cidade_encrypted = Config.db.Column('col_c4', Config.db.String(500), nullable=True)
    _estado_encrypted = Config.db.Column('col_c5', Config.db.String(500), nullable=True)
    _pais_encrypted = Config.db.Column('col_c6', Config.db.String(500), nullable=True)
    _asn_encrypted = Config.db.Column('col_c7', Config.db.String(500), nullable=True)
    _os_encrypted = Config.db.Column('col_c8', Config.db.String(500), nullable=True)
    _browser_encrypted = Config.db.Column('col_c9', Config.db.String(500), nullable=True)
    _version_encrypted = Config.db.Column('col_c10', Config.db.String(500), nullable=True)

    ip = encryptedProperty('_ip_encrypted')
    cidade = encryptedProperty('_cidade_encrypted')
    estado = encryptedProperty('_estado_encrypted')
    pais = encryptedProperty('_pais_encrypted')
    asn = encryptedProperty('_asn_encrypted')
    os = encryptedProperty('_os_encrypted')
    browser = encryptedProperty('_browser_encrypted')
    version = encryptedProperty('_version_encrypted')

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


class PasswordFlags(Config.db.Model):
    __tablename__ = 'tbl_4'
    passwordId = Config.db.Column('col_e0', Config.db.Integer, Config.db.ForeignKey('tbl_1.col_b0', ondelete='CASCADE'), primary_key=True)
    flagId = Config.db.Column('col_e1', Config.db.Integer, Config.db.ForeignKey('tbl_3.col_d0', ondelete='CASCADE'), primary_key=True)


class Filters(Config.db.Model):
    __tablename__ = 'tbl_3'
    id = Config.db.Column('col_d0', Config.db.Integer, primary_key=True)
    name = Config.db.Column('col_d1', Config.db.String(50), nullable=False)
    userId = Config.db.Column('col_d2', Config.db.String(36), Config.db.ForeignKey('tbl_0.col_a0'), nullable=False)

    passwords = Config.db.relationship('Passwords',
                                       secondary=PasswordFlags.__table__,
                                       backref=Config.db.backref('filters', lazy='dynamic'))

    def toDict(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.userId,
            'passwords_id': [p.id for p in self.passwords],
        }


class Database:
    def __init__(self) -> None:
        self.db = Config.db
        self.session = Config.session
        self.iscryptograph = Cryptograph()
        self.createTables()
        self.bootstrapAdmin()

    def createTables(self) -> None:
        with Config.app.app_context():
            self.db.create_all()

    def bootstrapAdmin(self) -> None:
        """Cria o sysadmin de BOOTSTRAP_ADMIN_* se ele ainda não existir. Nunca altera uma conta existente."""
        if not settings.BOOTSTRAP_ADMIN_LOGIN:
            return
        with Config.app.app_context():
            if self.session.query(User).filter(User._login_hash == lookupHash(settings.BOOTSTRAP_ADMIN_LOGIN)).first():
                return
            success, result = self.createUser(settings.BOOTSTRAP_ADMIN_LOGIN, settings.BOOTSTRAP_ADMIN_PASSWORD, role='sysadmin')
            if success is True:
                Config.app.logger.warning(f'Admin "{settings.BOOTSTRAP_ADMIN_LOGIN}" criado a partir de BOOTSTRAP_ADMIN_*.')
            else:
                Config.app.logger.error(f'Falha ao criar admin inicial: {result}')

    def _userFlags(self, userId: str, names: list[str]) -> tuple[bool, list[Filters] | str]:
        flags = []
        for name in dict.fromkeys(n.strip().lower() for n in names if n and n.strip()):
            flag = self.session.query(Filters).filter_by(userId=userId, name=name).first()
            if flag is None:
                return False, f'Flag "{name}" não encontrada para este usuário.'
            flags.append(flag)
        return True, flags

    def _userPasswords(self, userId: str, query: str = '', sort: str = 'site', sortOrder: str = 'asc') -> list[Passwords]:
        """Todas as credenciais do usuário, filtradas e ordenadas já decifradas (busca por substring não funciona sobre dados cifrados)."""
        passwords = self.session.query(Passwords).filter(Passwords.userId == userId).all()

        query = (query or '').strip().lower()
        if query:
            passwords = [p for p in passwords if query in (p.site or '').lower() or query in (p.login or '').lower()]

        sortKeys = {
            'site': lambda p: (p.site or '').lower(),
            'login': lambda p: (p.login or '').lower(),
            'status': lambda p: p.status,
            'lastUse': lambda p: _parseLastUse(p.lastUse),
        }
        passwords.sort(key=sortKeys.get(sort, sortKeys['site']), reverse=sortOrder == 'desc')
        return passwords

    def getDashboardInfo(self, userId: str, page: int = 1, perPage: int = 10, sort: str = 'site', sortOrder: str = 'asc', query: str = '') -> tuple[bool, dict | str]:
        try:
            page = int(page)
            perPage = min(max(int(perPage), 1), 100)

            user: User | None = self.session.query(User).filter_by(id=userId).first()
            if user is None:
                return False, 'Invalid user'

            filters = {'query': query, 'sort': sort, 'sortOrder': sortOrder}

            if user.role == 'super':
                totalPasswords = self.session.query(Passwords).count()
                return True, {
                    'passwordCount': totalPasswords,
                    'leakedCount': self.session.query(Passwords).filter(Passwords.status == True).count(),
                    'repeatedCount': 0,
                    'totalUsers': self.session.query(User).count(),
                    'flags': [],
                    'passwords': [],
                    'pagination': buildPagination(1, perPage, 0),
                    'filters': filters,
                }

            allPasswords = self.session.query(Passwords).filter(Passwords.userId == userId).all()
            counts = Counter(p.password for p in allPasswords if p.password is not None)

            visible = self._userPasswords(userId, query=query, sort=sort, sortOrder=sortOrder)
            pageItems, pagination = _paginate(visible, page, perPage)

            return True, {
                'passwordCount': len(allPasswords),
                'leakedCount': sum(1 for p in allPasswords if p.status),
                'repeatedCount': sum(1 for c in counts.values() if c > 1),
                'flags': self.session.query(Filters).filter(Filters.userId == userId).all(),
                'passwords': pageItems,
                'pagination': pagination,
                'filters': filters,
            }
        except Exception as e:
            return -1, _errorMsg(e)

    def getUser(self, id: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            if user:
                return True, user
            return False, 'Invalid user'
        except Exception as e:
            return -1, _errorMsg(e)

    def getStats(self, userId: str) -> tuple[bool, dict | str]:
        try:
            user = self.session.query(User).filter_by(id=userId).first()
            if not user:
                return False, 'Usuário não encontrado'

            passwords = self.session.query(Passwords).filter_by(userId=userId).all()

            leakedPasswords = []
            weakPasswords = []
            reusedPasswordsDict = {}

            for password in passwords:
                entry = {'id': password.id, 'site': password.site, 'login': password.login}
                if password.status:
                    leakedPasswords.append(entry)

                decryptedPass = password.password
                if decryptedPass and len(decryptedPass) < 8:
                    weakPasswords.append({**entry, 'reason': 'Menos de 8 caracteres'})
                if decryptedPass:
                    reusedPasswordsDict.setdefault(decryptedPass, []).append(entry)

            reusedPasswords = [v for v in reusedPasswordsDict.values() if len(v) > 1]

            return True, {
                'totalPasswords': len(passwords),
                'leakedCount': len(leakedPasswords),
                'weakCount': len(weakPasswords),
                'reusedCount': len(reusedPasswords),
                'leakedPasswords': leakedPasswords,
                'weakPasswords': weakPasswords,
                'reusedPasswords': [{'sites': [p['site'] for p in sites], 'count': len(sites)} for sites in reusedPasswords],
            }
        except Exception as e:
            return -1, _errorMsg(e)

    def getUsers(self, query: str = '', page: int = 1, perPage: int = 50, sort: str = 'login', sortOrder: str = 'asc') -> tuple[bool, list[dict]] | tuple[int, str]:
        try:
            users = [u.toDict() for u in self.session.query(User).all()]

            query = (query or '').strip().lower()
            if query:
                users = [u for u in users if query in (u['login'] or '').lower()]

            sortKey = sort if sort in ('login', 'role', 'enabled', 'passwordPwned') else 'login'
            users.sort(key=lambda u: str(u[sortKey]).lower(), reverse=sortOrder == 'desc')

            pageItems, _ = _paginate(users, int(page), int(perPage))
            return True, pageItems
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def validUser(self, login: str, password: str) -> tuple[bool, User | str]:
        try:
            user = self.session.query(User).filter(User._login_hash == lookupHash(login)).first()

            if user is None:
                self.iscryptograph.burnVerify(password)
                return False, 'Credenciais inválidas'

            success, _ = self.iscryptograph.isValidPass(user.password, password)
            if success is not True or not user.enabled:
                return False, 'Credenciais inválidas'
            return True, user
        except Exception as e:
            Config.app.logger.error(f'Erro em validUser: {_errorMsg(e)}')
            return False, 'Erro ao validar credenciais'

    def createUser(self, login: str, password: str, role: str = 'user') -> tuple[bool, User | str]:
        try:
            if self.session.query(User).filter(User._login_hash == lookupHash(login)).first() is not None:
                return False, 'Usuário já existe. Escolha outro nome de usuário.'

            newUser = User(login=login, password=self.iscryptograph.encryptPass(password), role=role)
            self.session.add(newUser)
            self.session.commit()
            return True, newUser
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def addFlag(self, id: str, name: str) -> tuple[bool, str]:
        try:
            if self.session.query(User).filter_by(id=id).first() is None:
                return False, 'Invalid user'
            if self.session.query(Filters).filter_by(userId=id, name=name).first() is not None:
                return False, 'Flag já existe'
            self.session.add(Filters(userId=id, name=name))
            self.session.commit()
            return True, 'Flag added'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def deleteFlag(self, id: str, flagId: str) -> tuple[bool, str]:
        try:
            flag = self.session.query(Filters).filter_by(id=flagId, userId=id).first()
            if flag is None:
                return False, 'Flag not found'
            self.session.query(PasswordFlags).filter_by(flagId=flag.id).delete()
            self.session.delete(flag)
            self.session.commit()
            return True, 'Flag deleted'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def deleteUser(self, id: str) -> tuple[bool, str]:
        try:
            user = self.session.query(User).filter_by(id=id).first()
            if user is None:
                return False, 'User not found'
            passwordIds = [p.id for p in self.session.query(Passwords.id).filter_by(userId=id)]
            if passwordIds:
                self.session.query(PasswordFlags).filter(PasswordFlags.passwordId.in_(passwordIds)).delete(synchronize_session=False)
                self.session.query(Logs).filter(Logs.passwordId.in_(passwordIds)).delete(synchronize_session=False)
                self.session.query(Passwords).filter_by(userId=id).delete(synchronize_session=False)
            self.session.query(Filters).filter_by(userId=id).delete(synchronize_session=False)
            self.session.delete(user)
            self.session.commit()
            return True, 'User deleted'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def updateUser(self, id: str, password: str = None, role: str = None, profilePic: str = None) -> tuple[bool, str]:
        """O login não muda por aqui: ele é a chave de busca da conta."""
        try:
            user = self.session.query(User).filter_by(id=id).first()
            if user is None:
                return False, 'Invalid id'

            if password:
                user.password = self.iscryptograph.encryptPass(password)
            if role:
                user.role = role
            if profilePic is not None:
                user.profilePic = profilePic or None

            self.session.commit()
            return True, 'User updated'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def addPassword(self, userId: str, site: str, login: str, password: str, flags: list[str]) -> tuple[bool, str]:
        try:
            if not self.session.query(User).filter_by(id=userId).first():
                return False, 'Usuário não encontrado'

            ok, flagObjs = self._userFlags(userId, flags)
            if not ok:
                return False, flagObjs

            leaked, _ = self.checkPasswordPwned(password)
            newPassword = Passwords(
                userId=userId,
                site=site,
                login=login,
                password=password,
                lastUse=datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                status=leaked is True,
            )
            self.session.add(newPassword)
            self.session.flush()

            for flag in flagObjs:
                self.session.add(PasswordFlags(passwordId=newPassword.id, flagId=flag.id))

            self.session.commit()
            return True, 'Senha e flags cadastradas com sucesso'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def updatePassword(self, passwordId: str, userId: str, site: str, login: str, password: str, flags: list[str]) -> tuple[bool, str]:
        try:
            credential = self.session.query(Passwords).filter_by(id=passwordId, userId=userId).first()
            if credential is None:
                return False, 'Senha não encontrada'

            ok, flagObjs = self._userFlags(userId, flags)
            if not ok:
                return False, flagObjs

            passwordChanged = password != credential.password
            credential.site = site
            credential.login = login
            credential.password = password
            if passwordChanged:
                leaked, _ = self.checkPasswordPwned(password)
                credential.status = leaked is True

            # As flags enviadas substituem as anteriores.
            self.session.query(PasswordFlags).filter_by(passwordId=credential.id).delete()
            for flag in flagObjs:
                self.session.add(PasswordFlags(passwordId=credential.id, flagId=flag.id))

            self.session.commit()
            return True, 'Senha e flags atualizadas com sucesso'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def getPasswords(self, userId: str, query: str = '', page: int = 1, perPage: int = 50, sort: str = 'site', sortOrder: str = 'asc') -> tuple[bool, dict] | tuple[int, str]:
        """Lista paginada para a API. Não inclui a senha: ela sai só por /passwords/<id>/decrypt."""
        try:
            perPage = min(max(int(perPage), 1), 100)
            passwords = self._userPasswords(userId, query=query, sort=sort, sortOrder=sortOrder)
            pageItems, pagination = _paginate(passwords, int(page), perPage)
            return True, {
                'items': [p.toDict() for p in pageItems],
                'pagination': pagination,
                'filters': {'query': query, 'sort': sort, 'sortOrder': sortOrder},
            }
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def deletePassword(self, passwordId: str, userId: str) -> tuple[bool, str]:
        try:
            password = self.session.query(Passwords).filter_by(id=passwordId, userId=userId).first()
            if password is None:
                return False, 'Password not found'

            self.session.query(PasswordFlags).filter_by(passwordId=password.id).delete()
            self.session.query(Logs).filter_by(passwordId=password.id).delete()
            self.session.delete(password)
            self.session.commit()
            return True, 'Password deleted'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def checkPasswordPwned(self, password: str) -> tuple[bool, str]:
        """k-anonymity da HIBP: só os 5 primeiros caracteres do SHA-1 saem da máquina."""
        try:
            sha1Hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1Hash[:5], sha1Hash[5:]

            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5, headers={'Add-Padding': 'true'})
            if response.status_code != 200:
                return False, f'Erro ao acessar a API: {response.status_code}'

            for line in response.text.splitlines():
                hashSuffix, _, count = line.partition(':')
                if hashSuffix == suffix and count.strip() != '0':
                    return True, count.strip()
            return False, 'A senha não foi encontrada em violações conhecidas.'
        except Exception as e:
            return False, f'{type(e).__name__}: {e}'

    def updatePasswordStatus(self, id: str) -> tuple[bool, str]:
        try:
            for credential in self.session.query(Passwords).filter_by(userId=id, status=False).all():
                if credential.password:
                    leaked, _ = self.checkPasswordPwned(credential.password)
                    credential.status = leaked is True
            self.session.commit()
            return True, 'Passwords updated'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)

    def getPassword(self, credId: str, userId: str) -> tuple[bool, Passwords] | tuple[bool, str]:
        """Busca sempre restrita ao dono: uma credencial de outro usuário é 'não encontrada'."""
        try:
            password = self.session.query(Passwords).filter_by(id=credId, userId=userId).first()
            if password is not None:
                return True, password
            return False, 'Invalid password'
        except Exception as e:
            return -1, _errorMsg(e)

    def getPasswordLogs(self, passwordId: str, userId: str) -> tuple[bool, object | str]:
        try:
            password = self.session.query(Passwords).filter_by(id=passwordId, userId=userId).first()
            if not password:
                return False, 'Credencial não encontrada ou acesso negado'

            logs = self.session.query(Logs).filter_by(passwordId=password.id).order_by(Logs.lastUse.desc()).all()
            return True, SimpleNamespace(
                id=password.id,
                site=password.site,
                login=password.login,
                status=password.status,
                flags=password.flags,
                logs=logs,
            )
        except Exception as e:
            return -1, _errorMsg(e)

    def deletePasswordLogs(self, logs: list, userId: str) -> tuple[bool, str]:
        try:
            deleted = 0
            for logId in logs:
                log = self.session.query(Logs).filter_by(id=int(logId)).first()
                if not log:
                    continue
                if not self.session.query(Passwords).filter_by(id=log.passwordId, userId=userId).first():
                    self.session.rollback()
                    return False, 'Acesso negado'
                self.session.delete(log)
                deleted += 1

            self.session.commit()
            return True, f'{deleted} log(s) excluído(s) com sucesso'
        except Exception as e:
            self.session.rollback()
            return -1, _errorMsg(e)


database = Database()
