from app import app as flaskApp
from cryptograph import lookupHash, encryptField, decryptField
from database import database, Config, Passwords, User
from extensions import limiter
from tests.conftest import makeUser, loginAs


def addCredential(userId, site='example.com', login='me', password='p4ss-word', flags=()):
    with flaskApp.app_context():
        success, msg = database.addPassword(userId=userId, site=site, login=login, password=password, flags=list(flags))
        assert success is True, msg
        return Config.session.query(Passwords).filter(Passwords.userId == userId).order_by(Passwords.id.desc()).first().id


class TestNoDefaultAdmin:
    def test_bootDoesNotCreateSysadmin(self):
        with flaskApp.app_context():
            assert Config.session.query(User).filter(User._login_hash == lookupHash('sysadmin')).first() is None

    def test_defaultCredentialsRejected(self, client):
        resp = loginAs(client, 'sysadmin', 'sysadmin')
        assert resp.headers['Location'].endswith('/login/')


class TestOwnership:
    def test_cannotEditOtherUsersCredential(self, client):
        alice = makeUser('alice')
        makeUser('bob')
        credId = addCredential(alice, password='alice-secret')

        loginAs(client, 'bob')
        client.post('/editPassword', data={'password_id': credId, 'site': 'x', 'login': 'x', 'password': 'hacked'})

        with flaskApp.app_context():
            assert Config.session.get(Passwords, credId).password == 'alice-secret'

    def test_cannotViewOtherUsersCredential(self, client):
        alice = makeUser('alice')
        makeUser('bob')
        credId = addCredential(alice)

        loginAs(client, 'bob')
        resp = client.post('/password/view', data={'password_id': credId})
        assert resp.status_code == 404
        assert 'password' not in resp.get_json()

    def test_cannotDeleteOtherUsersCredential(self, client):
        alice = makeUser('alice')
        makeUser('bob')
        credId = addCredential(alice)

        loginAs(client, 'bob')
        client.post('/deletePassword', data={'password_id': credId})
        with flaskApp.app_context():
            assert Config.session.get(Passwords, credId) is not None


class TestCsrf:
    def test_postWithoutTokenIsRejected(self, client):
        makeUser('alice')
        flaskApp.config['WTF_CSRF_ENABLED'] = True
        resp = loginAs(client)
        assert resp.status_code == 400

    def test_apiIsExempt(self, client):
        makeUser('alice')
        flaskApp.config['WTF_CSRF_ENABLED'] = True
        resp = client.post('/api/auth/login', json={'login': 'alice', 'password': 'senha-forte-123'})
        assert resp.status_code == 200


class TestRateLimit:
    def test_loginIsThrottled(self, client):
        limiter.enabled = True
        limiter.reset()
        codes = [loginAs(client, 'ghost', 'wrong').status_code for _ in range(6)]
        assert codes[-1] == 429


class TestAccounts:
    def test_disabledUserCannotLogin(self, client):
        userId = makeUser('alice')
        with flaskApp.app_context():
            Config.session.get(User, userId).enabled = False
            Config.session.commit()
        resp = loginAs(client)
        assert resp.headers['Location'].endswith('/login/')

    def test_signupRejectsShortPassword(self, client):
        client.post('/signup/', data={'login': 'carol', 'password': 'curta', 'passwordConfirm': 'curta'})
        with flaskApp.app_context():
            assert Config.session.query(User).count() == 0

    def test_lookupHashIsKeyed(self):
        import hashlib
        assert lookupHash('alice') != hashlib.sha256(b'alice').hexdigest()

    def test_fieldRoundTrip(self):
        assert decryptField(encryptField('olá')) == 'olá'


class TestApi:
    def token(self, client):
        resp = client.post('/api/auth/login', json={'login': 'alice', 'password': 'senha-forte-123'})
        return resp.get_json()['token']

    def test_listOmitsPasswords(self, client):
        alice = makeUser('alice')
        addCredential(alice)
        resp = client.get('/api/passwords', headers={'Authorization': f'Bearer {self.token(client)}'})
        assert resp.status_code == 200
        items = resp.get_json()
        assert len(items) == 1 and 'password' not in items[0]

    def test_decryptOnlyOwn(self, client):
        alice = makeUser('alice')
        bob = makeUser('bob')
        bobCred = addCredential(bob)
        aliceCred = addCredential(alice, password='mine')
        headers = {'Authorization': f'Bearer {self.token(client)}'}

        assert client.get(f'/api/passwords/{aliceCred}/decrypt', headers=headers).get_json() == {'password': 'mine'}
        assert client.get(f'/api/passwords/{bobCred}/decrypt', headers=headers).status_code == 404

    def test_tokenOfDisabledUserIsRejected(self, client):
        alice = makeUser('alice')
        token = self.token(client)
        with flaskApp.app_context():
            Config.session.get(User, alice).enabled = False
            Config.session.commit()
        resp = client.get('/api/auth/verify', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 401


class TestBootstrapAdmin:
    def test_createsAdminOnceAndNeverOverwrites(self, monkeypatch):
        import settings
        monkeypatch.setattr(settings, 'BOOTSTRAP_ADMIN_LOGIN', 'root')
        monkeypatch.setattr(settings, 'BOOTSTRAP_ADMIN_PASSWORD', 'primeira-senha-forte')
        database.bootstrapAdmin()

        monkeypatch.setattr(settings, 'BOOTSTRAP_ADMIN_PASSWORD', 'outra-senha-qualquer')
        database.bootstrapAdmin()

        with flaskApp.app_context():
            admin = Config.session.query(User).filter(User._login_hash == lookupHash('root')).one()
            assert admin.role == 'sysadmin'
            assert database.validUser('root', 'primeira-senha-forte')[0] is True


class TestDatabaseUrl:
    def test_postgresUrlsUsePsycopg3(self):
        from settings import _normalizeDatabaseUrl
        for url in ('postgres://u:p@h/db', 'postgresql://u:p@h/db', 'postgresql+psycopg2://u:p@h/db', 'postgresql+psycopg://u:p@h/db'):
            assert _normalizeDatabaseUrl(url) == 'postgresql+psycopg://u:p@h/db'
        assert _normalizeDatabaseUrl('sqlite://') == 'sqlite://'
