"""Rotas da API usadas pela extensão para salvar, atualizar e registrar uso de credenciais."""
from app import app as flaskApp
from database import database, Config, Passwords, Logs
from tests.conftest import makeUser, loginAs

CHROME_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36'


def apiLogin(client, login='alice', password='senha-forte-123'):
    resp = client.post('/api/auth/login', json={'login': login, 'password': password})
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def credentialOf(userId):
    with flaskApp.app_context():
        return Config.session.query(Passwords).filter(Passwords.userId == userId).one()


class TestCreate:
    def test_createsAndReturnsId(self, client):
        alice = makeUser('alice')
        resp = client.post('/api/passwords', headers=apiLogin(client), json={'site': 'github.com', 'login': 'me', 'password': 'pw-123456'})
        assert resp.status_code == 201
        credential = credentialOf(alice)
        assert resp.get_json() == {'id': credential.id}
        assert (credential.site, credential.login, credential.password) == ('github.com', 'me', 'pw-123456')

    def test_duplicateSiteAndLoginIsConflict(self, client):
        makeUser('alice')
        headers = apiLogin(client)
        first = client.post('/api/passwords', headers=headers, json={'site': 'github.com', 'login': 'Me', 'password': 'pw-1'})
        # mesmo host com outra grafia e login com outra caixa: ainda é a mesma credencial
        again = client.post('/api/passwords', headers=headers, json={'site': 'https://www.GitHub.com/login', 'login': 'me', 'password': 'pw-2'})
        assert again.status_code == 409
        assert again.get_json()['id'] == first.get_json()['id']

    def test_rejectsMissingAndOversizedFields(self, client):
        makeUser('alice')
        headers = apiLogin(client)
        assert client.post('/api/passwords', headers=headers, json={'site': 'a.com', 'login': 'me'}).status_code == 400
        assert client.post('/api/passwords', headers=headers, json={'site': 'a.com', 'login': 'me', 'password': 'x' * 201}).status_code == 400
        assert client.post('/api/passwords', headers=headers, json={'site': 123, 'login': 'me', 'password': 'pw'}).status_code == 400

    def test_requiresToken(self, client):
        assert client.post('/api/passwords', json={'site': 'a.com', 'login': 'me', 'password': 'pw'}).status_code == 401


class TestUpdate:
    def test_updatesPasswordAndKeepsFlags(self, client):
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addFlag(alice, 'work')
            database.addPassword(alice, 'github.com', 'me', 'old-pw-1', ['work'])
        credId = credentialOf(alice).id

        resp = client.put(f'/api/passwords/{credId}', headers=apiLogin(client), json={'password': 'new-pw-2'})
        assert resp.status_code == 200
        credential = credentialOf(alice)
        assert (credential.site, credential.login, credential.password) == ('github.com', 'me', 'new-pw-2')
        with flaskApp.app_context():
            assert Config.session.get(Passwords, credId).flags == ['work']

    def test_otherUsersCredentialIsNotFound(self, client):
        alice = makeUser('alice')
        makeUser('bob')
        with flaskApp.app_context():
            database.addPassword(alice, 'github.com', 'me', 'alice-pw', [])
        credId = credentialOf(alice).id

        resp = client.put(f'/api/passwords/{credId}', headers=apiLogin(client, 'bob'), json={'password': 'hacked'})
        assert resp.status_code == 404
        assert credentialOf(alice).password == 'alice-pw'


class TestRecordUsage:
    def test_writesLogAndShowsInVerLogs(self, client):
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addPassword(alice, 'github.com', 'me', 'pw-123456', [])
        credId = credentialOf(alice).id

        resp = client.post(f'/api/passwords/{credId}/use', headers={**apiLogin(client), 'User-Agent': CHROME_UA},
                           environ_base={'REMOTE_ADDR': '203.0.113.7'})
        assert resp.status_code == 201
        with flaskApp.app_context():
            log = Config.session.query(Logs).one()
            assert (log.passwordId, log.browser, log.version, log.os, log.ip) == (credId, 'Chrome', '155', 'Linux', '203.0.113.7')
            assert log.lastUse is not None

        loginAs(client)
        page = client.get(f'/moreInfo?passwordId={credId}').data.decode()
        assert 'Chrome 155' in page and 'Linux' in page and '203.0.113.7' in page

    def test_otherUsersCredentialIsNotFound(self, client):
        alice = makeUser('alice')
        makeUser('bob')
        with flaskApp.app_context():
            database.addPassword(alice, 'github.com', 'me', 'pw-123456', [])
        credId = credentialOf(alice).id

        assert client.post(f'/api/passwords/{credId}/use', headers=apiLogin(client, 'bob')).status_code == 404
        with flaskApp.app_context():
            assert Config.session.query(Logs).count() == 0

    def test_nonNumericIdIsNotFound(self, client):
        makeUser('alice')
        assert client.post('/api/passwords/abc/use', headers=apiLogin(client)).status_code == 404
