from app import app as flaskApp
from database import database, Config, Passwords, Filters, buildPagination
from tests.conftest import makeUser, loginAs


class TestFlags:
    def test_updateReplacesFlags(self):
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addFlag(alice, 'work')
            database.addFlag(alice, 'home')
            database.addPassword(alice, 'a.com', 'me', 'pw-123456', ['work'])
            credId = Config.session.query(Passwords).first().id

            success, msg = database.updatePassword(credId, alice, 'a.com', 'me', 'pw-123456', ['home'])
            assert success is True, msg
            assert Config.session.get(Passwords, credId).flags == ['home']

    def test_flagsAppearOnDashboard(self, client):
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addFlag(alice, 'work')
            database.addPassword(alice, 'a.com', 'me', 'pw-123456', ['work'])
        loginAs(client)
        assert b'work' in client.get('/').data


class TestDashboard:
    def test_searchAndPagination(self, client):
        alice = makeUser('alice')
        with flaskApp.app_context():
            for i in range(12):
                database.addPassword(alice, f'site{i:02d}.com', 'me', 'pw-123456', [])
        loginAs(client)

        page2 = client.get('/?page=2').data
        assert b'site10.com' in page2 and b'site00.com' not in page2

        found = client.get('/?query=site05').data
        assert b'site05.com' in found and b'site06.com' not in found

    def test_sysadminDashboardListsUsers(self, client):
        makeUser('root', role='sysadmin')
        makeUser('alice')
        loginAs(client, 'root')
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'alice' in resp.data

    def test_paginationHasNoGaps(self):
        p = buildPagination(page=5, perPage=10, total=200)
        assert p['visiblePages'] == [3, 4, 5, 6, 7]
        assert p['showFirst'] and p['showLast']
        assert buildPagination(1, 10, 0)['totalPages'] == 0


class TestOwnerActions:
    """O dono consegue agir sobre as próprias credenciais. IDs chegam dos formulários como texto."""

    def setupCredential(self):
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addFlag(alice, 'work')
            database.addPassword(alice, 'a.com', 'me', 'old-secret-1', ['work'])
            return alice, Config.session.query(Passwords).first().id

    def test_viewOwn(self, client):
        _, credId = self.setupCredential()
        loginAs(client)
        resp = client.post('/password/view', data={'password_id': str(credId)})
        assert resp.status_code == 200
        assert resp.get_json() == {'success': True, 'password': 'old-secret-1'}

    def test_editOwn(self, client):
        _, credId = self.setupCredential()
        loginAs(client)
        client.post('/editPassword', data={'password_id': str(credId), 'site': 'b.com', 'login': 'me2', 'password': 'new-secret-2'})
        with flaskApp.app_context():
            credential = Config.session.get(Passwords, credId)
            assert (credential.site, credential.login, credential.password) == ('b.com', 'me2', 'new-secret-2')

    def test_deleteOwn(self, client):
        _, credId = self.setupCredential()
        loginAs(client)
        client.post('/deletePassword', data={'password_id': str(credId)})
        with flaskApp.app_context():
            assert Config.session.get(Passwords, credId) is None

    def test_moreInfoOwn(self, client):
        _, credId = self.setupCredential()
        loginAs(client)
        resp = client.get(f'/moreInfo?passwordId={credId}')
        assert resp.status_code == 200
        assert b'a.com' in resp.data

    def test_deleteOwnFlag(self, client):
        alice, _ = self.setupCredential()
        loginAs(client)
        with flaskApp.app_context():
            flagId = database.session.query(Filters).filter_by(userId=alice).one().id
        resp = client.post('/flags/delete', data={'flag_id': str(flagId)})
        assert resp.get_json()['success'] is True
        with flaskApp.app_context():
            assert Config.session.query(Passwords).first().flags == []

    def test_nonNumericIdIsNotFound(self, client):
        self.setupCredential()
        loginAs(client)
        assert client.post('/password/view', data={'password_id': 'abc'}).status_code == 404


class TestFlagForm:
    def test_addFlagRedirectsBackToDashboard(self, client):
        makeUser('alice')
        loginAs(client)
        resp = client.post('/flags/add', data={'flagName': 'Pessoal'})
        assert resp.status_code == 302 and resp.headers['Location'].endswith('/')
        assert b'pessoal' in client.get('/').data

    def test_viewButtonCarriesFlags(self, client):
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addFlag(alice, 'work')
            database.addPassword(alice, 'a.com', 'me', 'pw-123456', ['work'])
        loginAs(client)
        html = client.get('/').data.decode()
        viewButton = html[html.index('data-bs-target="#viewPasswordModal"'):]
        viewButton = viewButton[:viewButton.index('>')]
        assert 'data-flags="work"' in viewButton


class TestTimezone:
    def test_lastUseUsesConfiguredTimezone(self, monkeypatch):
        import datetime, settings
        from zoneinfo import ZoneInfo
        monkeypatch.setattr(settings, 'TIMEZONE', 'America/Sao_Paulo')
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addPassword(alice, 'a.com', 'me', 'pw-123456', [])
            stored = datetime.datetime.strptime(Config.session.query(Passwords).first().lastUse, '%d/%m/%Y %H:%M:%S')
        expected = datetime.datetime.now(ZoneInfo('America/Sao_Paulo')).replace(tzinfo=None)
        assert abs((expected - stored).total_seconds()) < 60
