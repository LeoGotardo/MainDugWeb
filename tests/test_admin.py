"""Painel do administrador: estatísticas, editar e excluir usuários."""
from app import app as flaskApp
from database import database, Config, User, Passwords
from tests.conftest import makeUser, loginAs


def getUser(userId):
    with flaskApp.app_context():
        return Config.session.get(User, userId)


class TestDashboard:
    def test_cardsShowSystemWideNumbers(self, client):
        makeUser('root', role='sysadmin')
        alice = makeUser('alice')
        makeUser('bob')
        with flaskApp.app_context():
            database.addPassword(alice, 'a.com', 'me', 'pw-1', [])
            database.addPassword(alice, 'b.com', 'me', 'pw-2', [])
        loginAs(client, 'root')

        html = client.get('/').data.decode()
        cards = html[html.index('Dashboard do Administrador'):html.index('Gerenciamento de Usuários')]
        values = [chunk.split('</div>')[0].strip() for chunk in cards.split('class="stat-value')[1:]]
        assert [v.split('>')[-1] for v in values] == ['3', '2', '0']

    def test_userListShowsCredentialCount(self, client):
        makeUser('root', role='sysadmin')
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addPassword(alice, 'a.com', 'me', 'pw-1', [])
        with flaskApp.app_context():
            ok, users = database.getUsers()
        assert ok is True
        assert {u['login']: u['passwordCount'] for u in users} == {'root': 0, 'alice': 1}


class TestUpdateUser:
    def test_adminDisablesUserWhoLosesSessionImmediately(self, client, app):
        makeUser('root', role='sysadmin')
        alice = makeUser('alice')
        aliceClient = app.test_client()
        loginAs(aliceClient)
        assert aliceClient.get('/stats/').status_code == 200

        loginAs(client, 'root')
        client.post(f'/admin/users/{alice}/update', data={'role': 'user'})  # sem "enabled" = desativar
        assert getUser(alice).enabled is False
        assert aliceClient.get('/stats/').status_code == 302  # sessão aberta deixou de valer

    def test_adminPromotesUser(self, client):
        makeUser('root', role='sysadmin')
        alice = makeUser('alice')
        loginAs(client, 'root')
        client.post(f'/admin/users/{alice}/update', data={'role': 'sysadmin', 'enabled': 'on'})
        assert getUser(alice).role == 'sysadmin'

    def test_adminCannotDisableOrDemoteSelf(self, client):
        root = makeUser('root', role='sysadmin')
        loginAs(client, 'root')
        client.post(f'/admin/users/{root}/update', data={'role': 'user', 'enabled': 'on'})
        client.post(f'/admin/users/{root}/update', data={'role': 'sysadmin'})
        user = getUser(root)
        assert (user.role, user.enabled) == ('sysadmin', True)

    def test_invalidRoleIsRejected(self, client):
        makeUser('root', role='sysadmin')
        alice = makeUser('alice')
        loginAs(client, 'root')
        client.post(f'/admin/users/{alice}/update', data={'role': 'super', 'enabled': 'on'})
        assert getUser(alice).role == 'user'

    def test_lastActiveAdminIsProtected(self, client):
        root = makeUser('root', role='sysadmin')
        other = makeUser('other', role='sysadmin')
        loginAs(client, 'root')
        client.post(f'/admin/users/{other}/update', data={'role': 'user', 'enabled': 'on'})
        assert getUser(other).role == 'user'
        # root agora é o único admin ativo: o banco também recusa deixá-lo sem admin
        with flaskApp.app_context():
            ok, msg = database.adminUpdateUser(adminId=other, targetId=root, role='user', enabled=True)
        assert ok is False and getUser(root).role == 'sysadmin'


class TestDeleteUser:
    def test_adminDeletesUserAndCredentials(self, client):
        makeUser('root', role='sysadmin')
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addFlag(alice, 'work')
            database.addPassword(alice, 'a.com', 'me', 'pw-1', ['work'])
        loginAs(client, 'root')
        client.post(f'/admin/users/{alice}/delete')
        assert getUser(alice) is None
        with flaskApp.app_context():
            assert Config.session.query(Passwords).count() == 0

    def test_adminCannotDeleteSelf(self, client):
        root = makeUser('root', role='sysadmin')
        loginAs(client, 'root')
        client.post(f'/admin/users/{root}/delete')
        assert getUser(root) is not None


class TestAccessControl:
    def test_regularUserCannotUseAdminRoutes(self, client):
        alice = makeUser('alice')
        bob = makeUser('bob')
        loginAs(client)
        client.post(f'/admin/users/{bob}/update', data={'role': 'sysadmin', 'enabled': 'on'})
        client.post(f'/admin/users/{bob}/delete')
        assert getUser(bob) is not None and getUser(bob).role == 'user'
        client.post(f'/admin/users/{alice}/update', data={'role': 'sysadmin', 'enabled': 'on'})
        assert getUser(alice).role == 'user'

    def test_anonymousIsRedirectedToLogin(self, client):
        bob = makeUser('bob')
        resp = client.post(f'/admin/users/{bob}/delete')
        assert resp.status_code == 302 and '/login/' in resp.headers['Location']
        assert getUser(bob) is not None
