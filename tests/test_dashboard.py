from app import app as flaskApp
from database import database, Config, Passwords, buildPagination
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
