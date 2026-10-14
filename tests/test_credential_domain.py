"""Domínio da credencial (preenchimento automático): normalização, site, API e páginas de edição."""
import json
import os

import pytest

from app import app as flaskApp
from database import database, Config, Passwords, normalizeDomain, INVALID_DOMAIN_MESSAGE
from tests.conftest import makeUser, loginAs
from tests.test_api_extension import apiLogin

CASES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extension', 'domainCases.json')


def credentials(userId):
    with flaskApp.app_context():
        return {c.site: c for c in Config.session.query(Passwords).filter(Passwords.userId == userId).all()}


def editButton(html):
    """Atributos do primeiro botão que abre o modal de edição."""
    start = html.index('data-bs-target="#editPasswordModal"')
    return html[start:html.index('>', start)]


@pytest.mark.parametrize('value, expected', json.load(open(CASES_PATH))['normalize'])
def test_normalizeDomainAgreesWithExtension(value, expected):
    # Mesmos casos de tests/extension/domain.test.mjs: o servidor grava o que a extensão vai comparar.
    assert normalizeDomain(value) == expected


class TestWebForm:
    def add(self, client, site, domain=None):
        data = {'site': site, 'login': 'me', 'password': 'pw-123456'}
        if domain is not None:
            data['domain'] = domain
        return client.post('/addPassword', data=data, follow_redirects=True)

    def test_namedSiteWithDomain(self, client):
        alice = makeUser('alice')
        loginAs(client)
        self.add(client, 'GitHub', 'https://www.GitHub.com/login')
        assert credentials(alice)['GitHub'].domain == 'github.com'

    def test_blankDomainIsDerivedFromSite(self, client):
        alice = makeUser('alice')
        loginAs(client)
        self.add(client, 'https://gitlab.com/users/sign_in', '')
        self.add(client, 'Wi-Fi de casa', '')
        saved = credentials(alice)
        assert saved['https://gitlab.com/users/sign_in'].domain == 'gitlab.com'
        assert saved['Wi-Fi de casa'].domain is None

    def test_invalidDomainIsRejected(self, client):
        alice = makeUser('alice')
        loginAs(client)
        resp = self.add(client, 'GitHub', 'GitHub')
        assert INVALID_DOMAIN_MESSAGE in resp.data.decode()
        assert credentials(alice) == {}

    def test_editChangesKeepsOrDerivesDomain(self, client):
        alice = makeUser('alice')
        loginAs(client)
        self.add(client, 'GitHub', 'github.com')
        credId = credentials(alice)['GitHub'].id
        edit = {'password_id': str(credId), 'login': 'me', 'password': ''}

        client.post('/editPassword', data={**edit, 'site': 'GitHub', 'domain': 'gist.github.com'})
        assert credentials(alice)['GitHub'].domain == 'gist.github.com'
        # Formulário sem o campo (página aberta antes do deploy): mantém.
        client.post('/editPassword', data={**edit, 'site': 'GitHub'})
        assert credentials(alice)['GitHub'].domain == 'gist.github.com'
        # Em branco: deduz do site (aqui, um nome: fica sem domínio).
        client.post('/editPassword', data={**edit, 'site': 'GitHub', 'domain': ''})
        assert credentials(alice)['GitHub'].domain is None
        # Inválido: recusa sem alterar nada.
        client.post('/editPassword', data={**edit, 'site': 'Outro nome', 'domain': 'não é domínio'})
        assert 'GitHub' in credentials(alice)

    def test_dashboardShowsDomainAndEditButtonCarriesIt(self, client):
        alice = makeUser('alice')
        loginAs(client)
        self.add(client, 'GitHub', 'github.com')
        html = client.get('/').data.decode()
        assert 'data-domain="github.com"' in editButton(html)
        assert '<small class="text-muted">github.com</small>' in html
        # Busca também pelo domínio.
        assert 'GitHub' in client.get('/?query=github.com').data.decode()


class TestStatsPage:
    def test_editFromStatsKeepsDomainAndFlags(self, client):
        # Antes, os botões "Alterar" das estatísticas não levavam as flags e o modal não tinha
        # opções nessa página: salvar a edição apagava as flags (e apagaria o domínio).
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addFlag(alice, 'work')
            database.addPassword(alice, 'GitHub', 'me', 'curta', ['work'], domain='github.com')  # senha fraca: aparece nas estatísticas
        loginAs(client)
        html = client.get('/stats/').data.decode()
        button = editButton(html)
        assert 'data-domain="github.com"' in button and 'data-flags="work"' in button
        assert '<option value="work">work</option>' in html


class TestApi:
    def test_createWithDomainAndConflictByDomain(self, client):
        alice = makeUser('alice')
        headers = apiLogin(client)
        created = client.post('/api/passwords', headers=headers, json={'site': 'Meu Banco', 'domain': 'mybank.com', 'login': 'me', 'password': 'pw-1'})
        assert created.status_code == 201
        listed = client.get('/api/passwords', headers=headers).get_json()
        assert [(item['site'], item['domain']) for item in listed] == [('Meu Banco', 'mybank.com')]

        # A extensão salva com site = domínio da página: é a mesma credencial ("Atualizar", não duplicar).
        again = client.post('/api/passwords', headers=headers, json={'site': 'mybank.com', 'login': 'me', 'password': 'pw-2'})
        assert again.status_code == 409 and again.get_json()['id'] == created.get_json()['id']
        assert len(credentials(alice)) == 1

    def test_invalidDomainIs400(self, client):
        makeUser('alice')
        headers = apiLogin(client)
        resp = client.post('/api/passwords', headers=headers, json={'site': 'x', 'domain': 'não é domínio', 'login': 'me', 'password': 'pw'})
        assert resp.status_code == 400 and resp.get_json()['error'] == INVALID_DOMAIN_MESSAGE

    def test_updateKeepsDomainUnlessSent(self, client):
        alice = makeUser('alice')
        headers = apiLogin(client)
        credId = client.post('/api/passwords', headers=headers, json={'site': 'Meu Banco', 'domain': 'mybank.com', 'login': 'me', 'password': 'pw-1'}).get_json()['id']

        assert client.put(f'/api/passwords/{credId}', headers=headers, json={'password': 'pw-2'}).status_code == 200
        assert credentials(alice)['Meu Banco'].domain == 'mybank.com'
        assert client.put(f'/api/passwords/{credId}', headers=headers, json={'password': 'pw-3', 'domain': 'novobanco.com'}).status_code == 200
        assert credentials(alice)['Meu Banco'].domain == 'novobanco.com'
        assert client.put(f'/api/passwords/{credId}', headers=headers, json={'password': 'pw-4', 'domain': 'x'}).status_code == 400

    def test_legacyCredentialHasNullDomainAndStillConflicts(self, client):
        # Credenciais anteriores à coluna ficam com domain NULL; a extensão usa o site no lugar.
        alice = makeUser('alice')
        with flaskApp.app_context():
            database.addPassword(alice, 'https://www.github.com/login', 'me', 'pw-123456', [])
            credential = Config.session.query(Passwords).one()
            credential.domain = None
            Config.session.commit()
        headers = apiLogin(client)
        listed = client.get('/api/passwords', headers=headers).get_json()
        assert listed[0]['domain'] is None
        assert client.post('/api/passwords', headers=headers, json={'site': 'github.com', 'login': 'me', 'password': 'pw'}).status_code == 409
