import os, sys

# Ambiente de teste definido antes de qualquer import da app: settings.py valida no import.
os.environ.update({
    'EXEC_MODE': 'dev',
    'DEBUG': 'false',
    'SECRET_KEY': 'test-session-secret',
    'ENCRYPTION_KEY': 'test-encryption-key',
    'JWT_SECRET': 'test-jwt-secret-with-at-least-32-bytes',
    'DATABASE_URL': 'sqlite://',
    'RATE_LIMIT_STORAGE': 'memory://',
})
os.environ.pop('SecretKey', None)
os.environ.pop('VERCEL', None)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

import pytest

from app import app as flaskApp
from database import database, Config
from extensions import limiter


@pytest.fixture(autouse=True)
def cleanDb(monkeypatch):
    # Sem rede nos testes: a consulta à HIBP responde "não vazou".
    monkeypatch.setattr(type(database), 'checkPasswordPwned', lambda self, password: (False, 'offline'))
    flaskApp.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    limiter.enabled = False
    with flaskApp.app_context():
        Config.db.drop_all()
        Config.db.create_all()
    yield
    with flaskApp.app_context():
        Config.session.remove()


@pytest.fixture
def app():
    return flaskApp


@pytest.fixture
def client(app):
    return app.test_client()


def makeUser(login='alice', password='senha-forte-123', role='user'):
    with flaskApp.app_context():
        success, user = database.createUser(login=login, password=password, role=role)
        assert success is True, user
        return user.id


def loginAs(client, login='alice', password='senha-forte-123'):
    return client.post('/login/', data={'login': login, 'password': password})
