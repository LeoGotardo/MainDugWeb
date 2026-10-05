"""
Configuração da aplicação, lida do ambiente uma única vez.

Recusa iniciar quando falta alguma variável obrigatória e lista todas as ausentes,
em vez de cair em defaults inseguros. Ver `.env.example` na raiz.
"""
import os

from dotenv import load_dotenv

_srcDir = os.path.dirname(os.path.abspath(__file__))
_rootDir = os.path.dirname(_srcDir)

load_dotenv(os.path.join(_rootDir, '.env'))
load_dotenv(os.path.join(_srcDir, '.env'))


class ConfigError(RuntimeError):
    pass


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ('1', 'true', 'yes', 'on')


EXEC_MODE = os.getenv('EXEC_MODE', 'prod').strip().lower()
IS_DEV = EXEC_MODE == 'dev'
IS_PROD = not IS_DEV
DEBUG = _bool('DEBUG') and IS_DEV

# Chave das sessões do Flask (cookies). Trocar desloga todo mundo, nada mais.
SECRET_KEY = os.getenv('SECRET_KEY')

# Chave que cifra os dados no banco. Trocar torna os dados ilegíveis.
# `SecretKey` é o nome antigo, quando a mesma chave fazia os dois papéis: continua
# aceito aqui para que os dados já cifrados sigam legíveis.
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY') or os.getenv('SecretKey')

JWT_SECRET = os.getenv('JWT_SECRET')
JWT_EXPIRE_HOURS = int(os.getenv('JWT_EXPIRE_HOURS', '24'))

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL and IS_DEV:
    DATABASE_URL = 'sqlite:///' + os.path.join(_rootDir, 'instance', 'maindug.db')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

SITE_URL = os.getenv('SITE_URL', 'https://maindug.leogotardo.com.br')

# Proxies na frente da app que reescrevem X-Forwarded-For. No Vercel é 1.
TRUSTED_PROXY_HOPS = int(os.getenv('TRUSTED_PROXY_HOPS', '1' if os.getenv('VERCEL') else '0'))

RATE_LIMIT_STORAGE = os.getenv('RATE_LIMIT_STORAGE', 'memory://')


def _validate() -> None:
    missing = [name for name, value in (
        ('SECRET_KEY', SECRET_KEY),
        ('ENCRYPTION_KEY', ENCRYPTION_KEY),
        ('JWT_SECRET', JWT_SECRET),
        ('DATABASE_URL', DATABASE_URL),
    ) if not value]
    if missing:
        raise ConfigError(f'Variáveis de ambiente obrigatórias ausentes: {", ".join(missing)}')

    if SECRET_KEY == ENCRYPTION_KEY:
        raise ConfigError('SECRET_KEY e ENCRYPTION_KEY precisam ser diferentes')
    if JWT_SECRET in (SECRET_KEY, ENCRYPTION_KEY):
        raise ConfigError('JWT_SECRET precisa ser diferente de SECRET_KEY e ENCRYPTION_KEY')
    if EXEC_MODE not in ('dev', 'prod'):
        raise ConfigError(f'EXEC_MODE inválido: {EXEC_MODE!r} (use dev ou prod)')
    if IS_PROD and DATABASE_URL.startswith('sqlite'):
        raise ConfigError('SQLite não é permitido em produção: os dados se perdem a cada instância')


_validate()
