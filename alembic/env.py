"""
Ambiente do Alembic.

Não importa `settings` nem `database` para aplicar migrações: o job de produção (GitHub Actions)
só tem a URL do banco, não as chaves da aplicação. Os modelos são carregados apenas em
`alembic revision --autogenerate`, que roda localmente com o ambiente de desenvolvimento.
"""
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from databaseUrl import normalizeDatabaseUrl

config = context.config
if config.config_file_name is not None and not config.attributes.get('connection'):
    fileConfig(config.config_file_name)


def databaseUrl() -> str:
    # DDL não passa pelo pooler do Neon: migrações usam a URL direta quando existir.
    url = normalizeDatabaseUrl(os.getenv('DATABASE_URL_UNPOOLED') or os.getenv('DATABASE_URL'))
    if not url:
        raise SystemExit('Defina DATABASE_URL_UNPOOLED ou DATABASE_URL para rodar as migrações.')
    return url


def targetMetadata():
    if getattr(config.cmd_opts, 'autogenerate', False):
        from database import Config  # importa a app: exige o .env de desenvolvimento
        return Config.db.metadata
    return None


def runMigrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=targetMetadata(),
        render_as_batch=connection.dialect.name == 'sqlite',  # ALTER TABLE no SQLite exige recriar a tabela
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    context.configure(url=databaseUrl(), target_metadata=targetMetadata(), literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
elif config.attributes.get('connection') is not None:
    # Conexão fornecida por quem chamou (scripts/migrate.py e testes).
    runMigrations(config.attributes['connection'])
else:
    engine = create_engine(databaseUrl(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        runMigrations(connection)
