"""
Aplica as migrações do Alembic. É o que roda em produção (GitHub Actions, a cada push no main)
e localmente antes de subir a app.

Só precisa de DATABASE_URL_UNPOOLED ou DATABASE_URL (não importa a app nem exige as chaves dela).

Três situações:
- banco vazio: cria tudo (`upgrade head`);
- banco criado antes do Alembic (tem as tabelas, mas não `alembic_version`): confere que o schema
  bate com a migração inicial e só então carimba (`stamp`) nela; depois aplica o que vier depois;
- banco já versionado: `upgrade head` (não faz nada se já estiver em dia).

    ./venv/bin/python scripts/migrate.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, inspect, pool

from databaseUrl import normalizeDatabaseUrl

BASELINE_REVISION = '0001'
VERSION_TABLE = 'alembic_version'


def alembicConfig(connection=None) -> AlembicConfig:
    config = AlembicConfig(os.path.join(ROOT, 'alembic.ini'))
    if connection is not None:
        config.attributes['connection'] = connection
    return config


def schemaOf(connection) -> dict[str, set[str]]:
    inspector = inspect(connection)
    return {table: {column['name'] for column in inspector.get_columns(table)}
            for table in inspector.get_table_names() if table != VERSION_TABLE}


def baselineSchema() -> dict[str, set[str]]:
    """Schema esperado de um banco pré-Alembic: a migração inicial aplicada num SQLite em memória."""
    engine = create_engine('sqlite://', poolclass=pool.StaticPool)
    with engine.begin() as connection:
        command.upgrade(alembicConfig(connection), BASELINE_REVISION)
        return schemaOf(connection)


def schemaProblems(actual: dict[str, set[str]], expected: dict[str, set[str]]) -> list[str]:
    problems = [f'tabela ausente: {table}' for table in sorted(expected.keys() - actual.keys())]
    for table in sorted(expected.keys() & actual.keys()):
        problems += [f'coluna ausente: {table}.{column}' for column in sorted(expected[table] - actual[table])]
    return problems


def migrate(url: str) -> str:
    """Aplica as migrações em `url` e devolve o que foi feito: 'created', 'stamped' ou 'upgraded'."""
    engine = create_engine(normalizeDatabaseUrl(url), poolclass=pool.NullPool)
    with engine.begin() as connection:
        tables = set(inspect(connection).get_table_names())
        config = alembicConfig(connection)

        if VERSION_TABLE not in tables and 'tbl_0' in tables:
            problems = schemaProblems(schemaOf(connection), baselineSchema())
            if problems:
                raise SystemExit('Banco existente não bate com a migração inicial; nada foi alterado:\n  ' + '\n  '.join(problems))
            command.stamp(config, BASELINE_REVISION)
            command.upgrade(config, 'head')
            return 'stamped'

        command.upgrade(config, 'head')
        return 'created' if not tables else 'upgraded'


def main() -> int:
    url = os.getenv('DATABASE_URL_UNPOOLED') or os.getenv('DATABASE_URL')
    if not url:
        print('Defina DATABASE_URL_UNPOOLED (ou DATABASE_URL) com a URL direta do banco.', file=sys.stderr)
        return 1
    result = migrate(url)
    messages = {
        'created': 'Banco vazio: schema criado pelas migrações.',
        'stamped': f'Banco existente conferido e carimbado na migração inicial ({BASELINE_REVISION}); migrações seguintes aplicadas.',
        'upgraded': 'Migrações em dia.',
    }
    print(messages[result])
    return 0


if __name__ == '__main__':
    sys.exit(main())
