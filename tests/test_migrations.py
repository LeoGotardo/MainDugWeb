"""Migrações (Alembic + scripts/migrate.py): o schema que elas criam é exatamente o dos modelos."""
import os
import sys

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import MetaData, create_engine, inspect, pool, text

from database import Config

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))
import migrate as migrateScript  # noqa: E402


def dropEverything(url):
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.begin() as connection:
        metadata = MetaData()
        metadata.reflect(connection)
        metadata.drop_all(connection)


def schemaDiff(url):
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={'compare_type': True})
        return compare_metadata(context, Config.db.metadata)


@pytest.fixture
def sqliteUrl(tmp_path):
    return f'sqlite:///{tmp_path / "migrations.db"}'


@pytest.fixture
def emptyDatabases(sqliteUrl):
    """Banco SQLite novo e, se TEST_DATABASE_URL estiver definido, o Postgres de teste esvaziado."""
    urls = [sqliteUrl]
    postgres = os.getenv('TEST_DATABASE_URL')
    if postgres:
        postgres = migrateScript.normalizeDatabaseUrl(postgres)
        dropEverything(postgres)
        urls.append(postgres)
    yield urls
    if postgres:
        dropEverything(postgres)  # o fixture cleanDb recria as tabelas para o próximo teste


def test_migrationsCreateExactlyTheModelSchema(emptyDatabases):
    for url in emptyDatabases:
        assert migrateScript.migrate(url) == 'created'
        assert schemaDiff(url) == [], url


def test_migrateIsIdempotent(sqliteUrl):
    assert migrateScript.migrate(sqliteUrl) == 'created'
    assert migrateScript.migrate(sqliteUrl) == 'upgraded'


def test_legacyDatabaseIsStampedNotRecreated(sqliteUrl):
    engine = create_engine(sqliteUrl)
    Config.db.metadata.create_all(engine)  # como o boot fazia antes do Alembic
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO tbl_3 (col_d0, col_d1, col_d2) VALUES (1, 'work', 'someone')"))

    assert migrateScript.migrate(sqliteUrl) == 'stamped'
    with engine.connect() as connection:
        assert connection.execute(text('SELECT version_num FROM alembic_version')).scalar() == migrateScript.BASELINE_REVISION
        assert connection.execute(text('SELECT col_d1 FROM tbl_3')).scalar() == 'work'  # dados preservados
    assert migrateScript.migrate(sqliteUrl) == 'upgraded'


def test_divergentLegacySchemaIsRefusedAndLeftUntouched(sqliteUrl):
    engine = create_engine(sqliteUrl)
    Config.db.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE tbl_1 DROP COLUMN col_b7'))

    with pytest.raises(SystemExit, match='tbl_1.col_b7'):
        migrateScript.migrate(sqliteUrl)
    assert 'alembic_version' not in inspect(engine).get_table_names()
