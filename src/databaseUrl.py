"""Normalização da URL do banco. Sem efeitos colaterais: usado pela app (settings.py) e pelas migrações."""


def normalizeDatabaseUrl(url: str | None) -> str | None:
    """Força o driver psycopg (v3) em qualquer URL Postgres: `postgres://`, `postgresql://` ou `postgresql+<driver>://`."""
    if not url:
        return url
    scheme, sep, rest = url.partition('://')
    if sep and (scheme in ('postgres', 'postgresql') or scheme.startswith('postgresql+')):
        return f'postgresql+psycopg://{rest}'
    return url
