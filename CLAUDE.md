# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project

MainDug — password vault. Python · Flask · Flask-Login · SQLAlchemy · PostgreSQL (Neon) · Fernet + Argon2 · JWT for the browser-extension API. Deployed on Vercel (`api/wsgi.py` → `src/app.py`).

## Commands

```bash
cp .env.example .env                                   # fill in the three secrets
./venv/bin/python src/app.py                           # serve on :5000 (EXEC_MODE=dev uses SQLite in instance/)
./venv/bin/python -m pytest                            # in-memory SQLite, no network
./venv/bin/python scripts/createAdmin.py               # first sysadmin (BOOTSTRAP_ADMIN_*)
./venv/bin/python scripts/migrateLookupHashes.py       # one-off, see "Lookup hashes"
```

## Layout

- `src/settings.py` — reads the environment once and refuses to boot when something required is missing. Never call `os.getenv` elsewhere.
- `src/database.py` — Flask app + SQLAlchemy models + the `Database` class, exposed as the singleton `database`. Do not instantiate `Database()` again (it runs `create_all`).
- `src/app.py` — web routes (session auth, CSRF-protected). `src/apiRoutes.py` — JSON API for the extension (JWT, CSRF-exempt), mounted at `/api`.
- `src/extensions.py` — shared `csrf` and `limiter`.
- `extention/` (prototype) and `src/extension/` — two copies of the browser extension; they are not wired to the Flask API yet (see PROBLEMS.md).

## Conventions

- `camelCase` for variables, functions and file names; `PascalCase` for classes.
- `Database` methods return `(True, value)`, `(False, userMessage)` or `(-1, internalError)`. `-1` is truthy: always check with `is True` / `is False`, never `if success:` / `if not success:`.
- Every query for a credential, flag or log filters by the owner (`userId=current_user.id`). A record owned by someone else is "not found", never "forbidden".
- Every POST form carries `{{ csrf_token() }}`; `static/scripts/csrf.js` adds `X-CSRFToken` to same-origin `fetch` calls.

## Encryption

- `ENCRYPTION_KEY` encrypts every stored field (Fernet key = sha256 of it). Changing it makes existing data unreadable. `SecretKey` is the legacy name and is still accepted.
- `SECRET_KEY` only signs Flask sessions. `JWT_SECRET` only signs API tokens. All three must differ (enforced at boot).
- Encrypted columns are declared with `encryptedProperty('_col', '_col_hash')`. SQL cannot filter or sort on them: search/sort happens in Python after decrypting (fine at per-user scale).

## Lookup hashes

`*_hash` columns hold `lookupHash(value)` (HMAC-SHA256 keyed from `ENCRYPTION_KEY`). Older rows hold plain `sha256(value)`; run `scripts/migrateLookupHashes.py` once per existing database or those users cannot log in.

## Schema

Table and column names are obfuscated (`tbl_0`, `col_a0`, …) and kept for compatibility with existing data. There are no migrations yet: `create_all()` runs once per process and never alters existing tables.
