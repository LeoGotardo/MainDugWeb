# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project

MainDug — password vault. Python · Flask · Flask-Login · SQLAlchemy · PostgreSQL (Neon) · Fernet + Argon2 · JWT for the browser-extension API. Deployed on Vercel, which auto-detects Flask and serves `src/app.py` directly (no `vercel.json`: a catch-all rewrite would hand Flask the rewritten path and 404 every route).

## Commands

```bash
cp .env.example .env                                   # fill in the three secrets
./venv/bin/python src/app.py                           # serve on :5000 (EXEC_MODE=dev uses SQLite in instance/)
./venv/bin/python -m pytest                            # in-memory SQLite, no network
# Same suite against real Postgres (stricter types than SQLite; run before deploying DB changes):
docker run -d --rm --name maindug-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=maindug_test -p 127.0.0.1:55432:5432 postgres:16-alpine
TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:55432/maindug_test ./venv/bin/python -m pytest
./venv/bin/python scripts/createAdmin.py               # first sysadmin (BOOTSTRAP_ADMIN_*)
./venv/bin/python scripts/migrateLookupHashes.py       # one-off, see "Lookup hashes"
node --test tests/extension/                           # extension unit tests (e2e: see README)
```

## Layout

- `src/settings.py` — reads the environment once and refuses to boot when something required is missing. Never call `os.getenv` elsewhere.
- `src/database.py` — Flask app + SQLAlchemy models + the `Database` class, exposed as the singleton `database`. Do not instantiate `Database()` again (it runs `create_all`).
- `src/app.py` — web routes (session auth, CSRF-protected). `src/apiRoutes.py` — JSON API for the extension (JWT, CSRF-exempt), mounted at `/api`.
- `src/extensions.py` — shared `csrf` and `limiter`.
- `src/extension/maindug/` — Chrome MV3 extension (load unpacked). `lib/` holds ES modules shared by the service worker and the popup; `content.js` is a classic script and must stay self-contained.

## Conventions

- `camelCase` for variables, functions and file names; `PascalCase` for classes.
- `Database` methods return `(True, value)`, `(False, userMessage)` or `(-1, internalError)`. `-1` is truthy: always check with `is True` / `is False`, never `if success:` / `if not success:`.
- IDs from forms/URLs are strings: pass them through `_toIntId()` before filtering an integer column. psycopg 3 sends typed parameters and Postgres rejects `integer = varchar` (SQLite silently accepts it).
- Every query for a credential, flag or log filters by the owner (`userId=current_user.id`). A record owned by someone else is "not found", never "forbidden".
- Every POST form carries `{{ csrf_token() }}`; `static/scripts/csrf.js` adds `X-CSRFToken` to same-origin `fetch` calls.

## Extension rules

- **The service worker decides.** Domain matching uses `sender.url` of the content-script message (never data sent by the page), and a password leaves the worker only for a fill on a matching domain. Matching is exact host or dot-boundary subdomain (`lib/domain.js`); never go back to substring matching.
- Token, credential index and pending saves live only in `chrome.storage.session` (memory, wiped on browser close and on idle/lock). Workers are suspended at any time: no state in module variables. Don't change the session storage access level (content scripts must not read it).
- Page UI goes in the closed shadow root built with `textContent`; buttons act only on `event.isTrusted` clicks.
- Auto-lock is client-side and based on system idle/screen lock (`chrome.idle`), not on vault usage; a JWT stays valid on the server until `JWT_EXPIRE_HOURS`.
- No fill/save offers on the vault's own site (`isVaultPage` in `background.js`): its credential forms and the master-password login must never be captured.
- Commands: `node --test tests/extension/` and `CHROME_PATH=… node tests/extension/e2e.mjs` (Chrome for Testing; branded Chrome ignores `--load-extension`).

## Encryption

- `ENCRYPTION_KEY` encrypts every stored field (Fernet key = sha256 of it). Changing it makes existing data unreadable. `SecretKey` is the legacy name and is still accepted.
- `SECRET_KEY` only signs Flask sessions. `JWT_SECRET` only signs API tokens. All three must differ (enforced at boot).
- Encrypted columns are declared with `encryptedProperty('_col', '_col_hash')`. SQL cannot filter or sort on them: search/sort happens in Python after decrypting (fine at per-user scale).

## Lookup hashes

`*_hash` columns hold `lookupHash(value)` (HMAC-SHA256 keyed from `ENCRYPTION_KEY`). Older rows hold plain `sha256(value)`; run `scripts/migrateLookupHashes.py` once per existing database or those users cannot log in.

## Schema

Table and column names are obfuscated (`tbl_0`, `col_a0`, …) and kept for compatibility with existing data. There are no migrations yet: `create_all()` runs once per process and never alters existing tables.
