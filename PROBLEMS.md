# Known problems

Open items only. Fixed items (default sysadmin, IDOR on edit, shared session/encryption key,
CSRF, login rate limit, wrong `jwt` package, `to_dict`, per-request `Database()`, broken
pagination/search/flags, error-page tracebacks, request timeouts, …) are covered by `tests/`.

## Architecture (vs. the hookahsys-back standard)

1. **No migrations.** `create_all()` creates missing tables but never alters existing ones. Adopt Alembic before the next schema change.
2. **No layering.** `database.py` mixes the Flask app, models and business logic; `app.py` routes call it directly. Target: `routes → services → repositories → models`.
3. **Tuple returns instead of exceptions.** `(True|False|-1, value)` everywhere. Replace with domain exceptions plus one error handler.
4. **Obfuscated schema names** (`tbl_0`, `col_a0`). They add no security and make every query harder to read; renaming needs a migration.
5. **Rate limit is per instance** (`memory://`). On Vercel each instance has its own counter. Point `RATE_LIMIT_STORAGE` at a Redis for a global limit.

## Features

6. **`Logs` is never written.** `/moreInfo` always shows an empty history: nothing records credential usage.
7. **Password recovery** is not implemented (no email sending); the page says so.
8. **API logout does not revoke tokens.** JWTs stay valid until they expire (`JWT_EXPIRE_HOURS`).

## Browser extension

9. **Two copies**: `extention/` and `src/extension/extension/` (only `background.js` differs) plus two identical Node backends (`server.js`, 1333 lines) with their own Postgres schema and a `'your-secret-key'` JWT fallback. Pick one extension, delete the other, and drop the Node backend in favour of `/api`.
10. **API URL hard-coded to `http://localhost:5000/api`** in `background.js` / `cconfig.js`.
11. **`popup.js` does not use the API**: it stores credentials in `chrome.storage.local`, "encrypted" with `btoa` and the local master password hashed with unsalted SHA-256.
12. **MV3 service worker uses `setInterval`** (token check, no-op "backup"), which stops when the worker is suspended.

## Cleanup

13. `prototype.html` (1883 lines) at the repo root and `src/static/scripts/dropdown.js` (unused, contains Jinja syntax that is never rendered).
