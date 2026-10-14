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

6. **Usage is logged only by the extension.** `Logs` rows are written when the extension fills a credential (`POST /api/passwords/<id>/use`); viewing or copying a password on the website is not logged.
7. **Password recovery** is not implemented (no email sending); the page says so.
8. **API logout does not revoke tokens.** JWTs stay valid until they expire (`JWT_EXPIRE_HOURS`, default 12 h). The extension's auto-lock only drops its own copy of the token.

## Browser extension

The extension (`src/extension/maindug/`) was rebuilt on 2026-10-13: API login, in-memory session with auto-lock, exact-domain fill, isolated page UI, save/update after login, usage logging. Covered by `tests/extension/` (unit + 9-scenario Chrome e2e). Open items:

9. **Not covered by the e2e test** (check by hand after changes): the popup's "Preencher" button (the test opens the popup as a tab, so there is no other active tab), context-menu and `Ctrl+Shift+G` actions, the server-URL change with its permission prompt, auto-lock (`chrome.idle`), and the production `host_permissions` path (the test patches the manifest to allow 127.0.0.1).
10. **Sites saved as names never autofill.** A credential whose site is "GitHub" instead of `github.com` is listed but never matched. A normalized origin column (needs migrations, #1) would let the website store and validate domains.
11. **Top frame only** (`all_frames: false`): login forms inside iframes are not detected.
12. **Firefox is not supported**: its MV3 has no `background.service_worker` (needs `background.scripts` and a separate manifest).
13. **Not published**: no Chrome Web Store listing; users load it unpacked.
14. Copied passwords stay in the clipboard (no automatic clearing).
15. On `http://` pages the fill is offered with a warning rather than blocked.
