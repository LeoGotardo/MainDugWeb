# Known problems

Open items only. Fixed items (default sysadmin, IDOR on edit, shared session/encryption key,
CSRF, login rate limit, wrong `jwt` package, `to_dict`, per-request `Database()`, broken
pagination/search/flags, error-page tracebacks, request timeouts, …) are covered by `tests/`.

## Architecture (vs. the hookahsys-back standard)

1. **Migrations are new.** Alembic baseline (`0001`) plus one real migration (`0002`, credential domain); the production path (stamp, then upgrade) has only been rehearsed locally.
2. **No layering.** `database.py` mixes the Flask app, models and business logic; `app.py` routes call it directly. Target: `routes → services → repositories → models`.
3. **Tuple returns instead of exceptions.** `(True|False|-1, value)` everywhere. Replace with domain exceptions plus one error handler.
4. **Obfuscated schema names** (`tbl_0`, `col_a0`). They add no security and make every query harder to read; renaming is now a migration away.
5. **Rate limit is per instance** (`memory://`). On Vercel each instance has its own counter. Point `RATE_LIMIT_STORAGE` at a Redis for a global limit.

## Features

6. **Usage is logged only by the extension.** `Logs` rows are written when the extension fills a credential (`POST /api/passwords/<id>/use`); viewing or copying a password on the website is not logged.
7. **Password recovery** is not implemented (no email sending); the page says so.
8. **API logout does not revoke tokens.** JWTs stay valid until they expire (`JWT_EXPIRE_HOURS`, default 12 h). The extension's auto-lock only drops its own copy of the token.

## Browser extension

The extension (`src/extension/maindug/`) was rebuilt on 2026-10-13: API login, in-memory session with auto-lock, exact-domain fill, isolated page UI, save/update after login, usage logging. Covered by `tests/extension/` (unit + Chrome and Firefox e2e). Open items:

9. **Not covered by the e2e tests** (check by hand after changes): context-menu and `Ctrl+Shift+G` actions, the server-URL change with its permission prompt, auto-lock (`idle`), and the production `host_permissions` path (tests patch the manifest to allow 127.0.0.1). In Chrome the popup UI is driven directly but its "Preencher" button is not (no other active tab); in Firefox the popup UI itself is not driven (WebDriver cannot see extension pages), only its code path through a test page.
10. **Older credentials named like "GitHub" have no domain** until someone edits them and fills **Domínio** (the migration cannot derive it: `site` is encrypted and the CI job has no key). Credentials whose site is already an address keep working.
11. **Top frame only** (`all_frames: false`): login forms inside iframes are not detected.
12. **Firefox needs signing for a permanent install** (Firefox 142+ is supported from the same folder). `npm run sign:firefox` with the owner's addons.mozilla.org API keys produces the `.xpi`; until then it loads only as a temporary add-on.
13. **Not published**: no Chrome Web Store listing; Chrome users load it unpacked.
14. Copied passwords stay in the clipboard (no automatic clearing).
15. On `http://` pages the fill is offered with a warning rather than blocked.
