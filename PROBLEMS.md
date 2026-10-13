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

Validated on 2026-10-13: both copies loaded in Chrome for Testing 155, every API call replayed against the local Flask API on Postgres.
"main" = `src/extension/extension/` (April 2026); "prototype" = `extention/` (Dec 2025). `content.js` is identical in both.

### Blockers
9. **Main copy does not load.** Chrome rejects it: `Could not load icon 'icons/icon16.png' specified in 'icons'` (no `icons/` folder exists). With the icons pointed at `images/logo.svg` it loads, so this is the only load blocker.
10. **Main popup is disconnected from the server.** It keeps its own local accounts and passwords in `chrome.storage.local` and never calls `/api/auth/login`, so the `authToken` that `background.js` needs is never written: context menus, autofill and save always fail with "Faça login primeiro". The prototype popup does call the API.
11. **API contract mismatch** (replayed against `apiRoutes.py`):
    - prototype login sends `{email, password}`; the API requires `login` → 400.
    - `POST /auth/register`, `GET /passwords/export/csv`, `GET /health` → 404. `POST /passwords` (save) and `DELETE /passwords/<id>` → 405.
    - the extension reads `pwd.username` / `pwd.url`; the API returns `login` / `site` and has no URL field.
    - autofill calls `fillLoginForm(passwords[0])` with a list entry, but the list never includes the password (it is only returned by `/passwords/<id>/decrypt`), so autofill fills nothing.
12. **`contexts: ['password']` is not a valid context menu context** (observed in both copies). The call throws in the service worker, so only "Gerar senha segura" is created; "Salvar" and "Preencher" menus never exist.
13. **API URL defaults to `http://localhost:5000/api`** (main: `apiBaseUrl` in storage, never set by any UI; prototype: hard-coded).
14. **Notification icon missing** (`icon128.png` / `icons/icon128.png`): `chrome.notifications.create` fails, so no notification is ever shown. The "Notificações" setting is also never read.

### Security
15. **Lookalike-domain autofill.** Matching is by substring on both sides (server `query in site`, background `site.includes(hostname)`). Verified: a page on `bank.com` or `ank.com` is offered the `mybank.com` credential. Matching must be on the exact registrable domain/origin.
16. **The page can drive the injected UI.** The autofill/save prompts are plain DOM in the page, built with `innerHTML` from `document.title`, saved site names and usernames. The page can restyle them, read filled values or click "Preencher" itself (no `isTrusted` check). Use a closed shadow root or an extension-owned iframe, build with `textContent`, and only fill after a real user gesture.
17. **Main popup "encryption" is obfuscation.** AES-GCM is used, but the key is stored as JWK in `chrome.storage.local` next to the ciphertext and is not derived from the master password; every local account in the browser shares it. (The prototype has no local storage of passwords.)
18. **Browsing data sent to the server.** Every page with a password field sends its hostname to `/passwords?search=`, and the server decrypts the user's whole vault on each call. Cache the (non-secret) site list in the service worker instead.
19. **Account avatar leaks to a third party**: the main popup loads `ui-avatars.com/api/?name=<email>`.
20. **Plaintext CSV export** without quote escaping (a `"` in a field breaks the file; leading `=` allows CSV formula injection).

### Behaviour bugs
21. **Save never matches fill.** Save stores `site = document.title` (e.g. "Login - GitHub") while fill searches by hostname.
22. **Save prompt almost never appears.** `shouldOfferToSave()` compares `location.href` with itself; on a normal form login the page navigates away and the content script dies before the 2 s timer.
23. **Duplicate autofill requests/prompts**: `detectLoginForms`, the content `pageLoaded` round-trip and `tabs.onUpdated` each trigger `requestAutoFill`; prompts reuse the same element id.
24. **SPA detection via `history.pushState` override does not work**: it runs in the isolated world and never sees the page's calls (the MutationObserver fallback runs on every page of every site).
25. **Username field guess**: `findUsernameField` takes the first non-empty `input[type=text]` in the form (can be a search box).
26. Main popup: "Editar conta" button has no handler; `passwordDetected` listener is never triggered by anything; local password generation requires being logged in even though it does not use the server.

### Missing features (server side first)
27. API to create, update and delete credentials (`POST/PUT/DELETE /api/passwords`) and to register usage, which is what would finally fill the `Logs` table behind "Ver Logs" (#6).
28. A normalized site/origin field on credentials for exact matching (#15, #21). Adding a column needs migrations first (#1): `create_all()` does not alter existing tables.
29. Auto-lock (clear the token after inactivity / browser close) and re-auth before revealing or filling a password.
30. Configurable server URL defaulting to production, and a production `host_permissions` entry instead of `<all_urls>` for API calls.
31. Real icons (PNG 16/48/128), packaging for the Chrome Web Store / Firefox AMO.

### Extension cleanup
32. Keep one copy. The Node backends (`extention/server.js`, `src/extension/backend/server.js`, identical, own Postgres schema, `'your-secret-key'` JWT fallback) duplicate `/api` and should be deleted.

## Cleanup

33. `prototype.html` (1883 lines) at the repo root and `src/static/scripts/dropdown.js` (unused, contains Jinja syntax that is never rendered).
