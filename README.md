# MainDug

MainDug is an open-source password manager built as a final-year Computer Science project (TCC) at Instituto Federal do Paraná. It focuses on **transparency, privacy, flexibility, and security**: instead of locking users into a proprietary vault, MainDug lets you self-host the webservice, plug in your own database, and adapt the encryption layer to your needs.

The system is made up of two parts:
- **Webservice** — a Flask + PostgreSQL application for managing credentials, viewing security stats (repeated/leaked passwords), and administering users.
- **Browser extension** — captures logins, offers autocomplete, and reports usage back to the webservice.

Full project documentation (in Portuguese), including requirements, threat model, and diagrams, is in [`docs/tex/main.tex`](docs/tex/main.tex) (compiled PDF: [`docs/tex/main.pdf`](docs/tex/main.pdf)).

## Features

- Login / registration with password recovery via e-mail
- Secure password generation and complexity checks
- Detection of reused and leaked (pwned) credentials
- Credential search/filtering and access logs
- Admin panel: manage users, ban accounts, view usage statistics
- Browser extension for autocomplete and login capture

See the functional/non-functional requirements tables in the TCC document (`docs/tex/main.tex`, section *Resultados*) for the full list.

## Security model

- **Master password** is hashed one-way (bcrypt/Argon2-style), never stored or recoverable.
- **Vault credentials** are encrypted both-ways, with the decryption key derived from the user's master password — a zero-knowledge design where the database alone is not enough to read stored credentials.
- **Database "mimicry"**: table and column names are obfuscated (see the `col_a0`, `tbl_0`-style naming in `src/database.py`) so raw DB access doesn't reveal the schema.

See [`docs/tex/main.tex`](docs/tex/main.tex) (*Estratégias de segurança*) for details.

## Tech stack

- **Backend:** Python, Flask, Flask-Login, Flask-SQLAlchemy, Flask-Admin
- **Database:** PostgreSQL (SQLite fallback for local dev)
- **Crypto:** `cryptography`, `argon2-cffi`, JWT (for the API)
- **Extension:** JavaScript (Manifest V3, Chrome), talking to the Flask `/api`

## Project structure

```
src/
  app.py            # Flask app, web routes (Vercel entry point)
  apiRoutes.py       # JWT-protected API blueprint (used by the extension)
  settings.py         # Environment config, validated at boot
  database.py         # SQLAlchemy models + Database access layer
  cryptograph.py       # Encryption helpers
  config.json          # Table/column config for the admin & password views
  templates/, static/   # Jinja templates, CSS, JS
  extension/maindug/    # Browser extension (Manifest V3)
scripts/              # createAdmin.py, migrateLookupHashes.py
tests/                # pytest suite; tests/extension/ = extension unit + e2e tests
docs/
  tex/                # TCC (thesis) LaTeX source, PDF, and screenshots
  classDiagram.mmd, mer.mmd  # Mermaid class/ER diagrams
requirements.txt
```

## Getting started

### Requirements
- Python 3.10+
- PostgreSQL (or use the SQLite fallback for local development)

### Setup

```bash
git clone <repo-url>
cd MainDugWeb
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill it in. `src/settings.py` refuses to start and lists
any missing key. `SECRET_KEY`, `ENCRYPTION_KEY` and `JWT_SECRET` must be three different values.

Create the schema (Alembic owns it; the app never creates tables), then run the app and the tests:

```bash
DATABASE_URL=sqlite:///$PWD/instance/maindug.db python scripts/migrate.py   # same URL the app uses
python src/app.py
python -m pytest
```

New schema change: edit the models in `src/database.py`, then `alembic revision --autogenerate -m "..."`
(with your dev `.env` loaded), review the generated file in `alembic/versions/` and run `scripts/migrate.py`.

The first admin is created at boot from `BOOTSTRAP_ADMIN_LOGIN` / `BOOTSTRAP_ADMIN_PASSWORD` (12+ chars) when that login does not exist yet; remove the variables afterwards. Locally you can also run `python scripts/createAdmin.py` with the same variables.

### Browser extension

The same folder works in Chrome/Brave/Edge and in Firefox (one manifest: `background.service_worker` for Chrome, `background.scripts` for Firefox).

**Chrome, Brave, Edge**: open `chrome://extensions` (or `brave://extensions`), enable **Developer mode**, click **Load unpacked** and pick `src/extension/maindug`.

**Firefox** (142+):
- Quick test: `about:debugging` → **This Firefox** → **Load Temporary Add-on…** → pick `src/extension/maindug/manifest.json`. It is removed when Firefox closes.
- Permanent install: Firefox only installs signed add-ons. Sign it (unlisted, for your own use) with your addons.mozilla.org API keys, then open the generated `.xpi` in Firefox:
  ```bash
  cd tests/extension && npm install
  WEB_EXT_API_KEY=<jwt issuer> WEB_EXT_API_SECRET=<jwt secret> npm run sign:firefox   # keys: addons.mozilla.org/developers/addon/api/key/
  # -> dist/extension/*.xpi
  ```

Then click the MainDug icon and sign in with your MainDug account. It talks to `https://maindug.leogotardo.com.br/api` by default; for a local server set **Config. → Servidor (avançado)** to `http://localhost:5000/api` (the browser asks for permission).

The vault locks when the browser closes, when the screen locks and after 15 minutes of system inactivity (`idle` API; using the computer without touching the vault does not lock it). Credentials are suggested only on their exact domain or its subdomains, so save sites as domains (`github.com`).

Tests and packaging (from `tests/extension/`, after `npm install`):

```bash
npm run test:unit                                    # domain matching (no browser)
npx @puppeteer/browsers install chrome@stable        # Chrome for Testing, once
CHROME_PATH=<path> npm run test:e2e
npx @puppeteer/browsers install firefox@stable       # Firefox outside snap, once
FIREFOX_PATH=<path> npm run test:e2e:firefox
npm run lint:firefox                                 # Mozilla's add-on linter
npm run build                                        # dist/extension/*.zip (Chrome Web Store / Firefox)
```

## Deployment

The repo deploys on Vercel with zero config: Vercel detects Flask and serves `src/app.py`. Do not add a catch-all rewrite in `vercel.json` — Vercel now forwards the rewritten path to Flask, so every route would 404. See [`VERCEL_ATTEMPTS.md`](VERCEL_ATTEMPTS.md) for the history.

Database migrations run in GitHub Actions (`.github/workflows/ci.yml`): every push runs the tests; a push to `main` then runs `scripts/migrate.py` against production. One-time setup:

1. **GitHub secret `DATABASE_URL`** (Settings → Secrets and variables → Actions): the **direct (unpooled)** Postgres URL from the Neon console. DDL does not work through the pooler.
2. **Vercel → Settings → Deployment Checks**: add GitHub and require the `migrate` check, so a production deployment is promoted only after its migrations ran.

Migrations must stay compatible with the code that is live while they run (add columns as nullable, backfill, then make them required in a later deploy; drop things only after no deployed code reads them). Preview deployments share the production database and migrations only run from `main`, so preview code must not depend on unmerged migrations.

## Known issues

Open items and limitations are tracked in [`PROBLEMS.md`](PROBLEMS.md).

## Author

Leonardo da Silva Gotardo — Instituto Federal do Paraná, Campus Londrina (2025). Advisor: Augusto Luengo Pereira Nunes.
