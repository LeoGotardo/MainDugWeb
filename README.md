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
  extension/extension/  # Browser extension (Manifest V3)
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

Run the app and the tests:

```bash
python src/app.py
python -m pytest
```

No admin account is created automatically. Create one with:

```bash
BOOTSTRAP_ADMIN_LOGIN=<login> BOOTSTRAP_ADMIN_PASSWORD=<12+ chars> python scripts/createAdmin.py
```

### Browser extension

1. Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked** and pick `src/extension/extension`.
2. Click the MainDug icon and sign in with your MainDug account. It talks to `https://maindug.leogotardo.com.br/api` by default; for a local server set **Config. → Servidor (avançado)** to `http://localhost:5000/api` (Chrome asks for permission).

The vault locks when the browser closes and after 15 minutes idle. Credentials are suggested only on their exact domain or its subdomains, so save sites as domains (`github.com`).

Tests:

```bash
node --test tests/extension/                         # domain matching (no dependencies)
npx @puppeteer/browsers install chrome@stable        # Chrome for Testing, once
cd tests/extension && npm install && cd -            # puppeteer-core, once
CHROME_PATH=<path printed above> node tests/extension/e2e.mjs
```

## Deployment

The repo deploys on Vercel with zero config: Vercel detects Flask and serves `src/app.py`. Do not add a catch-all rewrite in `vercel.json` — Vercel now forwards the rewritten path to Flask, so every route would 404. See [`VERCEL_ATTEMPTS.md`](VERCEL_ATTEMPTS.md) for the history.

## Known issues

The codebase currently has several open bugs (undefined methods/columns, mismatched function signatures, etc.) tracked in [`PROBLEMS.md`](PROBLEMS.md) — check there before relying on features like `/moreInfo`, the `/api` endpoints, or account editing.

## Author

Leonardo da Silva Gotardo — Instituto Federal do Paraná, Campus Londrina (2025). Advisor: Augusto Luengo Pereira Nunes.
