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
- **Extension:** JavaScript (Manifest V3), with an optional Node/Express backend

## Project structure

```
src/
  app.py            # Flask app, routes, views
  api/index.py       # JWT-protected API blueprint (used by the extension)
  database.py         # SQLAlchemy models + Database access layer
  cryptograph.py       # Encryption helpers
  config.json          # Table/column config for the admin & password views
  templates/, static/   # Jinja templates, CSS, JS
  extension/            # Browser extension + its Node/Express backend
extention/            # Standalone browser extension prototype (JS + Node backend)
api/wsgi.py            # Vercel entry point, wraps src/app.py
docs/
  tex/                # TCC (thesis) LaTeX source, PDF, and screenshots
  classDiagram.mmd, mer.mmd  # Mermaid class/ER diagrams
vercel.json
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

Create `src/.env` with:

```
SecretKey=<flask + encryption secret key>
DefaultPassword=<default password used for seeded/admin accounts>
DATABASE_URL=postgresql://user:password@localhost:5432/maindug   # omit to fall back to sqlite
JWT_SECRET=<secret for signing extension API tokens>
SITE_URL=https://your-deployment-url
```

Run the app:

```bash
python src/app.py
```

### Browser extension

Load `src/extension/extension` (or `extention/` for the standalone prototype) as an unpacked extension in Chrome/Firefox. Both ship a Manifest V3 extension and an optional Node/Express backend under their respective `backend/`/root folders — see `src/extension/backend/server.js` for its API surface.

## Deployment

The repo is configured to deploy on Vercel: `api/wsgi.py` is the serverless entry point, and `vercel.json` routes all requests to it. See [`VERCEL_ATTEMPTS.md`](VERCEL_ATTEMPTS.md) for the history of issues hit while wiring this up (mainly the `api/index.py` naming clash between Vercel's convention and the internal API blueprint).

## Known issues

The codebase currently has several open bugs (undefined methods/columns, mismatched function signatures, etc.) tracked in [`PROBLEMS.md`](PROBLEMS.md) — check there before relying on features like `/moreInfo`, the `/api` endpoints, or account editing.

## Author

Leonardo da Silva Gotardo — Instituto Federal do Paraná, Campus Londrina (2025). Advisor: Augusto Luengo Pereira Nunes.
