# Tentativas de Deploy no Vercel

## Contexto

Projeto: Flask app (`src/app.py`) + blueprint de API (`src/api/index.py`).  
Problema central: Vercel exige um entry point em `api/index.py` na raiz, mas o `app.py` já importa `from api.index import blueprint` — conflito de nomes entre o wrapper do Vercel (`api/index.py` raiz) e o blueprint interno (`src/api/index.py`).

---

## Tentativa 1 — Configuração inicial do Vercel (`221911e`)

**O que foi feito:**
- Criado `api/index.py` na raiz como entry point do Vercel:
  ```python
  import sys, os
  sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
  from app import app
  ```
- Criado `vercel.json`:
  ```json
  {
    "builds": [{ "src": "api/index.py", "use": "@vercel/python" }],
    "rewrites": [{ "source": "/(.*)", "destination": "/api/index" }]
  }
  ```
- Atualizado `requirements.txt` com dependências do Flask.
- Corrigido path hardcoded `./src/config.json` em `app.py`.
- Criado `PROBLEMS.md` documentando bugs do código.

**Resultado:** Deploy não funcionou — `app.py` importa `from api.index import blueprint`, e com o `api/index.py` da raiz no path, Python capturava o wrapper Vercel no lugar do blueprint real em `src/api/index.py`.

---

## Tentativa 2 — Limpar cache do módulo `api` (`ff66b49`)

**O que foi feito:**
- Adicionado no topo de `src/app.py`:
  ```python
  import sys, os
  _src_dir = os.path.dirname(os.path.abspath(__file__))
  sys.path.insert(0, _src_dir)
  # Remover qualquer 'api' cacheado que aponte para o wrapper Vercel
  for _key in list(sys.modules.keys()):
      if _key == 'api' or _key.startswith('api.'):
          del sys.modules[_key]
  ```
- Criado `src/api/__init__.py` vazio para garantir que `src/api/` seja reconhecido como pacote.

**Raciocínio:** Quando o Vercel importa `api.index` (a raiz), Python cacheia esse módulo. Quando `app.py` depois faz `from api.index import blueprint`, pega o cache errado. Limpar `sys.modules` antes força re-importação a partir de `src/api/`.

**Resultado:** Parcialmente melhorou, mas `.env` não estava sendo carregado — variáveis de ambiente ausentes causavam crash no `Database()`.

---

## Tentativa 3 — Carregar `.env` em ambos os lados (`7b22c2c`)

**O que foi feito:**
- `api/index.py` (entry Vercel) passou a carregar `.env` antes de importar `app`:
  ```python
  from dotenv import load_dotenv
  _src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')
  load_dotenv(os.path.join(_src_dir, '.env'))
  sys.path.insert(0, _src_dir)
  from app import app
  ```
- `src/app.py` também carrega `.env` antes de qualquer import:
  ```python
  from dotenv import load_dotenv
  load_dotenv(os.path.join(_src_dir, '.env'))
  ```
- Removida chamada duplicada de `load_dotenv()` que estava no meio do arquivo.

**Resultado:** Deploy sobe, mas status atual desconhecido — não foi confirmado se todas as rotas funcionam corretamente em produção.

---

## Estado Atual dos Arquivos

### `api/index.py` (raiz — entry point Vercel)
```python
import sys, os
from dotenv import load_dotenv

_src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')
load_dotenv(os.path.join(_src_dir, '.env'))
sys.path.insert(0, _src_dir)

from app import app
```

### `vercel.json`
```json
{
  "builds": [{ "src": "api/index.py", "use": "@vercel/python" }],
  "rewrites": [{ "source": "/(.*)", "destination": "/api/index" }]
}
```

### Início de `src/app.py`
```python
import sys, os
from dotenv import load_dotenv

_src_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_src_dir, '.env'))
sys.path.insert(0, _src_dir)
# Limpar cache do módulo 'api' para evitar capturar o wrapper Vercel
for _key in list(sys.modules.keys()):
    if _key == 'api' or _key.startswith('api.'):
        del sys.modules[_key]
```

---

## Problemas Conhecidos Não Resolvidos

1. **Conflito de nomes `api/`** — `api/index.py` raiz (Vercel) vs `src/api/index.py` (blueprint Flask). A limpeza de `sys.modules` é um workaround frágil.
2. **`config.json` com path relativo** — `open('./src/config.json')` ainda pode quebrar dependendo do cwd no Vercel (bug #10 do `PROBLEMS.md`).
3. **Variáveis de ambiente** — `.env` não existe em produção no Vercel; as vars precisam estar configuradas no painel do Vercel (Settings → Environment Variables). `load_dotenv` silenciosamente não faz nada se o arquivo não existe — ok, mas qualquer var ausente causa crash no `Database()`.
4. **SQLite em produção** — Vercel Functions são stateless/efêmeras. Se o banco for SQLite (`src/instance/`), dados não persistem entre deploys ou instâncias. Precisa de banco externo (Postgres, MySQL).

---

## Próximos Passos Sugeridos

- [ ] Verificar logs do deploy atual no painel Vercel para confirmar se está funcionando.
- [ ] Confirmar que todas as env vars estão no painel do Vercel (não só no `.env` local).
- [ ] Resolver conflito de nomes `api/` de forma limpa — renomear entry point para `wsgi.py` ou usar configuração diferente no `vercel.json`.
- [ ] Checar se banco é SQLite e migrar para banco persistente se necessário.
