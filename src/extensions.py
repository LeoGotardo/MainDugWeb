"""Extensões Flask compartilhadas, criadas aqui para evitar import circular entre app e rotas."""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

import settings

csrf = CSRFProtect()

# Armazenamento em memória: o limite vale por instância. No Vercel isso é um piso, não
# um teto global; para limite global, aponte RATE_LIMIT_STORAGE para um Redis.
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.RATE_LIMIT_STORAGE)
