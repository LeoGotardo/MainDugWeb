"""
Migração única: troca os hashes de busca antigos (sha256 puro) pelos novos (HMAC com
chave derivada de ENCRYPTION_KEY) nas colunas de login e site.

Rode uma vez, com ENCRYPTION_KEY igual ao antigo `SecretKey`, antes de abrir a nova
versão para os usuários. Sem isso, ninguém que já tinha conta consegue entrar.

    ./venv/bin/python scripts/migrateLookupHashes.py
"""
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

from database import Config, User, Passwords


def main() -> int:
    with Config.app.app_context():
        session = Config.session
        users = session.query(User).all()
        passwords = session.query(Passwords).all()

        # Reatribuir o valor decifrado recalcula a coluna *_hash pelo setter.
        for user in users:
            user.login = user.login
        for credential in passwords:
            credential.login = credential.login
            credential.site = credential.site

        session.commit()
        print(f'{len(users)} usuário(s) e {len(passwords)} credencial(is) migrados.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
