"""
Cria (ou atualiza) a conta sysadmin a partir de BOOTSTRAP_ADMIN_LOGIN / BOOTSTRAP_ADMIN_PASSWORD.
Também desativa a antiga conta padrão `sysadmin`/`sysadmin`, se ela ainda existir.

    ./venv/bin/python scripts/createAdmin.py
"""
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

from database import database, Config, User
from cryptograph import lookupHash

MIN_LENGTH = 12


def main() -> int:
    login = os.getenv('BOOTSTRAP_ADMIN_LOGIN', '').strip()
    password = os.getenv('BOOTSTRAP_ADMIN_PASSWORD', '')
    if not login or len(password) < MIN_LENGTH:
        print(f'Defina BOOTSTRAP_ADMIN_LOGIN e BOOTSTRAP_ADMIN_PASSWORD (mínimo {MIN_LENGTH} caracteres).')
        return 1

    with Config.app.app_context():
        session = Config.session

        legacy = session.query(User).filter(User._login_hash == lookupHash('sysadmin')).first()
        if legacy and login != 'sysadmin' and database.iscryptograph.isValidPass(legacy.password, 'sysadmin')[0] is True:
            legacy.enabled = False
            session.commit()
            print('Conta padrão sysadmin/sysadmin desativada.')

        user = session.query(User).filter(User._login_hash == lookupHash(login)).first()
        if user is None:
            success, result = database.createUser(login=login, password=password, role='sysadmin')
            if success is not True:
                print(f'Falha ao criar admin: {result}')
                return 1
            print(f'Admin "{login}" criado.')
        else:
            user.password = database.iscryptograph.encryptPass(password)
            user.role = 'sysadmin'
            user.enabled = True
            session.commit()
            print(f'Admin "{login}" atualizado.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
