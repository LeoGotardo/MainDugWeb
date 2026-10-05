import base64, hashlib, hmac, sys

import argon2
from cryptography.fernet import Fernet

import settings


class Cryptograph:
    def __init__(self) -> None:
        self.ph = argon2.PasswordHasher()
        # Hash de uma senha qualquer, verificado quando o login não existe: assim a
        # resposta leva o mesmo tempo e não revela quais usuários existem.
        self._dummyHash = self.ph.hash('maindug-dummy-password')

    @staticmethod
    def keyGenerator(key: str) -> tuple[bool, bytes] | tuple[bool, str]:
        try:
            hash_bytes = hashlib.sha256(key.encode('utf-8')).digest()
            base64_key = base64.urlsafe_b64encode(hash_bytes)
            return True, base64_key
        except Exception as e:
            return False, f'{type(e).__name__}: {e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'

    def isValidPass(self, hash, password: str) -> tuple[bool, str]:
        try:
            return self.ph.verify(hash, password), "Valid user."
        except Exception as e:
            return False, f'{type(e).__name__}: {e}'

    def burnVerify(self, password: str) -> None:
        self.isValidPass(self._dummyHash, password)

    def encryptPass(self, password: str) -> str:
        return self.ph.hash(password)


# Chave Fernet derivada uma vez por processo. A derivação (sha256 da chave) é a mesma
# de antes, para que os dados já gravados continuem legíveis.
_fernet = Fernet(Cryptograph.keyGenerator(settings.ENCRYPTION_KEY)[1])

# Chave separada para os hashes de busca (login, site). HMAC em vez de sha256 puro:
# sem a chave, não dá para testar uma lista de logins contra o banco.
_lookupKey = hashlib.sha256(b'maindug-lookup:' + settings.ENCRYPTION_KEY.encode('utf-8')).digest()


def encryptField(value: str) -> str:
    """Cifra um valor para gravar no banco (token Fernet em base64, como sempre foi gravado)."""
    return base64.b64encode(_fernet.encrypt(value.encode('utf-8'))).decode('utf-8')


def decryptField(stored: str | bytes | None) -> str | None:
    """Decifra um valor do banco. Levanta InvalidToken se a chave estiver errada."""
    if not stored:
        return None
    raw = base64.b64decode(stored)
    return _fernet.decrypt(raw).decode('utf-8')


def lookupHash(value: str) -> str:
    """Hash determinístico usado nas colunas `*_hash` para busca e unicidade."""
    return hmac.new(_lookupKey, value.encode('utf-8'), hashlib.sha256).hexdigest()
