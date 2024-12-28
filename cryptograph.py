import base64, argon2, sys

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from hashlib import sha256

class Cryptograph:
    def __init__(self) -> None:
        load_dotenv()
        self.ph = argon2.PasswordHasher()
        
        
    def keyGenerator(key: str) -> tuple[bool, bytes] | tuple[bool, str]:
        try:
            hash_bytes = sha256(key.encode('utf-8')).digest()
            
            base64_key = base64.urlsafe_b64encode(hash_bytes)
            
            return True, base64_key
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
    
    
    def isValidPass(self, hash, password: str) -> bool:
        try:
            return self.ph.verify(hash, password)
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
  
    
    def encryptSentence(message: str, key: bytes) -> bytes:
        try:
            cipher = Fernet(key)
            encrypted_message = cipher.encrypt(message.encode('utf-8'))

            return True, encrypted_message
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
    
    
    def decryptSentence(encrypted_string: bytes, key: bytes) -> tuple[bool, str]:
        try:
            cipher = Fernet(key)
            
            decrypted_message = cipher.decrypt(encrypted_string)
            decrypted_message = decrypted_message.decode('utf-8')

            return True, decrypted_message
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
    
    def encryptPass(self, password: str) -> str:
        try:
            hash = self.ph.hash(password)
            
            return hash
        except Exception as e:
            return False, f'{e} in line {sys.exc_info()[-1].tb_lineno} in file {sys.exc_info()[-1].tb_frame.f_code.co_filename}'
    
        
if __name__ == "__main__":
    Cryptograph()