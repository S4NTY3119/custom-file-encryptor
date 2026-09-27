import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

file_path = input("enter the path of the file that has to be encrypted: ").strip().strip('"')
print("encrypting...")

password = "{password}"
salt = os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
cipher = Fernet(key)
with open(file_path, 'rb') as file:
    original_data = file.read()
encrypted_data = cipher.encrypt(original_data)
encrypted_path = file_path + ".s4nty"
with open(encrypted_path, 'wb') as file:
    file.write(salt + encrypted_data)
os.remove(file_path)

print("encrypted, use your password to unlock the file.")