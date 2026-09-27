import os
import sys
import base64
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

if len(sys.argv) > 1:
    file_path = sys.argv[1]
else:
    file_path = input("Enter the path of the file: ").strip().strip('"')

password = input(f"Enter password to unlock {os.path.basename(file_path)}: ").strip()

try:
    with open(file_path, 'rb') as file:
        data = file.read()
    
    salt = data[:16]
    encrypted_data = data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher = Fernet(key)

    decrypted_data = cipher.decrypt(encrypted_data)
    
    if file_path.endswith('.s4nty'):
        temp_file = file_path[:-6] 
    else:
        temp_file = file_path + "_temp.txt"
        
    with open(temp_file, 'wb') as file:
        file.write(decrypted_data)
        
    print("Password accepted. Opening Notepad...")
    subprocess.run(['notepad.exe', temp_file])
    os.remove(temp_file)
    
except Exception as e:
    print(f"\n[ERROR] Decryption failed: {e}")
    input("Press Enter to exit...")