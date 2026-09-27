import base64
import getpass
import os
import subprocess
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SALT_LENGTH = 16
ITERATIONS = 480_000
ENCRYPTED_SUFFIX = ".s4nty"


def make_cipher(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def encrypt_file(file_path: Path) -> None:
    if not file_path.is_file():
        raise FileNotFoundError("The selected file does not exist.")
    if file_path.suffix.lower() == ENCRYPTED_SUFFIX:
        raise ValueError("This file is already encrypted.")

    encrypted_path = Path(f"{file_path}{ENCRYPTED_SUFFIX}")
    if encrypted_path.exists():
        raise FileExistsError(f"{encrypted_path.name} already exists.")

    password = getpass.getpass("Create a password for this file: ")
    confirmation = getpass.getpass("Confirm the password: ")
    if not password:
        raise ValueError("A password is required.")
    if password != confirmation:
        raise ValueError("The passwords do not match.")

    salt = os.urandom(SALT_LENGTH)
    encrypted_data = make_cipher(password, salt).encrypt(file_path.read_bytes())
    encrypted_path.write_bytes(salt + encrypted_data)
    file_path.unlink()
    print(f"Encrypted successfully: {encrypted_path}")


def decrypt_file(file_path: Path) -> None:
    if not file_path.is_file():
        raise FileNotFoundError("The encrypted file does not exist.")

    password = getpass.getpass(f"Enter password to unlock {file_path.name}: ")
    if not password:
        raise ValueError("A password is required.")

    data = file_path.read_bytes()
    if len(data) <= SALT_LENGTH:
        raise ValueError("This is not a valid encrypted file.")

    try:
        decrypted_data = make_cipher(password, data[:SALT_LENGTH]).decrypt(data[SALT_LENGTH:])
    except InvalidToken as exc:
        raise ValueError("Incorrect password or an invalid encrypted file.") from exc

    output_path = Path(str(file_path)[:-len(ENCRYPTED_SUFFIX)])
    if output_path.exists():
        raise FileExistsError(f"{output_path.name} already exists; it was not overwritten.")

    output_path.write_bytes(decrypted_data)
    print("Password accepted. Opening the decrypted file in Notepad...")
    try:
        subprocess.run(["notepad.exe", str(output_path)], check=False)
    finally:
        if output_path.exists():
            output_path.unlink()


def main() -> None:
    try:
        if len(sys.argv) > 1:
            selected_path = Path(sys.argv[1].strip('"'))
            if selected_path.suffix.lower() != ENCRYPTED_SUFFIX:
                raise ValueError("Only .s4nty files can be opened for decryption.")
            decrypt_file(selected_path)
        else:
            selected_path = Path(input("Enter the path of the file to encrypt: ").strip().strip('"'))
            encrypt_file(selected_path)
    except (FileNotFoundError, FileExistsError, ValueError, OSError) as exc:
        print(f"\n[ERROR] {exc}")
    finally:
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
