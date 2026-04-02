#!/usr/bin/env python3
import sys
import json
import base64
import os
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def derive_key(password, salt):
    """Генерация ключа из пароля и соли"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend() 
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        return

    try:
        with open(input_file, 'rb') as f:
            data = f.read()
            # Проверка валидности JSON перед шифрованием
            json.loads(data)
    except json.JSONDecodeError:
        print("Error: Input file is not valid JSON.")
        return

    password = getpass.getpass("Enter password for encryption: ")
    confirm = getpass.getpass("Confirm password: ")
    
    if password != confirm:
        print("Error: Passwords do not match.")
        return

    # Генерируем случайную соль (16 байт)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    
    encrypted_data = f.encrypt(data)

    # Сохраняем: первые 16 байт - соль, остальное - данные
    with open(output_file, 'wb') as f:
        f.write(salt + encrypted_data)
    
    print(f"Success! Encrypted config saved to '{output_file}'")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 config_encryptor.py <input_json> <output_enc>")
        print("Example: python3 config_encryptor.py config.json config.enc")
    else:
        encrypt_file(sys.argv[1], sys.argv[2])
