# crypto_utils.py

import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 4096  # 4 KB blocks


def generate_key_iv():
    key = secrets.token_bytes(32)  # AES-256
    iv = secrets.token_bytes(16)   # 16 bytes IV for AES-CBC
    return key, iv


def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt_file(input_path):
    key, iv = generate_key_iv()
    output_path = f"{input_path}.enc"

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        while chunk := fin.read(CHUNK_SIZE):
            if len(chunk) % 16 != 0:
                chunk = pad(chunk)
            encrypted = encryptor.update(chunk)
            fout.write(encrypted)
        fout.write(encryptor.finalize())

    sha256 = hash_file(input_path)
    return output_path, key, iv, sha256


def decrypt_file(enc_path, key, iv, output_path):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(enc_path, "rb") as fin, open(output_path, "wb") as fout:
        decrypted_data = b""
        while chunk := fin.read(CHUNK_SIZE):
            decrypted_data += decryptor.update(chunk)
        decrypted_data += decryptor.finalize()
        fout.write(unpad(decrypted_data))


def hash_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha256.update(block)
    return sha256.hexdigest()
