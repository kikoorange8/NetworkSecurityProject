# auth.py
import os
import base64
import pwinput
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def user_exists(username):
    if not os.path.exists("users.txt"):
        return False
    with open("users.txt", "r") as f:
        return any(line.split(",")[0] == username for line in f)

# 🔐 PBKDF2 Password Hashing
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # 128-bit salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 compatible
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.b64encode(key).decode(), base64.b64encode(salt).decode()  # both as base64 strings

def verify_password(password, stored_key_b64, salt_b64):
    salt = base64.b64decode(salt_b64)
    stored_key = base64.b64decode(stored_key_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), stored_key)
        return True
    except Exception:
        return False

def register_user():
    username = input("Choose a username: ").strip()
    password = pwinput.pwinput(prompt="Password: ", mask="*")

    if not username or not password:
        print("[!] Username and password cannot be empty.")
        return

    if user_exists(username):
        print("[!] Username already exists.")
        return

    derived_key, salt = hash_password(password)
    with open("users.txt", "a") as f:
        f.write(f"{username},{salt},{derived_key}\n")

    print(f"[✓] User '{username}' registered successfully.")

def login_user():
    username = input("Username: ").strip()
    password = pwinput.pwinput(prompt="Password: ", mask="*")

    if not os.path.exists("users.txt"):
        print("[!] No users registered yet.")
        return None

    with open("users.txt", "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != 3:
                continue
            stored_user, salt_b64, key_b64 = parts
            if stored_user == username and verify_password(password, key_b64, salt_b64):
                print(f"[✓] Logged in as {username}")
                return username

    print("[!] Invalid username or password.")
    return None
