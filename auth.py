# auth.py
import hashlib
import os
import getpass
import pwinput

def user_exists(username):
    if not os.path.exists("users.txt"):
        return False
    with open("users.txt", "r") as f:
        return any(line.split(",")[0] == username for line in f)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user():
    username = input("Choose a username: ").strip()
    password = pwinput.pwinput(prompt="Password: ", mask="*")

    if not username or not password:
        print("[!] Username and password cannot be empty.")
        return

    if os.path.exists("users.txt"):
        with open("users.txt", "r") as f:
            for line in f:
                if user_exists(username):
                    print("[!] Username already exists.")
                    return


    hashed_pw = hash_password(password)
    with open("users.txt", "a") as f:
        f.write(f"{username},{hashed_pw}\n")

    print(f"[✓] User '{username}' registered successfully.")

def login_user():
    username = input("Username: ").strip()
    password = pwinput.pwinput(prompt="Password: ", mask="*")
    hashed_pw = hash_password(password)

    if not os.path.exists("users.txt"):
        print("[!] No users registered yet.")
        return None

    with open("users.txt", "r") as f:
        for line in f:
            stored_user, stored_hash = line.strip().split(",")
            if stored_user == username and stored_hash == hashed_pw:
                print(f"[✓] Logged in as {username}")
                return username  # ✅ return username on success

    print("[!] Invalid username or password.")
    return None
