# peer.py
import socket
import threading
import discovery
import time
import os
import uuid
import shutil
import json
from auth import *

# For Phase 3 File Encryption, Decryption, File Integrity, Key Management
from crypto_utils import encrypt_file, decrypt_file, hash_file


class FileSharePeer:
    def __init__(self, listen_port=5000):
        # for login
        self.logged_in_user = None

        # for connection with other peers
        self.listen_port = listen_port
        self.local_ip = discovery.get_local_ip()
        self.peers = set()  # Discovered peers (IP, port)
        self.running = True

        # for file sharing
        os.makedirs("shared", exist_ok=True)
        os.makedirs("received", exist_ok=True)
        self.shared_files = {}  # Initialize file tracking


    def start(self):
        print(f"[+] Starting peer at {self.local_ip}:{self.listen_port}")

        # Start TCP server to accept connections
        threading.Thread(target=self.start_server, daemon=True).start()

        # Start UDP listener for peer discovery
        threading.Thread(target=self.listen_for_broadcasts, daemon=True).start()

        # Broadcast presence
        threading.Thread(target=self.broadcast_presence, daemon=True).start()

        # Start client command loop
        self.command_loop()

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.local_ip, self.listen_port))
        server.listen(5)
        print(f"[TCP] Listening on {self.local_ip}:{self.listen_port}...")

        while self.running:
            conn, addr = server.accept()
            print(f"[TCP] Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(1024)
            if data:
                print(f"[{addr}] {data.decode()}")
        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
        finally:
            conn.close()

    def broadcast_presence(self):
        while self.running:
            discovery.broadcast_presence(self.listen_port)
            time.sleep(5)

    def listen_for_broadcasts(self):
        def callback(ip, port):
            if ip == self.local_ip and port == self.listen_port:
                return
            if (ip, port) not in self.peers:
                print(f"[DISCOVERY] Found peer: {ip}:{port}")
                self.peers.add((ip, port))

        discovery.listen_for_broadcasts(callback)

    def connect_to_peer(self, ip, port):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((ip, port))
            client.send(b"LIST_FILES")

            data = client.recv(8192).decode()

            response = json.loads(data)
            files = response.get("files", [])
            owner_username = response.get("username", "unknown")

            print(f"\n[+] Connected to peer: {ip}:{port} ({owner_username})")

            if not files:
                print("[*] No files available from peer.")
                client.close()
                return

            print("\n[+] Files shared by peer:")
            for i, f in enumerate(files, 1):
                print(f"{i}. {f['name']} (ID: {f['id']}, Size: {f['size']} bytes)")

            choice = input("Enter file number to download or 'x' to skip: ").strip()
            if choice.lower() == 'x':
                client.close()
                return

            index = int(choice) - 1
            if 0 <= index < len(files):
                file_id = files[index]['id']
                client.close()
                self.download_file(file_id, ip, port)
            else:
                print("[!] Invalid choice.")
                client.close()

        except Exception as e:
            print(f"[!] Could not connect to {ip}:{port} - {e}")

    def authenticated_loop(self):
        while self.running:
            cmd = input("Enter command (connect/upload/myfiles/logout/exit): ").strip().lower()

            if cmd == "connect":
                if not self.peers:
                    print("No peers discovered yet.")
                    continue
                for i, peer in enumerate(self.peers):
                    print(f"{i + 1}: {peer[0]}:{peer[1]}")
                index = int(input("Enter peer number to connect: ")) - 1
                if 0 <= index < len(self.peers):
                    ip, port = list(self.peers)[index]
                    self.connect_to_peer(ip, port)
                else:
                    print("Invalid index.")

            elif cmd == "upload":
                path = input("Enter full path to the file: ").strip()
                self.upload_file(path)

            elif cmd == "myfiles":
                self.list_shared_files()

            elif cmd == "logout":
                print(f"[*] User {self.logged_in_user} logged out.")
                self.logged_in_user = None
                self.command_loop()  # Go back to unauthenticated mode
                break

            elif cmd == "exit":
                print("[*] Shutting down...")
                self.running = False
                break

            else:
                print("Unknown command.")

    def command_loop(self):
        while self.running and not self.logged_in_user:
            cmd = input("Enter command (register/login/exit): ").strip().lower()

            if cmd == "register":
                register_user()

            elif cmd == "login":
                username = login_user()
                if username:
                    self.logged_in_user = username

            elif cmd == "exit":
                print("[*] Shutting down...")
                self.running = False
                break

            else:
                print("Unknown command.")

        # ➡️ This is where authenticated_loop() is called!
        if self.logged_in_user:
            print(f"[✓] Welcome, {self.logged_in_user}! You're now logged in.")
            self.authenticated_loop()

    def upload_file(self, filepath):
        if not self.logged_in_user:
            print("[!] You must be logged in to upload files.")
            return

        if not os.path.isfile(filepath):
            print("[!] File does not exist.")
            return

        filename = os.path.basename(filepath)
        file_id = str(uuid.uuid4())

        # Encrypt the file
        enc_path, key, iv, sha256_hash = encrypt_file(filepath)

        # Move encrypted file into shared/
        final_shared_path = os.path.join("shared", f"{file_id}.enc")
        shutil.move(enc_path, final_shared_path)

        # Track encrypted file and metadata
        self.shared_files[file_id] = {
            "filename": filename,
            "path": final_shared_path,
            "size": os.path.getsize(final_shared_path)
        }

        if not hasattr(self, "encryption_keys"):
            self.encryption_keys = {}

        self.encryption_keys[file_id] = {
            "key": key,
            "iv": iv,
            "hash": sha256_hash,
            "original_name": filename
        }

        print(f"[+] File '{filename}' encrypted and shared with ID: {file_id}")

    def list_shared_files(self):
        if not self.shared_files:
            print("[*] No files currently shared.")
            return
        for i, (fid, info) in enumerate(self.shared_files.items(), start=1):
            print(f"{i}. {info['filename']} (ID: {fid}, Size: {info['size']} bytes)")

    def download_file(self, file_id, ip, port):
        if not self.logged_in_user:
            print("[!] You must be logged in to download files.")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            sock.send(f"GET_FILE:{file_id}|{self.logged_in_user}".encode())

            # 🔹 Step 1: Receive metadata first (key, iv, hash, original filename)
            buffer = b""
            while not buffer.endswith(b"\n"):
                chunk = sock.recv(1)
                if not chunk:
                    raise Exception("Connection closed before metadata received")
                buffer += chunk

            metadata = json.loads(buffer.decode())
            key = bytes.fromhex(metadata["key"])
            iv = bytes.fromhex(metadata["iv"])
            expected_hash = metadata["hash"]
            original_filename = metadata["filename"]

            # 🔹 Step 2: Receive the encrypted file
            enc_path = os.path.join("received", f"{file_id}.enc")
            with open(enc_path, "wb") as f:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    f.write(chunk)

            # 🔹 Step 3: Decrypt the file
            decrypted_path = os.path.join("received", original_filename)
            decrypt_file(enc_path, key, iv, decrypted_path)

            # 🔹 Step 4: Verify integrity
            if hash_file(decrypted_path) == expected_hash:
                print(f"[✓] File downloaded, decrypted, and verified: {decrypted_path}")
            else:
                print("[!] Warning: File integrity check FAILED.")

        except Exception as e:
            print(f"[!] Download failed: {e}")
        finally:
            sock.close()

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(1024).decode()

            if data.startswith("GET_FILE:"):
                file_info = data.split(":")[1]
                if "|" in file_info:
                    file_id, requesting_user = file_info.split("|")
                else:
                    file_id, requesting_user = file_info, "unknown"

                if file_id not in self.shared_files:
                    conn.send(b"ERROR: File not found.")
                    return

                file_path = self.shared_files[file_id]["path"]

                # 🔐 Metadata (key, iv, hash, original filename)
                enc_meta = self.encryption_keys.get(file_id)
                if not enc_meta:
                    conn.send(b"ERROR: Encryption metadata not found.")
                    return

                metadata = {
                    "key": enc_meta["key"].hex(),
                    "iv": enc_meta["iv"].hex(),
                    "hash": enc_meta["hash"],
                    "filename": enc_meta["original_name"]
                }

                # 🔹 Send metadata as JSON, ending with newline
                conn.sendall((json.dumps(metadata) + "\n").encode())
                time.sleep(0.1)  # 🧠 Ensure clean separation before sending file

                # 🔹 Send encrypted file content
                with open(file_path, "rb") as f:
                    while chunk := f.read(4096):
                        conn.sendall(chunk)

                print(f"[UPLOAD] Sent file {file_id} to {addr} (user: {requesting_user})")

            elif data == "LIST_FILES":
                file_list = []
                for file_id, meta in self.shared_files.items():
                    file_list.append({
                        "id": file_id,
                        "name": meta["filename"],
                        "size": meta["size"]
                    })

                response = {
                    "files": file_list,
                    "username": self.logged_in_user or "unknown"
                }
                conn.sendall(json.dumps(response).encode())

            else:
                print(f"[{addr}] {data}")  # Fallback for other message types

        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
        finally:
            conn.close()



if __name__ == "__main__":
    port_input = input("Enter port to listen on (e.g., 5000): ").strip()
    try:
        port = int(port_input)
    except:
        port = 5000
    peer = FileSharePeer(listen_port=port)
    peer.start()