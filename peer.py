# peer.py
import socket
import threading
import discovery
import time
import os
import uuid
import shutil
import json
import queue
from auth import *

# For Phase 3 File Encryption, Decryption, File Integrity, Key Management
from crypto_utils import encrypt_file, decrypt_file, hash_file

class FileSharePeer:
    def __init__(self, listen_port=5000):
        self.logged_in_user = None
        self.listen_port = listen_port
        self.local_ip = discovery.get_local_ip()
        self.peers = set()
        self.running = True
        self.request_queue = queue.Queue()

        os.makedirs("shared", exist_ok=True)
        os.makedirs("received", exist_ok=True)
        os.makedirs("chunks", exist_ok=True) # phase 4 chunks for large files

        self.shared_files = {}

    def start(self):
        print(f"[+] Starting peer at {self.local_ip}:{self.listen_port}")
        threading.Thread(target=self.start_server, daemon=True).start()
        threading.Thread(target=self.listen_for_broadcasts, daemon=True).start()
        threading.Thread(target=self.broadcast_presence, daemon=True).start()
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
            data = conn.recv(1024).decode()

            if data.startswith("GET_FILE:"):
                file_info = data.split(":")[1]
                if "|" in file_info:
                    file_id, requesting_user = file_info.split("|")
                else:
                    file_id, requesting_user = file_info, "unknown"
                self.request_queue.put({
                    "type": "download",
                    "file_id": file_id,
                    "requesting_user": requesting_user,
                    "conn": conn,
                    "addr": addr
                })
                return

            elif data == "LIST_FILES":
                self.request_queue.put({
                    "type": "list",
                    "conn": conn,
                    "addr": addr
                })
                return

            else:
                print(f"[{addr}] {data}")
        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
        finally:
            pass

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
            self.process_pending_requests()
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
                self.command_loop()
                break

            elif cmd == "exit":
                print("[*] Shutting down...")
                self.running = False
                break

            else:
                print("Unknown command.")

    def process_pending_requests(self):
        while not self.request_queue.empty():
            request = self.request_queue.get()
            conn = request["conn"]
            addr = request["addr"]

            if request["type"] == "list":
                print(f"[REQUEST] Peer {addr[0]} wants to view your shared files.")
                decision = input("Allow this peer to list your files? (yes/no): ").strip().lower()
                if decision != "yes":
                    conn.send(b"ERROR: Access denied by the user.")
                    conn.close()
                    continue

                file_list = []
                for file_id, meta in self.shared_files.items():
                    file_list.append({"id": file_id, "name": meta["filename"], "size": meta["size"]})

                response = {
                    "files": file_list,
                    "username": self.logged_in_user or "unknown"
                }
                conn.sendall(json.dumps(response).encode())
                conn.close()


            elif request["type"] == "download":
                file_id = request["file_id"]
                requesting_user = request["requesting_user"]
                print(f"[REQUEST] Peer {addr[0]} is requesting file download.")
                decision = input("Allow this download request? (yes/no): ").strip().lower()

                if decision != "yes":
                    request["conn"].send(b"ERROR: Access denied by the user.")
                    request["conn"].close()
                    continue

                if file_id not in self.shared_files:
                    request["conn"].send(b"ERROR: File not found.")
                    request["conn"].close()
                    continue

                chunk_meta = self.encryption_keys.get(file_id)

                if not chunk_meta:
                    request["conn"].send(b"ERROR: Encryption metadata not found.")
                    request["conn"].close()
                    continue

                metadata = {
                    "filename": self.shared_files[file_id]["filename"],
                    "chunks": []
                }

                for chunk_info in chunk_meta:
                    metadata["chunks"].append({
                        "key": chunk_info["key"].hex(),
                        "iv": chunk_info["iv"].hex(),
                        "hash": chunk_info["hash"]
                    })

                request["conn"].sendall((json.dumps(metadata) + "\n").encode())
                time.sleep(0.1)

                for chunk_info in chunk_meta:
                    with open(chunk_info["chunk_file"], "rb") as f:
                        while chunk := f.read(4096):
                            request["conn"].sendall(chunk)
                request["conn"].close()
                print(f"[UPLOAD] Sent file {file_id} to {addr} (user: {requesting_user})")

    def command_loop(self):
        while self.running and not self.logged_in_user:
            self.process_pending_requests()
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

        if self.logged_in_user:
            print(f"[✓] Welcome, {self.logged_in_user}! You're now logged in.")
            self.authenticated_loop()

    def _write_temp_chunk(self, data):
        temp_path = "temp_chunk.tmp"
        with open(temp_path, "wb") as f:
            f.write(data)
        return temp_path

    def upload_file(self, filepath):
        # Ensure the user is logged in before uploading
        if not self.logged_in_user:
            print("[!] You must be logged in to upload files.")
            return

        # Check that the specified file exists
        if not os.path.isfile(filepath):
            print("[!] File does not exist.")
            return

        # Prepare file metadata
        filename = os.path.basename(filepath)
        file_id = str(uuid.uuid4())
        chunk_dir = os.path.join("chunks", file_id)
        os.makedirs(chunk_dir, exist_ok=True)  # Create directory for storing chunks

        chunk_size = 1024 * 1024  # 1MB per chunk
        keys = []  # To store encryption metadata for each chunk

        with open(filepath, "rb") as f:
            index = 0
            while True:
                chunk_data = f.read(chunk_size)  # Read 1MB of data
                if not chunk_data:
                    break  # Stop if no more data

                # Encrypt and save the chunk
                chunk_path = os.path.join(chunk_dir, f"chunk_{index}.enc")
                encrypted_path, key, iv, sha256 = encrypt_file(
                    self._write_temp_chunk(chunk_data)  # Write chunk to temp file for encryption
                )
                shutil.move(encrypted_path, chunk_path)  # Move encrypted file to chunk directory

                # Save metadata for decryption and verification
                keys.append({
                    "key": key,
                    "iv": iv,
                    "hash": sha256,
                    "chunk_file": chunk_path
                })
                index += 1
        # Register file for sharing
        self.shared_files[file_id] = {
            "filename": filename,
            "chunk_dir": chunk_dir,
            "chunks": len(keys),
            "size": os.path.getsize(filepath)
        }
        # Store encryption keys if not already initialized
        if not hasattr(self, "encryption_keys"):
            self.encryption_keys = {}

        # Save encryption info for this file
        self.encryption_keys[file_id] = keys
        print(f"[+] File '{filename}' uploaded in {len(keys)} chunks. ID: {file_id}")


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

            # Receive metadata
            buffer = b""
            while not buffer.endswith(b"\n"):
                chunk = sock.recv(1)
                if not chunk:
                    raise Exception("Connection closed before metadata received")
                buffer += chunk

            metadata = json.loads(buffer.decode())
            filename = metadata["filename"]
            chunks_meta = metadata["chunks"]
            num_chunks = len(chunks_meta)

            enc_chunk_paths = []
            for i in range(num_chunks):
                enc_path = os.path.join("received", f"{file_id}_chunk_{i}.enc")
                with open(enc_path, "wb") as f:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        f.write(chunk)
                        if f.tell() >= 1024 * 1024 or i == num_chunks - 1:
                            break
                enc_chunk_paths.append(enc_path)

            final_path = os.path.join("received", filename)
            with open(final_path, "wb") as out_f:
                for i, enc_path in enumerate(enc_chunk_paths):
                    key = bytes.fromhex(chunks_meta[i]["key"])
                    iv = bytes.fromhex(chunks_meta[i]["iv"])
                    expected_hash = chunks_meta[i]["hash"]

                    temp_decrypted = f"received/temp_decrypted_{i}.bin"
                    decrypt_file(enc_path, key, iv, temp_decrypted)

                    if hash_file(temp_decrypted) != expected_hash:
                        print(f"[!] Integrity failed for chunk {i}")
                        continue

                    with open(temp_decrypted, "rb") as part:
                        shutil.copyfileobj(part, out_f)
                    os.remove(temp_decrypted)

            print(f"[✓] File downloaded, decrypted, and assembled: {final_path}")

        except Exception as e:
            print(f"[!] Download failed: {e}")
        finally:
            sock.close()



if __name__ == "__main__":
    port_input = input("Enter port to listen on (e.g., 5000): ").strip()
    try:
        port = int(port_input)
    except:
        port = 5000
    peer = FileSharePeer(listen_port=port)
    peer.start()
