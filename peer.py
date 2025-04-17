# peer.py
import socket
import threading
import discovery
import time
import os
import uuid
import shutil
import json

class FileSharePeer:
    def __init__(self, listen_port=5000):
        self.listen_port = listen_port
        self.local_ip = discovery.get_local_ip()
        self.peers = set()  # Discovered peers (IP, port)
        self.running = True
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
            import json
            files = json.loads(data).get("files", [])

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



    def command_loop(self):
        while self.running:
            cmd = input("Enter command (list/connect/exit/upload/myfies): ").strip().lower()
            if cmd == "list":
                if not self.peers:
                    print("No peers discovered yet.")
                else:
                    for i, peer in enumerate(self.peers):
                        print(f"{i+1}: {peer[0]}:{peer[1]}")
            elif cmd == "connect":
                if not self.peers:
                    print("No peers to connect to.")
                    continue
                index = int(input("Enter peer number to connect: ")) - 1
                if 0 <= index < len(self.peers):
                    ip, port = list(self.peers)[index]
                    self.connect_to_peer(ip, port)
                else:
                    print("Invalid index.")
            elif cmd == "exit":
                print("[*] Shutting down...")
                self.running = False
                break
            elif cmd == "upload":
                path = input("Enter full path to the file: ").strip()
                self.upload_file(path)

            elif cmd == "myfiles":
                self.list_shared_files()

            else:
                print("Unknown command.")

    def upload_file(self, filepath):
        if not os.path.isfile(filepath):
            print("[!] File does not exist.")
            return

        filename = os.path.basename(filepath)
        file_id = str(uuid.uuid4())
        shared_path = os.path.join("shared", filename)

        shutil.copy(filepath, shared_path)

        self.shared_files[file_id] = {
            "filename": filename,
            "path": shared_path,
            "size": os.path.getsize(shared_path)
        }

        print(f"[+] File '{filename}' is now shared with ID: {file_id}")

    def list_shared_files(self):
        if not self.shared_files:
            print("[*] No files currently shared.")
            return
        for i, (fid, info) in enumerate(self.shared_files.items(), start=1):
            print(f"{i}. {info['filename']} (ID: {fid}, Size: {info['size']} bytes)")

    def download_file(self, file_id, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            sock.send(f"GET_FILE:{file_id}".encode())

            dest_path = os.path.join("received", f"{file_id}.bin")
            with open(dest_path, "wb") as f:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    f.write(chunk)

            print(f"[+] File downloaded and saved to {dest_path}")
        except Exception as e:
            print(f"[!] Download failed: {e}")
        finally:
            sock.close()

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(1024).decode()
            if data.startswith("GET_FILE:"):
                file_id = data.split(":")[1]
                if file_id in self.shared_files:
                    file_path = self.shared_files[file_id]["path"]
                    with open(file_path, "rb") as f:
                        while chunk := f.read(1024):
                            conn.sendall(chunk)
                    print(f"[UPLOAD] Sent file {file_id} to {addr}")
                else:
                    conn.send(b"ERROR: File not found.")

            elif data == "LIST_FILES":
                file_list = []
                for file_id, meta in self.shared_files.items():
                    file_list.append({
                        "id": file_id,
                        "name": meta["filename"],
                        "size": meta["size"]
                    })
                response = json.dumps({"files": file_list})
                conn.sendall(response.encode())
            else:
                print(f"[{addr}] {data}")  # Basic text message fallback
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