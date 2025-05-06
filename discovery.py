# discovery.py

import socket
import threading

DISCOVERY_PORT = 9999
DISCOVERY_MESSAGE = b"DISCOVER_CIPHERSHARE"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

def broadcast_presence(tcp_port):
    message = f"{DISCOVERY_MESSAGE.decode()}:{tcp_port}".encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(message, ("<broadcast>", DISCOVERY_PORT))
    sock.close()

def listen_for_broadcasts(callback):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", DISCOVERY_PORT))

    def listen():
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                message = data.decode()
                if message.startswith(DISCOVERY_MESSAGE.decode()):
                    parts = message.split(":")
                    if len(parts) == 2:
                        peer_port = int(parts[1])
                        callback(addr[0], peer_port)
            except Exception as e:
                print(f"[!] Discovery error: {e}")
                break

    threading.Thread(target=listen, daemon=True).start()