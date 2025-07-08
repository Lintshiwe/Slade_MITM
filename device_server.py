import socket
import threading
import os
from PIL import ImageGrab
import io

def handle_client(conn, addr):
    try:
        data = conn.recv(4096)
        if not data:
            return
        if data.startswith(b'MSG:'):
            msg = data[4:].decode(errors='ignore')
            print(f"[Message from {addr}] {msg}")
        elif data.startswith(b'FILE:'):
            header, filedata = data.split(b'\n', 1)
            _, filename, length = header.decode().split(':')
            length = int(length)
            received = filedata
            while len(received) < length:
                chunk = conn.recv(min(4096, length - len(received)))
                if not chunk:
                    break
                received += chunk
            with open(f"received_{filename}", 'wb') as f:
                f.write(received)
            print(f"[File from {addr}] Saved as received_{filename}")
        elif data.startswith(b'SCREEN_REQUEST'):
            # Take screenshot and send back
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            img_bytes = buf.getvalue()
            conn.sendall(img_bytes)
            print(f"[Screen] Sent screenshot to {addr}")
        else:
            print(f"[Unknown] {data}")
    except Exception as e:
        print(f"[Error] {e}")
    finally:
        conn.close()

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 5001))
    s.listen(5)
    print("[*] Device server listening on port 5001...")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    try:
        from PIL import ImageGrab
    except ImportError:
        print("Install pillow: pip install pillow")
        exit(1)
    server()
