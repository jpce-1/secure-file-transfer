import socket
import hashlib
import os
import sys
from cryptography.fernet import Fernet

# ── Configuration ──────────────────────────────────────
PORT = 5001        # Must match server port
BUFFER_SIZE = 4096 # Must match server buffer size
KEY_FILE = 'secret.key'  # Encryption key file
# ───────────────────────────────────────────────────────


def load_key():
    if not os.path.exists(KEY_FILE):
        print(f"[ERROR] No key file found! Copy 'secret.key' from the server first.")
        sys.exit()
    with open(KEY_FILE, 'rb') as f:
        return f.read()


def encrypt_file(file_data, key):
    fernet = Fernet(key)
    return fernet.encrypt(file_data)


def calculate_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()


def send_file(host, filepath):
    if not os.path.exists(filepath):
        print(f"[ERROR] File '{filepath}' not found!")
        sys.exit()

    key = load_key()

    # Read the file
    with open(filepath, 'rb') as f:
        file_data = f.read()

    filename = os.path.basename(filepath)
    file_hash = calculate_hash(file_data)
    encrypted_data = encrypt_file(file_data, key)

    print(f"[INFO] File: {filename}")
    print(f"[INFO] Original size: {len(file_data)} bytes")
    print(f"[INFO] Encrypted size: {len(encrypted_data)} bytes")
    print(f"[INFO] SHA256 Hash: {file_hash[:20]}...")
    print(f"[INFO] Connecting to server at {host}:{PORT}...\n")

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, PORT))
        print(f"[CONNECTION] Connected to server successfully!")

        # Send filename
        client_socket.send(filename.encode())
        client_socket.recv(BUFFER_SIZE)

        # Send file hash
        client_socket.send(file_hash.encode())
        client_socket.recv(BUFFER_SIZE)

        # Send encrypted file size
        client_socket.send(str(len(encrypted_data)).encode())
        client_socket.recv(BUFFER_SIZE)

        # Send encrypted file data
        print(f"[INFO] Encrypting and sending file...")
        client_socket.sendall(encrypted_data)

        # Wait for server response
        response = client_socket.recv(BUFFER_SIZE).decode()

        if response == 'SUCCESS':
            print(f"[SUCCESS] File transferred securely! ✓")
            print(f"[SUCCESS] Integrity verified by server ✓")
        elif response == 'INTEGRITY_FAILED':
            print(f"[ERROR] Server reported integrity check failed!")
        else:
            print(f"[ERROR] Unexpected server response: {response}")

    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to server. Is it running?")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python client.py <server_ip> <filepath>")
        print("Example: python client.py 127.0.0.1 document.pdf")
        sys.exit()

    host = sys.argv[1]
    filepath = sys.argv[2]

    send_file(host, filepath)