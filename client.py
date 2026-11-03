import socket
import hashlib
import os
import sys
from cryptography.fernet import Fernet
from transfer_protocol import (
    CONNECT_TIMEOUT,
    MAX_FILE_SIZE,
    SOCKET_TIMEOUT,
    ProtocolError,
    receive_frame,
    send_frame,
    validate_filename,
)

# ── Configuration ──────────────────────────────────────
PORT = 5001        # Must match server port
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
    if not os.path.isfile(filepath):
        print(f"[ERROR] File '{filepath}' not found!")
        sys.exit()

    key = load_key()

    with open(filepath, 'rb') as f:
        file_data = f.read(MAX_FILE_SIZE + 1)
    if len(file_data) > MAX_FILE_SIZE:
        print(f"[ERROR] File exceeds the {MAX_FILE_SIZE}-byte transfer limit.")
        return

    filename = os.path.basename(filepath)
    try:
        validate_filename(filename)
    except ProtocolError as e:
        print(f"[ERROR] {e}")
        return

    file_hash = calculate_hash(file_data)
    encrypted_data = encrypt_file(file_data, key)

    print(f"[INFO] File: {filename}")
    print(f"[INFO] Original size: {len(file_data)} bytes")
    print(f"[INFO] Encrypted size: {len(encrypted_data)} bytes")
    print(f"[INFO] SHA256 Hash: {file_hash[:20]}...")
    print(f"[INFO] Connecting to server at {host}:{PORT}...\n")

    try:
        with socket.create_connection((host, PORT), timeout=CONNECT_TIMEOUT) as client_socket:
            client_socket.settimeout(SOCKET_TIMEOUT)
            print(f"[CONNECTION] Connected to server successfully!")

            send_frame(client_socket, filename.encode("utf-8"))
            send_frame(client_socket, file_hash.encode("ascii"))
            client_socket.sendall(len(encrypted_data).to_bytes(8, "big"))
            client_socket.sendall(encrypted_data)

            response = receive_frame(client_socket)

        if response == b'SUCCESS':
            print(f"[SUCCESS] File transferred securely! ✓")
            print(f"[SUCCESS] Integrity verified by server ✓")
        elif response == b'INTEGRITY_FAILED':
            print(f"[ERROR] Server reported integrity check failed!")
        elif response == b'ERROR':
            print(f"[ERROR] Server rejected the transfer.")
        else:
            print(f"[ERROR] Unexpected server response: {response.decode('utf-8', errors='replace')}")

    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to server. Is it running?")
    except (OSError, ProtocolError) as e:
        print(f"[ERROR] {e}")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python client.py <server_ip> <filepath>")
        print("Example: python client.py 127.0.0.1 document.pdf")
        sys.exit()

    host = sys.argv[1]
    filepath = sys.argv[2]

    send_file(host, filepath)