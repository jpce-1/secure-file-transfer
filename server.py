import socket
import hashlib
import os
from cryptography.fernet import Fernet

# ── Configuration ──────────────────────────────────────
HOST = '0.0.0.0'   # Listen on all network interfaces
PORT = 5001        # Port to listen on
BUFFER_SIZE = 4096 # How much data to receive at once
SAVE_FOLDER = 'received_files'  # Where to save received files
KEY_FILE = 'secret.key'  # Encryption key file
# ───────────────────────────────────────────────────────


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        print(f"[KEY] New encryption key created and saved to {KEY_FILE}")
        return key


def decrypt_file(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)


def verify_integrity(file_data, received_hash):
    calculated_hash = hashlib.sha256(file_data).hexdigest()
    return calculated_hash == received_hash


def start_server():
    key = load_or_create_key()

    if not os.path.exists(SAVE_FOLDER):
        os.makedirs(SAVE_FOLDER)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"[SERVER] Secure File Transfer Server started on port {PORT}")
    print(f"[SERVER] Waiting for incoming files...\n")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[CONNECTION] Connected to {client_address[0]}:{client_address[1]}")

        try:
            # Receive filename
            filename = client_socket.recv(BUFFER_SIZE).decode()
            client_socket.send(b'OK')
            print(f"[INFO] Incoming file: {filename}")

            # Receive file hash
            received_hash = client_socket.recv(BUFFER_SIZE).decode()
            client_socket.send(b'OK')

            # Receive file size
            file_size = int(client_socket.recv(BUFFER_SIZE).decode())
            client_socket.send(b'OK')
            print(f"[INFO] File size: {file_size} bytes")

            # Receive encrypted file data
            encrypted_data = b''
            while len(encrypted_data) < file_size:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                encrypted_data += chunk

            print(f"[INFO] File received, decrypting...")

            # Decrypt the file
            file_data = decrypt_file(encrypted_data, key)

            # Verify integrity
            if verify_integrity(file_data, received_hash):
                save_path = os.path.join(SAVE_FOLDER, filename)
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                client_socket.send(b'SUCCESS')
                print(f"[SUCCESS] File saved to {save_path}")
                print(f"[SUCCESS] File integrity verified ✓\n")
            else:
                client_socket.send(b'INTEGRITY_FAILED')
                print(f"[ERROR] Integrity check failed! File may be corrupted.\n")

        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            client_socket.close()


if __name__ == '__main__':
    start_server()