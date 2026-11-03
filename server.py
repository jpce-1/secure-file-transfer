import socket
import hashlib
import hmac
import os
import tempfile
from cryptography.fernet import Fernet, InvalidToken
from transfer_protocol import (
    MAX_ENCRYPTED_SIZE,
    MAX_FILENAME_SIZE,
    MAX_FILE_SIZE,
    SOCKET_TIMEOUT,
    ProtocolError,
    receive_exact,
    receive_frame,
    send_frame,
    validate_filename,
)

# ── Configuration ──────────────────────────────────────
HOST = '0.0.0.0'   # Listen on all network interfaces
PORT = 5001        # Port to listen on
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
    return hmac.compare_digest(calculated_hash, received_hash)


def save_file(filename, file_data):
    validate_filename(filename)
    save_folder = os.path.abspath(SAVE_FOLDER)
    os.makedirs(save_folder, exist_ok=True)
    save_path = os.path.abspath(os.path.join(save_folder, filename))
    if os.path.commonpath((save_folder, save_path)) != save_folder:
        raise ProtocolError("Invalid filename")

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=save_folder, delete=False) as temporary_file:
            temporary_path = temporary_file.name
            temporary_file.write(file_data)
        os.replace(temporary_path, save_path)
    except OSError:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
        raise
    return save_path


def handle_client(client_socket, key):
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)
        filename_bytes = receive_frame(client_socket, MAX_FILENAME_SIZE)
        filename = filename_bytes.decode("utf-8")
        validate_filename(filename)

        received_hash = receive_frame(client_socket, 64).decode("ascii")
        if len(received_hash) != 64 or any(char not in "0123456789abcdef" for char in received_hash):
            raise ProtocolError("Invalid SHA256 hash")

        encrypted_size = int.from_bytes(receive_exact(client_socket, 8), "big")
        if encrypted_size == 0 or encrypted_size > MAX_ENCRYPTED_SIZE:
            raise ProtocolError("Transfer exceeds the maximum allowed size")
        print(f"[INFO] Incoming file: {filename}")
        print(f"[INFO] Encrypted file size: {encrypted_size} bytes")

        encrypted_data = receive_exact(client_socket, encrypted_size)
        file_data = decrypt_file(encrypted_data, key)
        if len(file_data) > MAX_FILE_SIZE:
            raise ProtocolError("Decrypted file exceeds the maximum allowed size")

        if not verify_integrity(file_data, received_hash):
            send_frame(client_socket, b"INTEGRITY_FAILED")
            print("[ERROR] Integrity check failed! File may be corrupted.\n")
            return

        save_path = save_file(filename, file_data)
        send_frame(client_socket, b"SUCCESS")
        print(f"[SUCCESS] File saved to {save_path}")
        print("[SUCCESS] File integrity verified\n")
    except (OSError, UnicodeError, InvalidToken, ValueError) as e:
        print(f"[ERROR] Transfer failed: {e}")
        try:
            send_frame(client_socket, b"ERROR")
        except OSError as send_error:
            print(f"[ERROR] Could not notify client: {send_error}")


def start_server():
    key = load_or_create_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    with server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)

        print(f"[SERVER] Secure File Transfer Server started on port {PORT}")
        print(f"[SERVER] Waiting for incoming files...\n")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"[CONNECTION] Connected to {client_address[0]}:{client_address[1]}")
            with client_socket:
                handle_client(client_socket, key)


if __name__ == '__main__':
    start_server()