import os
import socket

HEADER_SIZE = 4
MAX_FIELD_SIZE = 1024
MAX_FILENAME_SIZE = 255
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_ENCRYPTED_SIZE = 4 * ((MAX_FILE_SIZE + 128 + 2) // 3)
SOCKET_TIMEOUT = 30
CONNECT_TIMEOUT = 10
BUFFER_SIZE = 4096


class ProtocolError(ValueError):
    pass


def send_frame(sock, data):
    if len(data) > MAX_FIELD_SIZE:
        raise ProtocolError("Frame exceeds the maximum allowed size")
    sock.sendall(len(data).to_bytes(HEADER_SIZE, "big"))
    sock.sendall(data)


def receive_exact(sock, size):
    if size < 0:
        raise ProtocolError("Invalid field size")

    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(min(size - len(chunks), BUFFER_SIZE))
        if not chunk:
            raise ConnectionError("Connection closed before the transfer was complete")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_frame(sock, max_size=MAX_FIELD_SIZE):
    size = int.from_bytes(receive_exact(sock, HEADER_SIZE), "big")
    if size > max_size:
        raise ProtocolError("Frame exceeds the maximum allowed size")
    return receive_exact(sock, size)


def validate_filename(filename):
    if (
        not filename
        or filename in {".", ".."}
        or any(char in filename for char in ("/", "\\", ":", "\0"))
        or any(ord(char) < 32 or ord(char) == 127 for char in filename)
        or os.path.basename(filename) != filename
    ):
        raise ProtocolError("Invalid filename")

    try:
        encoded = filename.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProtocolError("Filename must be valid UTF-8") from exc

    if len(encoded) > MAX_FILENAME_SIZE:
        raise ProtocolError("Filename exceeds the maximum allowed size")
