import hashlib
import io
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cryptography.fernet import Fernet

import client
import server
from transfer_protocol import (
    MAX_ENCRYPTED_SIZE,
    MAX_FILE_SIZE,
    ProtocolError,
    receive_exact,
    receive_frame,
    send_frame,
    validate_filename,
)


class TransferProtocolTests(unittest.TestCase):
    def test_receive_exact_handles_fragmented_data(self):
        fragmented_socket = unittest.mock.Mock()
        fragmented_socket.recv.side_effect = [b"a", b"bc"]
        self.assertEqual(receive_exact(fragmented_socket, 3), b"abc")

    def test_receive_frame_handles_fragmented_header_and_payload(self):
        fragmented_socket = unittest.mock.Mock()
        fragmented_socket.recv.side_effect = [
            b"\x00",
            b"\x00",
            b"\x00",
            b"\x03",
            b"a",
            b"bc",
        ]
        self.assertEqual(receive_frame(fragmented_socket), b"abc")

    def test_receive_frame_rejects_oversized_field(self):
        receiver, sender = socket.socketpair()
        try:
            sender.sendall((5).to_bytes(4, "big"))
            with self.assertRaises(ProtocolError):
                receive_frame(receiver, max_size=4)
        finally:
            receiver.close()
            sender.close()

    def test_receive_exact_rejects_truncated_data(self):
        receiver, sender = socket.socketpair()
        try:
            sender.sendall(b"ab")
            sender.shutdown(socket.SHUT_WR)
            with self.assertRaises(ConnectionError):
                receive_exact(receiver, 3)
        finally:
            receiver.close()
            sender.close()

    def test_validate_filename_rejects_paths_and_invalid_names(self):
        for filename in ("", ".", "..", "../secret.txt", r"..\secret.txt", "C:secret.txt"):
            with self.subTest(filename=filename):
                with self.assertRaises(ProtocolError):
                    validate_filename(filename)

    def test_encrypted_size_limit_allows_fernet_overhead(self):
        self.assertGreater(MAX_ENCRYPTED_SIZE, MAX_FILE_SIZE)


class ServerTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def _run_transfer(self, filename, data, *, declared_size=None, hash_value=None):
        receiver, sender = socket.socketpair()
        key = Fernet.generate_key()
        server_thread = threading.Thread(
            target=server.handle_client,
            args=(receiver, key),
        )
        server_thread.start()
        try:
            send_frame(sender, filename.encode("utf-8"))
            send_frame(sender, (hash_value or hashlib.sha256(data).hexdigest()).encode("ascii"))
            encrypted = Fernet(key).encrypt(data)
            sender.sendall((declared_size if declared_size is not None else len(encrypted)).to_bytes(8, "big"))
            if declared_size is None:
                sender.sendall(encrypted)
            response = receive_frame(sender)
        finally:
            sender.close()
            server_thread.join(timeout=2)
            if server_thread.is_alive():
                receiver.close()
                self.fail("Server transfer handler did not finish")
            receiver.close()
        return response

    def test_valid_transfer_saves_file(self):
        data = b"example file contents"
        with patch.object(server, "SAVE_FOLDER", self.temp_dir.name):
            response = self._run_transfer("example.txt", data)

        self.assertEqual(response, b"SUCCESS")
        with open(os.path.join(self.temp_dir.name, "example.txt"), "rb") as saved_file:
            self.assertEqual(saved_file.read(), data)

    def test_invalid_filename_is_rejected_without_writing_outside_folder(self):
        with patch.object(server, "SAVE_FOLDER", self.temp_dir.name):
            response = self._run_transfer("../outside.txt", b"do not save")

        self.assertEqual(response, b"ERROR")
        self.assertEqual(os.listdir(self.temp_dir.name), [])

    def test_oversized_transfer_is_rejected_before_receiving_payload(self):
        oversized = MAX_ENCRYPTED_SIZE + 1
        with patch.object(server, "SAVE_FOLDER", self.temp_dir.name):
            response = self._run_transfer("large.bin", b"", declared_size=oversized)

        self.assertEqual(response, b"ERROR")

    def test_integrity_mismatch_does_not_save_file(self):
        with patch.object(server, "SAVE_FOLDER", self.temp_dir.name):
            response = self._run_transfer("example.txt", b"contents", hash_value="0" * 64)

        self.assertEqual(response, b"INTEGRITY_FAILED")
        self.assertFalse(os.path.exists(os.path.join(self.temp_dir.name, "example.txt")))

    def test_client_and_server_complete_a_transfer(self):
        data = b"sent through the client"
        key = Fernet.generate_key()
        receiver, sender = socket.socketpair()
        server_thread = threading.Thread(target=server.handle_client, args=(receiver, key))
        server_thread.start()
        try:
            with tempfile.NamedTemporaryFile(delete=False) as source_file:
                source_file.write(data)
                source_path = source_file.name
            self.addCleanup(os.unlink, source_path)
            with patch.object(client, "load_key", return_value=key), patch.object(
                client.socket,
                "create_connection",
                return_value=sender,
            ), patch.object(server, "SAVE_FOLDER", self.temp_dir.name):
                with redirect_stdout(io.StringIO()):
                    client.send_file("localhost", source_path)
        finally:
            server_thread.join(timeout=2)
            if server_thread.is_alive():
                sender.close()
                receiver.close()
                self.fail("Server transfer handler did not finish")
            sender.close()
            receiver.close()

        with open(os.path.join(self.temp_dir.name, os.path.basename(source_path)), "rb") as saved_file:
            self.assertEqual(saved_file.read(), data)


if __name__ == "__main__":
    unittest.main()
