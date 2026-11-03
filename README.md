#  Secure File Transfer System

A Python-based secure file transfer program that encrypts files before sending them over a network — ensuring privacy, security and integrity of transferred data.

---

##  Features

-  **End-to-end encryption** — files are encrypted using Fernet symmetric encryption before transfer
-  **File integrity verification** — SHA256 hashing ensures files arrive uncorrupted and untampered
-  **Any file type** — transfer PDFs, images, text files and more
-  **Simple CLI interface** — easy to use from the terminal
-  **Network ready** — works over local network between any two computers
-  **Bounded transfers** — rejects files larger than 100 MiB and times out stalled connections

---

##  Tech Stack

- **Python** — core language
- **Socket** — built-in Python networking library
- **Cryptography (Fernet)** — symmetric file encryption
- **Hashlib** — SHA256 file integrity verification

---

##  Installation

**1. Clone the repo**

    git clone https://github.com/YOUR_USERNAME/secure-file-transfer.git
    cd secure-file-transfer

**2. Create and activate virtual environment**

    python -m venv venv
    venv\Scripts\activate

**3. Install dependencies**

    pip install -r requirements.txt

Run the transfer tests with:

    python -m unittest discover -s tests -v

---

##  How to Use

**Step 1 — Start the server on the receiving computer**

    python server.py

This generates a secret.key file automatically on first run.

**Step 2 — Copy secret.key to the sending computer**

Both computers must share the same key to encrypt and decrypt files.

**Step 3 — Send a file from the client**

    python client.py <server_ip> <filepath>

Example:

    python client.py 192.168.1.5 document.pdf

For testing on the same machine use:

    python client.py 127.0.0.1 secret.txt

The client and server must use the same version of the transfer protocol. The
protocol uses length-prefixed metadata and file-size framing; each connection
times out after 30 seconds without network activity.

---

##  How the Security Works

    Sender                          Receiver
      |                                 |
      |-- 1. Read file                  |
      |-- 2. Calculate SHA256 hash      |
      |-- 3. Encrypt with Fernet key    |
      |-- 4. Send over network -------> |
      |                                 |-- 5. Receive encrypted data
      |                                 |-- 6. Decrypt with Fernet key
      |                                 |-- 7. Verify SHA256 hash
      |                                 |-- 8. Save file safely

- **Fernet encryption** ensures nobody can read the file in transit
- **SHA256 hashing** ensures the file was not modified during transfer

---

##  Project Structure

    secure-file-transfer/
    ├── server.py          # Receiving side — decrypts and saves files
    ├── client.py          # Sending side — encrypts and transfers files
    ├── transfer_protocol.py # Shared framed TCP protocol and limits
    ├── tests/             # Transfer protocol and server tests
    ├── secret.key         # Shared encryption key (auto-generated)
    ├── received_files/    # Folder where received files are saved
    ├── requirements.txt
    └── README.md

---

##  Future Improvements

- [ ] Password protected key exchange
- [ ] GUI interface
- [ ] Transfer multiple files at once
- [ ] Progress bar for large files
- [ ] HTTPS/TLS support

---

##  Author

**JP** — [GitHub](https://github.com/jpce-1) · [LinkedIn](https://www.linkedin.com/in/johnpaul-ehiemere-22563b397/)

---

## 📄 License

MIT License
