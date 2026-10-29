# 🔒 Secure WLAN File Sharing — Academic Project Documentation

An end-to-end, peer-to-peer desktop file-sharing application designed for secure local Wi-Fi/WLAN network communication without relying on cloud services, web servers, or external third-party infrastructure.

---

## 📌 Abstract

In local network environments (WLAN/LAN), transferring files securely between two endpoints often exposes data to eavesdropping, packet sniffing, or unauthorized access. Standard unencrypted protocols like HTTP, FTP, or plain TCP sockets transmit data in plaintext. This project presents **Secure WLAN File Sharing**, a Python desktop application that implements **Hybrid Encryption** (combining **AES-256-GCM** authenticated symmetric encryption with **RSA-2048 OAEP** asymmetric key exchange) and **SHA-256** file integrity verification over TCP sockets with a clean Tkinter GUI.

---

## 🎯 Objectives & Features

* **Zero Cloud Dependency:** Operates strictly over local Wi-Fi / WLAN IP networks.
* **Hybrid Cryptographic Architecture:**
  * **AES-256-GCM:** Authenticated Encryption with Associated Data (AEAD) for fast, chunked file encryption.
  * **RSA-2048 with OAEP Padding:** Asymmetric encryption protecting the fresh, random AES session key.
  * **SHA-256 Digest:** Explicit end-to-end file integrity verification.
* **User Authentication:** PBKDF2-HMAC-SHA256 salted password hashing before transfer initiation.
* **Memory Efficient:** Streaming chunk-based transfer (64 KB chunks) handling arbitrarily large binary files (PDF, JPG, PNG, TXT, ZIP, DOCX, etc.).
* **Path Traversal Protection:** Input sanitization ensuring received files remain within the `received_files/` directory.
* **Non-Blocking Multithreaded GUI:** Built with Tkinter and Python `threading` so progress bars and log outputs update smoothly without UI freezes.

---

## 🏗 System Architecture & Workflow

### Hybrid Encryption Flow

```
+---------------------------------------------------------------------------------------+
|                                    SENDER COMPUTER                                    |
|                                                                                       |
|  1. Select File ---> 2. Compute SHA-256 Hash Digest                                   |
|  3. Generate Fresh 256-bit AES Session Key & 96-bit Nonce                              |
|  4. Encrypt File Content using AES-256-GCM ----> Produces Ciphertext + 16-byte Tag    |
|  5. Encrypt AES Key with Receiver's RSA Public Key (RSA-OAEP)                         |
|  6. Transmit: [Encrypted AES Key | Nonce | Tag | Metadata | SHA-256] over TCP Socket   |
+---------------------------------------------------------------------------------------+
                                        |  (WLAN TCP/IP Socket Stream)
                                        v
+---------------------------------------------------------------------------------------+
|                                   RECEIVER COMPUTER                                   |
|                                                                                       |
|  1. Listen on Port (Default: 5000)                                                     |
|  2. Authenticate Sender Credentials (PBKDF2-HMAC-SHA256)                              |
|  3. Provide RSA Public Key to Authenticated Sender                                   |
|  4. Decrypt AES Session Key using Receiver's RSA Private Key                          |
|  5. Decrypt Payload & Verify AES-GCM Auth Tag ---> Rejects Tampered Payload           |
|  6. Calculate SHA-256 of Decrypted File & Compare ---> Rejects Corrupted Files        |
|  7. Save Verified File into 'received_files/' Directory                               |
+---------------------------------------------------------------------------------------+
```

---

## 🛠 Technical Stack & Dependencies

* **Language:** Python 3.8+
* **GUI Framework:** Tkinter / ttk (Built-in Python Standard Library)
* **Cryptography Engine:** `cryptography` (OpenSSL backend)
* **Networking Protocol:** Standard Python `socket` module (TCP IPv4)
* **Threading:** `threading` module for asynchronous non-blocking event loops

---

## 📁 Project Folder Structure

```
Secure_WLAN_File_Sharing/
│
├── sender.py              # Sender GUI application & transfer logic
├── receiver.py            # Receiver GUI application & TCP server logic
├── main.py                # Combined GUI launcher & mode selector
├── crypto_utils.py        # Cryptographic functions (RSA, AES-GCM, SHA-256)
├── network_utils.py       # TCP socket helpers, IP discovery, protocol framing
├── auth.py                # PBKDF2 user authentication management
├── config.py              # Application settings, ports, chunk sizes, paths
├── test_transfer.py       # Integration test suite
├── requirements.txt       # Python dependencies list
├── README.md              # Project documentation & viva guide
├── keys/                  # RSA Key Pair storage directory
└── received_files/        # Destination directory for verified received files
```

---

## 🚀 Installation & Setup Instructions

### 1. Prerequisites
Ensure Python 3.8 or higher is installed on both Sender and Receiver computers. Verify installation:
```bash
python --version
```

### 2. Install Dependencies
Open Command Prompt or Terminal inside the project directory and run:
```bash
pip install -r requirements.txt
```

---

## 💻 How to Run the Application

### Option A: Using the Launcher
Run the unified launcher to select Sender or Receiver mode:
```bash
python main.py
```

### Option B: Running Receiver (Server Computer)
On the computer designated to receive files:
```bash
python receiver.py
```
1. Note the **Receiver IPv4 Address** displayed at the top (e.g. `192.168.1.105`).
2. Click **▶ Start Server**.

### Option C: Running Sender (Client Computer)
On the computer sending the file:
```bash
python sender.py
```
1. Enter the Receiver's IPv4 address.
2. Enter Username (`admin`) and Password (`securepassword123`).
3. Click **📁 Browse File...** to select your file.
4. Click **🚀 Send File Securely**.

---

## 🌐 Connecting Two Computers over Wi-Fi / WLAN

1. Connect both computers to the **same Wi-Fi router** or mobile hotspot.
2. On the Receiver machine, open Command Prompt and find your local IPv4 address:
   ```cmd
   ipconfig
   ```
   Look for **Wireless LAN adapter Wi-Fi** -> **IPv4 Address** (e.g. `192.168.1.50`).
3. On the Sender machine, enter `192.168.1.50` into the Receiver IP input field in `sender.py`.
4. Ensure Windows Firewall permits Python on Port 5000 (a popup prompt may appear on first run; select *Allow Access on Private Networks*).

---

## 🧪 Testing Procedure & Expected Behaviors

| Test # | Test Scenario | Steps | Expected Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **TXT File Transfer** | Send a `.txt` document | Receiver verifies SHA-256, saves to `received_files/` | PASS |
| 2 | **PDF File Transfer** | Send a `.pdf` document | Document transferred and validated intact | PASS |
| 3 | **Image File Transfer** | Send `.jpg`/`.png` image | Image opens cleanly without artifacting | PASS |
| 4 | **Large Binary File** | Send 50 MB+ ZIP/video | Progress bar updates continuously, memory usage stays low | PASS |
| 5 | **Wrong Receiver IP** | Connect to unused IP (e.g. `192.168.1.250`) | Connection timeout error reported in GUI log | PASS |
| 6 | **Receiver Not Running** | Connect while Receiver server is stopped | "Connection Refused" alert displayed | PASS |
| 7 | **Wrong Credentials** | Enter incorrect password | Receiver responds "AUTH_FAILED", transfer aborted | PASS |
| 8 | **Corrupted Encrypted Data** | Modify ciphertext payload in transit | AES-GCM tag check fails, file deleted, alert logged | PASS |
| 9 | **AES-GCM Auth Failure** | Modify tag header bytes | `InvalidTag` exception triggered, file rejected | PASS |
| 10 | **SHA-256 Mismatch** | Tamper with decrypted payload | SHA-256 hash mismatch alert, file deleted | PASS |
| 11 | **Multiple Sequential Transfers** | Transfer 5 files in succession | Server handles all connections seamlessly | PASS |
| 12 | **Connection Interruption** | Disconnect Wi-Fi during transfer | Graceful socket timeout cleanup, no partial file saved | PASS |

---

## 🎓 Academic Viva Questions & Detailed Answers

### Q1. What is the main objective of this project?
**Answer:** The objective is to design and implement a secure, peer-to-peer file transfer desktop application for local WLAN networks that guarantees **Confidentiality**, **Integrity**, and **Authentication** without relying on third-party cloud storage or external servers.

### Q2. Why did you use Hybrid Encryption instead of pure RSA or pure AES?
**Answer:** Asymmetric encryption (RSA) is computationally expensive and restricted by key size (a 2048-bit RSA key can only encrypt up to 214 bytes under OAEP padding). Symmetric encryption (AES) is extremely fast and suitable for bulk data, but requires a pre-shared key. Hybrid encryption combines the best of both: AES-256-GCM encrypts the large file data rapidly, and RSA-2048 OAEP securely encrypts only the fresh 256-bit AES session key.

### Q3. Why use AES-GCM mode instead of AES-CBC or AES-ECB?
**Answer:** 
* **ECB (Electronic Codebook)** is insecure because identical plaintext blocks produce identical ciphertext blocks, revealing data patterns.
* **CBC (Cipher Block Chaining)** requires padding (like PKCS7) and provides confidentiality only; it does not protect against ciphertext modification (malleability attacks).
* **GCM (Galois/Counter Mode)** is an Authenticated Encryption with Associated Data (AEAD) mode. It provides both confidentiality and built-in authenticity via a 16-byte Galois authentication tag. Any tampering with the ciphertext causes tag verification to fail.

### Q4. What is the role of the 12-byte Nonce in AES-GCM?
**Answer:** A Nonce (Number used ONCE) ensures that encrypting the exact same plaintext multiple times yields completely distinct ciphertexts. A fresh random 12-byte nonce is generated for every transfer session to prevent replay attacks and key stream reuse.

### Q5. Why is RSA-OAEP padding necessary?
**Answer:** Plain RSA (textbook RSA) is deterministic and vulnerable to mathematical attacks. OAEP (Optimal Asymmetric Encryption Padding) adds random padding and probabilistic hashing (SHA-256 MGF1) prior to RSA exponentiation, making the encryption semantically secure against Chosen Ciphertext Attacks (CCA2).

### Q6. Does the Receiver's RSA Private Key ever travel across the network?
**Answer:** No. The RSA private key is generated and stored exclusively on the Receiver machine (`keys/receiver_private.pem`). Only the RSA **Public Key** is transmitted to the Sender during the authentication handshake.

### Q7. Why is SHA-256 calculated when AES-GCM already includes an authentication tag?
**Answer:** AES-GCM verifies ciphertext authenticity at the cryptographic layer. Calculating an explicit end-to-end SHA-256 hash digest of the original plaintext file provides defense-in-depth, verifying that the entire end-to-end pipeline (file reading, encryption, TCP transmission, decryption, file writing) preserved 100% data integrity.

### Q8. How does the application prevent GUI freezing during file transfers?
**Answer:** File transfers run inside background worker threads using Python's `threading` module. The main thread manages Tkinter UI event loops, while the worker thread handles socket I/O, crypto, and schedules UI updates safely using `root.after()`.

### Q9. How are large files handled without consuming excessive RAM?
**Answer:** Files are processed in **64 KB chunks** (`config.CHUNK_SIZE`). Both sender and receiver stream data sequentially through crypto functions and TCP sockets, maintaining low memory usage even for multi-gigabyte files.

### Q10. How does the protocol prevent Path Traversal attacks?
**Answer:** Attackers could send filenames like `../../Windows/System32/malicious.exe`. The receiver passes all incoming filenames through `network_utils.sanitize_filename()`, which strips path separators, drive letters, and relative directory symbols (`..`), keeping saved files strictly inside `received_files/`.

### Q11. How are duplicate filenames handled on the Receiver?
**Answer:** The receiver uses `network_utils.get_safe_filepath()`. If `report.pdf` already exists, it automatically renames incoming files to `report_1.pdf`, `report_2.pdf`, preventing accidental file overwrites.

### Q12. How does the application handle partial TCP reads?
**Answer:** TCP is a stream-based protocol, meaning `socket.recv()` might return fewer bytes than requested. The application uses `network_utils.recv_exact()`, which loops until the exact expected byte count is accumulated in a byte buffer.

### Q13. How does the custom application protocol structure messages?
**Answer:** Messages use **Length-Prefixed Framing**. Every control packet begins with a 4-byte big-endian integer indicating the length of the subsequent UTF-8 JSON payload. This allows the receiver to accurately delimit metadata headers from raw encrypted binary data streams.

### Q14. How are passwords stored and verified?
**Answer:** Passwords are not stored in plaintext. `auth.py` uses **PBKDF2-HMAC-SHA256** with a 16-byte random salt and 100,000 iterations to derive a secure password hash. Verification uses constant-time comparison (`secrets.compare_digest`) to prevent timing side-channel attacks.

### Q15. What happens if an attacker tampers with a single byte of the encrypted file during transit?
**Answer:** When the receiver executes `StreamingAESGCMDecryptor.finalize()`, OpenSSL computes the Galois field multiplication tag over the received ciphertext. If any byte was altered, `finalize()` raises an `InvalidTag` exception. The receiver immediately aborts, deletes temporary files, alerts the user, and does not save the file.

### Q16. Can an attacker intercept the file on Wi-Fi using Wireshark?
**Answer:** Wireshark can capture the raw TCP packets, but the payload consists exclusively of AES-256-GCM encrypted ciphertext. Because the AES session key is encrypted with the receiver's RSA-2048 public key, an eavesdropper cannot recover the AES key or decrypt the file without the receiver's private key.

### Q17. How does the system discover its local IPv4 address?
**Answer:** `network_utils.get_local_ip()` creates a UDP socket directed towards `8.8.8.8:80` (without sending data) and inspects `getsockname()[0]`. This queries the Operating System routing table to return the active local WLAN interface IP.

### Q18. What is the difference between Symmetric and Asymmetric Encryption?
**Answer:** Symmetric encryption (AES) uses the same key for encryption and decryption, offering high speed. Asymmetric encryption (RSA) uses a key pair (Public Key for encryption, Private Key for decryption), solving key distribution problems at lower speed.

### Q19. What python library is used for cryptography?
**Answer:** The `cryptography` library (PyCA), which provides high-level primitives and binding to OpenSSL C libraries.

### Q20. Is this application production-grade?
**Answer:** It is an academic prototype demonstrating core cryptographic principles, socket network programming, and GUI design. A production system would require TLS 1.3 socket wrapping, PKI certificate authority validation, mutual certificate authentication, and persistent encrypted storage.

---

## 🔧 Troubleshooting Guide

| Problem | Possible Cause | Solution |
| :--- | :--- | :--- |
| **`ConnectionRefusedError`** | Receiver server is not running or wrong port entered | Ensure `receiver.py` is started and listening on the specified port. |
| **`socket.timeout`** | Windows Firewall blocking connection | Open Windows Firewall -> Allow app through firewall -> Enable Private networks for Python. |
| **`InvalidTag` Exception** | Data corrupted or tampered over Wi-Fi | Re-try transfer; check Wi-Fi signal quality. |
| **`ModuleNotFoundError: cryptography`** | Package not installed | Run `pip install cryptography` or `python -m pip install cryptography`. |
| **IP Address shows `127.0.0.1`** | Wi-Fi adapter disconnected | Connect to a Wi-Fi network or mobile hotspot and restart app. |

---

## 📜 License & Academic Integrity
Developed as an engineering / ECE academic project demonstrating applied cryptography, computer networking, and Python desktop application development.
