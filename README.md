github link : https://github.com/Mahad811/securechat-skeleton.git

# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository implements a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🧩 Overview

This secure chat system implements all cryptographic operations at the application layer (no TLS/SSL). The system provides:

- **PKI-based mutual authentication** using self-signed certificates
- **Encrypted user registration and login** with salted password hashing
- **Secure chat messaging** with message integrity and replay protection
- **Non-repudiation** through signed transcripts and session receipts

## 🏗️ Architecture

```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 encryption
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models
│  │  └─ utils.py            # Helper functions
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  ├─ gen_cert.py            # Issue client/server certs signed by Root CA
│  ├─ inspect_cert.py        # Certificate inspection (OpenSSL alternative)
│  └─ verify_transcript.py  # Offline transcript and receipt verification
├─ certs/                    # Certificate storage (gitignored)
├─ transcripts/              # Session transcripts (gitignored)
├─ requirements.txt          # Python dependencies
└─ README.md                 # This file
```

## ⚙️ Setup Instructions

### Prerequisites

- Python 3.8 or higher
- MySQL 8.0 or higher (or Docker for MySQL)
- Git

### Step 1: Clone and Install Dependencies

```bash
# Clone the repository
git clone <your-repo-url>
cd securechat-skeleton

# Create virtual environment (optional but recommended)
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Set Up MySQL Database

**Option A: Using Docker (Recommended)**

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

Wait 20-30 seconds for MySQL to initialize, then proceed.

**Option B: Using Local MySQL**

1. Install MySQL Community Server
2. Create database and user:
   ```sql
   CREATE DATABASE securechat;
   CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
   GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
   FLUSH PRIVILEGES;
   ```

### Step 3: Initialize Database Schema

```bash
python -m app.storage.db --init
```

Expected output: `[OK] users table ensured in database`

### Step 4: Generate Certificates

```bash
# Generate Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

### Step 5: Verify Setup

```bash
# Inspect certificates (optional)
python scripts/inspect_cert.py certs/ca_cert.pem
python scripts/inspect_cert.py certs/server_cert.pem
python scripts/inspect_cert.py certs/client_cert.pem
```

## 🚀 Usage

### Starting the Server

```bash
python -m app.server
```

Expected output:
```
[OK] Server certificate loaded and validated
[OK] Server listening on 0.0.0.0:8888
Waiting for connections...
```

### Running the Client

In a separate terminal:

```bash
python -m app.client
```

### Client Workflow

1. **Certificate Exchange**: Automatic mutual authentication
2. **DH Key Exchange**: Establishes AES key for credentials
3. **Registration/Login**:
   - Choose `[r]egister` to create a new account
   - Choose `[l]ogin` to authenticate
4. **Chat Session Key**: Second DH exchange after login
5. **Messaging**: Type messages (encrypted and signed)
6. **Session End**: Type `quit` to end chat and generate receipts

### Example Session

```
Connecting to localhost:8888...
[OK] Connected to server
Sending client certificate...
[OK] Client certificate sent
Waiting for server certificate...
Validating server certificate...
[OK] Server certificate validated successfully
[OK] Certificate exchange completed successfully!
Starting DH key exchange...
[OK] DH key exchange completed; AES session key established
Do you want to [r]egister or [l]ogin? l
Username: mahad
Password: ********
[OK] Login successful
Establishing chat session key...
[OK] Chat session key established
  Ready for encrypted messaging

--- Chat Session Started ---
Type messages (or 'quit' to exit):
You: Hello, this is a test message
You: How are you?
You: quit

--- Chat Session Ended ---
Generating session receipt...
[OK] Session receipt sent
  Transcript hash: abc123...
  Sequence range: 1 - 2
  Transcript saved to: transcripts/client_session_XXXXX.txt
[OK] Received server receipt
  Server transcript hash: def456...
```

## 🔐 Security Features

### Task 2.1: PKI Setup and Certificate Validation

- **Root CA Generation**: Self-signed certificate authority
- **Certificate Issuance**: Server and client certificates signed by CA
- **Mutual Authentication**: Both parties verify each other's certificates
- **Validation Checks**:
  - Signature chain validity (trusted CA)
  - Expiry date and validity period
  - Common Name (CN) match
- **Error Handling**: Rejects self-signed, expired, or untrusted certificates with `BAD_CERT`

### Task 2.2: Registration and Login

- **Confidentiality in Transit**: Credentials encrypted with AES-128 using DH-derived key
- **Key Derivation**: `K = Trunc16(SHA256(big-endian(Ks)))`
- **Secure Storage**: Passwords stored as salted SHA-256 hashes
  - Formula: `pwd_hash = hex(SHA256(salt || password))`
  - 16-byte random salt per user
- **Database Schema**: `users(email, username, salt, pwd_hash)`
- **Login Requirements**: Valid certificate + matching password hash

### Task 2.3: Session Key Establishment

- **Classical Diffie-Hellman**: RFC 3526 MODP Group 14 (2048-bit)
- **Unique Session Keys**: New DH exchange after each login
- **Forward Secrecy**: Each session uses fresh keypair
- **Key Derivation**: Same formula as Task 2.2

### Task 2.4: Encrypted Chat and Message Integrity

- **Encryption**: AES-128 ECB with PKCS#7 padding
- **Message Format**: `{type, seqno, ts, ct, sig}`
- **Integrity**: `h = SHA256(seqno || timestamp || ciphertext)`
- **Signing**: RSA PKCS#1 v1.5 with SHA-256
- **Replay Protection**: Strictly increasing sequence numbers
- **Error Codes**: `SIG_FAIL` (signature failure), `REPLAY` (duplicate seqno)

### Task 2.5: Non-Repudiation

- **Transcript Format**: `seqno | timestamp | ciphertext | sig | peer-cert-fingerprint`
- **Transcript Hash**: `SHA256(concatenation of all log lines)`
- **Session Receipt**: Signed transcript hash with RSA
- **Receipt Format**: `{type, peer, first_seq, last_seq, transcript_sha256, sig}`
- **Offline Verification**: Script verifies all signatures and detects tampering

## 🧪 Testing and Evidence Collection

### Test 1: Certificate Inspection

```bash
python scripts/inspect_cert.py certs/ca_cert.pem
python scripts/inspect_cert.py certs/server_cert.pem
python scripts/inspect_cert.py certs/client_cert.pem
```

**Evidence**: Certificate details (issuer, subject, validity, extensions, signature)

### Test 2: Registration and Login

1. Start server: `python -m app.server`
2. Run client: `python -m app.client`
3. Register a new user
4. Login with the same credentials
5. Verify in MySQL: `SELECT * FROM users;`

**Evidence**: 
- Encrypted credentials in transit (Wireshark)
- Salted hashes in database (no plaintext passwords)

### Test 3: BAD_CERT Error

1. Use an untrusted certificate (e.g., signed by different CA)
2. Server should reject with `BAD_CERT` error

**Evidence**: Server logs showing `ERROR: Client certificate validation failed: ...`

### Test 4: Encrypted Chat

1. Login successfully
2. Send multiple messages
3. Verify messages are encrypted (Wireshark)
4. Check sequence numbers increment

**Evidence**: 
- Encrypted payloads in Wireshark
- Server logs showing decrypted messages
- Sequence numbers: 1, 2, 3, ...

### Test 5: Replay Protection

1. Send a message with seqno=1
2. Try to resend same message (seqno=1)
3. Server should reject with `REPLAY` error

**Evidence**: Server logs showing `ERROR: Replay detected - seqno 1 <= last 1`

### Test 6: Signature Verification Failure

1. Tamper with a message (modify ciphertext)
2. Server should reject with `SIG_FAIL` error

**Evidence**: Server logs showing `ERROR: Signature verification failed`

### Test 7: Transcript Verification

```bash
# Verify client transcript
python scripts/verify_transcript.py \
  --transcript transcripts/client_session_XXXXX.txt \
  --peer-cert certs/client_cert.pem

# Verify server transcript
python scripts/verify_transcript.py \
  --transcript transcripts/server_session_XXXXX.txt \
  --peer-cert certs/client_cert.pem
```

**Evidence**: Verification output showing all messages verified

### Test 8: Tamper Detection

1. Edit a transcript file (change one character)
2. Run verification again
3. Verification should fail

**Evidence**: Verification output showing hash mismatch or signature failure

## 📊 Database Schema

### Users Table

```sql
CREATE TABLE users (
    email      VARCHAR(255) NOT NULL,
    username   VARCHAR(255) NOT NULL UNIQUE,
    salt       VARBINARY(16) NOT NULL,
    pwd_hash   CHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Sample Query**:
```sql
SELECT email, username, HEX(salt) AS salt_hex, pwd_hash FROM users;
```

## 📝 Transcript Format

Each line in the transcript file follows this format:
```
seqno|timestamp|ciphertext|signature|peer-cert-fingerprint
```

Example:
```
1|1763306682723|pcszsTPtll/qW0vtdzQh+A==|FZP8zjmyehvjz4at4yUU0xIUjVsk/...|5f894f63b717a120e5f59390c46af320fb17521093b4919d97762eaac280be3e
```

## 🔍 Verification Scripts

### Certificate Inspection

```bash
python scripts/inspect_cert.py <certificate_path>
```

Shows: Version, serial number, issuer, subject, validity, extensions, signature algorithm.

### Transcript Verification

```bash
python scripts/verify_transcript.py \
  --transcript <transcript_file> \
  --peer-cert <peer_certificate> \
  [--receipt <receipt_json>] \
  [--signer-cert <signer_certificate>]
```

Verifies:
- All message signatures in transcript
- Receipt signature (if provided)
- Detects transcript tampering

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math. Use standard libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables Checklist

- [x] GitHub repository with all code
- [x] MySQL schema dump and sample records
- [x] Updated README.md (this file)
- [ ] Report document (RollNumber-FullName-Report-A02.docx)
- [ ] Test report (RollNumber-FullName-TestReport-A02.docx)

## 🧪 Test Evidence Checklist

- [x] Wireshark capture (encrypted payloads only)
- [x] Invalid/self-signed cert rejected (`BAD_CERT`)
- [x] Tamper test → signature verification fails (`SIG_FAIL`)
- [x] Replay test → rejected by seqno (`REPLAY`)
- [x] Non-repudiation → exported transcript + signed SessionReceipt verified offline

## 📚 Implementation Details

### Cryptographic Primitives Used

- **RSA**: 2048-bit keys for certificates and signatures
- **AES-128**: ECB mode with PKCS#7 padding
- **Diffie-Hellman**: RFC 3526 MODP Group 14 (2048-bit)
- **SHA-256**: For hashing (passwords, message integrity, transcript hash)
- **X.509**: For certificate format

### Key Derivation

All AES keys are derived using:
```
K = Trunc16(SHA256(big-endian(Ks)))
```

Where `Ks` is the Diffie-Hellman shared secret.

### Password Storage

Passwords are stored as:
```
pwd_hash = hex(SHA256(salt || password))
```

Where `salt` is a 16-byte random value generated per user.

## 🐛 Troubleshooting

### "ModuleNotFoundError: No module named 'app'"

Run commands from the project root directory, or use:
```bash
python -m scripts.verify_transcript ...
```

### "Access denied for user 'scuser'@'localhost'"

- Check MySQL is running
- Verify database and user exist
- Check credentials match (scuser/scpass)

### "Certificate not found"

Run certificate generation scripts:
```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client
```

### "Connection refused"

- Ensure server is running first
- Check server is listening on port 8888
- Verify firewall settings

## 📄 License

This project is part of CS-3002 Information Security course assignment.

## 👤 Author

[Your Name]  
[Your Roll Number]  
FAST-NU

---

**Note**: This implementation demonstrates all security properties (CIANR) through application-layer cryptography without using TLS/SSL.
