# SecureChat System - Assignment Report
## CS-3002 Information Security, Fall 2025

**Student Name:** [Your Name]  
**Roll Number:** [Your Roll Number]  
**Institution:** FAST-NU  
**Date:** [Current Date]

---

## 1. Introduction

### 1.1 Overview

This report documents the design, implementation, and security analysis of a **SecureChat System**—a console-based, PKI-enabled secure messaging application built entirely at the application layer without using TLS/SSL. The system demonstrates how cryptographic primitives can be combined to achieve the four fundamental security properties: **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

### 1.2 Objectives

The primary objectives of this project were to:

1. **Implement Public Key Infrastructure (PKI)** for mutual authentication between client and server
2. **Secure User Registration and Login** with encrypted credential transmission and salted password storage
3. **Establish Secure Session Keys** using Diffie-Hellman key exchange
4. **Enable Encrypted Chat Messaging** with message integrity verification and replay protection
5. **Provide Non-Repudiation** through signed transcripts and session receipts

### 1.3 Security Requirements

The system must ensure:

- **Confidentiality**: All sensitive data (credentials, messages) encrypted in transit
- **Integrity**: Message tampering detected through cryptographic signatures
- **Authenticity**: Both parties authenticated via PKI certificates
- **Non-Repudiation**: Signed transcripts prevent denial of communication

### 1.4 Implementation Constraints

- **No TLS/SSL**: All cryptographic operations implemented explicitly at the application layer
- **Standard Libraries**: Use of `cryptography` library for AES, RSA, and X.509 operations
- **Plain TCP**: Communication over unencrypted TCP sockets
- **Application-Layer Security**: Certificate exchange, key agreement, encryption, and signatures handled in application code

---

## 2. System Architecture & Design

### 2.1 High-Level Architecture

The SecureChat system follows a **client-server architecture** with the following components:

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
│             │                    │             │
│  - PKI      │◄───TCP Socket─────►│  - PKI      │
│  - DH       │                    │  - DH       │
│  - AES      │                    │  - AES      │
│  - RSA      │                    │  - RSA      │
│  - MySQL    │                    │  - MySQL    │
│  - Transcript│                    │  - Transcript│
└─────────────┘                    └─────────────┘
       │                                   │
       │                                   │
       ▼                                   ▼
┌─────────────┐                    ┌─────────────┐
│  Certificates│                    │  Certificates│
│  (certs/)    │                    │  (certs/)    │
└─────────────┘                    └─────────────┘
       │                                   │
       │                                   │
       ▼                                   ▼
┌─────────────┐                    ┌─────────────┐
│  Transcripts│                    │  Transcripts│
│(transcripts/)│                    │(transcripts/)│
└─────────────┘                    └─────────────┘
```

### 2.2 Component Architecture

#### 2.2.1 Client Components

- **`app/client.py`**: Main client application
  - Certificate exchange and validation
  - Diffie-Hellman key exchange (for credentials and chat)
  - Encrypted registration/login
  - Encrypted message sending with signatures
  - Transcript management and receipt generation

- **`app/crypto/`**: Cryptographic modules
  - `aes.py`: AES-128 ECB encryption with PKCS#7 padding
  - `dh.py`: Diffie-Hellman key exchange and key derivation
  - `pki.py`: X.509 certificate validation
  - `sign.py`: RSA signing and verification

- **`app/common/`**: Shared utilities
  - `protocol.py`: Pydantic message models
  - `utils.py`: Helper functions (base64, hashing, timestamps)

- **`app/storage/`**: Storage modules
  - `transcript.py`: Append-only transcript management

#### 2.2.2 Server Components

- **`app/server.py`**: Main server application
  - Certificate validation and exchange
  - User registration and login handling
  - Encrypted message reception and verification
  - Transcript management and receipt generation

- **`app/storage/db.py`**: MySQL database interface
  - User registration with salted password hashing
  - User authentication via password verification

#### 2.2.3 Certificate Management

- **`scripts/gen_ca.py`**: Root CA generation
  - Creates self-signed X.509 certificate
  - Generates RSA 2048-bit keypair
  - Valid for 10 years

- **`scripts/gen_cert.py`**: Certificate issuance
  - Issues certificates signed by Root CA
  - Generates entity keypairs
  - Includes Subject Alternative Name (SAN)

- **`scripts/inspect_cert.py`**: Certificate inspection
  - Alternative to OpenSSL for Windows
  - Displays certificate details

### 2.3 Communication Protocol Flow

The system implements a multi-phase protocol:

```
Phase 1: Certificate Exchange
  Client → Server: Client certificate
  Server → Client: Server certificate
  Both: Validate certificates (signature, expiry, CN)

Phase 2: Credential Encryption Key (DH Exchange #1)
  Client → Server: DH public value (A)
  Server → Client: DH public value (B)
  Both: Compute Ks = B^a mod p = A^b mod p
  Both: Derive AES key K = Trunc16(SHA256(big-endian(Ks)))

Phase 3: Registration/Login
  Client → Server: Encrypted {email, username, password} or {username, password}
  Server: Decrypt, verify, store/authenticate

Phase 4: Chat Session Key (DH Exchange #2)
  Client → Server: DH public value (A')
  Server → Client: DH public value (B')
  Both: Compute chat session key K' = Trunc16(SHA256(big-endian(Ks')))

Phase 5: Encrypted Messaging
  Client → Server: {type: "msg", seqno, ts, ct, sig}
  Server: Verify seqno, verify signature, decrypt, store in transcript

Phase 6: Session Closure
  Client → Server: Signed SessionReceipt
  Server → Client: Signed SessionReceipt
  Both: Store transcripts and receipts
```

### 2.4 Data Flow

#### Registration Flow
```
User Input → AES Encryption (DH Key) → Server → Decrypt → 
Salt Generation → Hash(salt||password) → MySQL Storage
```

#### Login Flow
```
User Input → AES Encryption (DH Key) → Server → Decrypt → 
Retrieve Salt → Hash(salt||password) → Compare with Stored Hash
```

#### Message Flow
```
Plaintext → AES Encryption (Session Key) → Hash(seqno||ts||ct) → 
RSA Sign → Send → Verify Seqno → Verify Signature → Decrypt → Display
```

---

## 3. Secure Protocol Implementation

### 3.1 Task 2.1: PKI Setup and Certificate Validation

#### 3.1.1 Root CA Generation

The Root CA is created using `scripts/gen_ca.py`:

- **Key Generation**: RSA 2048-bit private key
- **Certificate**: Self-signed X.509 v3 certificate
- **Validity**: 10 years
- **Extensions**: 
  - `BasicConstraints`: CA=True
  - `KeyUsage`: keyCertSign, crlSign, digitalSignature

**Implementation Location**: `scripts/gen_ca.py` lines 14-92

#### 3.1.2 Certificate Issuance

Certificates for server and client are issued by the Root CA:

- **Key Generation**: RSA 2048-bit keypair per entity
- **Signing**: Signed by CA private key using SHA-256
- **Extensions**:
  - `SubjectAlternativeName`: DNS name matching CN
  - `KeyUsage`: digitalSignature, keyEncipherment

**Implementation Location**: `scripts/gen_cert.py` lines 14-119

#### 3.1.3 Certificate Validation

Both client and server validate received certificates:

1. **Signature Chain Verification**: Verifies certificate is signed by trusted CA
   - Implementation: `app/crypto/pki.py` lines 84-136
   - Uses RSA signature verification with PKCS#1v15 padding

2. **Validity Period Check**: Ensures certificate is not expired
   - Implementation: `app/crypto/pki.py` lines 139-164
   - Checks `not_valid_before` and `not_valid_after`

3. **Common Name Verification**: Validates CN matches expected value
   - Implementation: `app/crypto/pki.py` lines 167-188
   - Server expects `server.local`, client CN optional

4. **Self-Signed Detection**: Rejects self-signed certificates
   - Implementation: `app/crypto/pki.py` lines 191-201

**Error Handling**: Invalid certificates result in `BAD_CERT` error
- Implementation: `app/server.py` lines 103-112, `app/client.py` line 137

### 3.2 Task 2.2: Registration and Login

#### 3.2.1 Certificate Exchange

Before any credential exchange, both parties authenticate:

- **Client sends certificate**: `app/client.py` lines 105-109
- **Server validates client certificate**: `app/server.py` lines 87-101
- **Server sends certificate**: `app/server.py` lines 124-129
- **Client validates server certificate**: `app/client.py` lines 126-140

#### 3.2.2 Diffie-Hellman Key Exchange

First DH exchange establishes key for credential encryption:

- **Parameters**: RFC 3526 MODP Group 14 (2048-bit prime)
- **Client generates keypair**: `app/client.py` line 152
- **Server generates keypair**: `app/server.py` line 152
- **Shared secret**: `Ks = peer_pub^priv mod p`
- **Implementation**: `app/crypto/dh.py` lines 42-46

#### 3.2.3 Key Derivation

AES-128 key derived from shared secret:

```
K = Trunc16(SHA256(big-endian(Ks)))
```

**Implementation**: `app/crypto/dh.py` lines 49-60
- Converts integer to big-endian bytes
- Computes SHA-256 hash
- Takes first 16 bytes

#### 3.2.4 Registration Process

1. **Client encrypts credentials**:
   - Payload: `{email, username, password}`
   - Encryption: AES-128 ECB with PKCS#7 padding
   - Implementation: `app/client.py` lines 174-179

2. **Server decrypts and validates**:
   - Decryption: `app/server.py` line 174
   - Duplicate check: `app/storage/db.py` lines 97-102
   - Salt generation: `app/storage/db.py` line 90 (16-byte random)
   - Hash computation: `pwd_hash = hex(SHA256(salt || password))`
   - Storage: MySQL `users` table
   - Implementation: `app/storage/db.py` lines 84-114

#### 3.2.5 Login Process

1. **New DH exchange**: Fresh keypair for each login session
   - Implementation: `app/client.py` lines 150-163, `app/server.py` lines 144-159

2. **Encrypted credentials**: Same encryption as registration
   - Implementation: `app/client.py` lines 192-197

3. **Server verification**:
   - Certificate validation (already done)
   - Password verification: `app/storage/db.py` lines 116-138
   - Recomputes `pwd_hash = hex(SHA256(salt || password))`
   - Compares with stored hash

4. **Login succeeds only if**:
   - Client certificate is valid and trusted ✅
   - Salted hash matches stored hash ✅
   - Implementation: `app/server.py` lines 201-210

### 3.3 Task 2.3: Session Key Establishment

After successful login, a **second DH exchange** establishes the chat session key:

#### 3.3.1 Chat Session Key Exchange

- **New DH keypair**: Generated after login
  - Client: `app/client.py` line 212
  - Server: `app/server.py` line 230

- **Shared secret computation**: Same formula as credential key
  - Client: `app/client.py` line 222
  - Server: `app/server.py` line 231

- **Key derivation**: Same formula `K = Trunc16(SHA256(big-endian(Ks)))`
  - Client: `app/client.py` line 223
  - Server: `app/server.py` line 232

#### 3.3.2 Forward Secrecy

- Each chat session uses a **fresh DH keypair**
- Previous session keys cannot be derived from new sessions
- Provides forward separation as required

### 3.4 Task 2.4: Encrypted Chat and Message Integrity

#### 3.4.1 Message Encryption

1. **Plaintext Input**: Read from console
   - Implementation: `app/client.py` line 249

2. **PKCS#7 Padding**: Pad to AES block size (16 bytes)
   - Implementation: `app/crypto/aes.py` lines 10-15

3. **AES-128 ECB Encryption**: Encrypt with session key
   - Implementation: `app/crypto/aes.py` lines 38-55
   - Used: `app/client.py` line 261

#### 3.4.2 Message Integrity

1. **Hash Computation**: `h = SHA256(seqno || timestamp || ciphertext)`
   - Implementation: `app/client.py` lines 264-269
   - Format: 8-byte seqno (big-endian) || 8-byte timestamp || ciphertext bytes

2. **RSA Signing**: `sig = RSA_SIGN(h)`
   - Implementation: `app/crypto/sign.py` lines 25-40
   - Algorithm: RSA PKCS#1 v1.5 with SHA-256
   - Used: `app/client.py` line 272

#### 3.4.3 Message Format

```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1763306682723,
  "ct": "base64-encoded-ciphertext",
  "sig": "base64-encoded-signature"
}
```

**Implementation**: `app/common/protocol.py` lines 46-55

#### 3.4.4 Message Verification

Upon receiving a message, the server:

1. **Sequence Number Check**: Ensures `seqno > last_seqno`
   - Implementation: `app/server.py` lines 271-278
   - Error: `REPLAY` if sequence number not strictly increasing

2. **Signature Verification**:
   - Recomputes hash: `SHA256(seqno || timestamp || ciphertext)`
   - Gets sender's public key from certificate
   - Verifies RSA signature
   - Implementation: `app/server.py` lines 280-297
   - Error: `SIG_FAIL` if signature invalid

3. **Decryption**:
   - AES-128 ECB decryption
   - PKCS#7 unpadding
   - Implementation: `app/server.py` line 300

#### 3.4.5 Security Properties Achieved

- **Confidentiality**: ✅ Only encrypted ciphertext transmitted
- **Integrity**: ✅ Hash mismatch → signature failure
- **Authenticity**: ✅ Only legitimate sender can generate valid signatures
- **Freshness**: ✅ Replayed messages rejected via sequence numbers

### 3.5 Task 2.5: Non-Repudiation and Session Closure

#### 3.5.1 Transcript Storage

Each side maintains an append-only transcript file:

**Format**: `seqno | timestamp | ciphertext | sig | peer-cert-fingerprint`

**Implementation**: `app/storage/transcript.py` lines 30-48

- Client stores: `app/client.py` lines 285-291
- Server stores: `app/server.py` lines 307-313

#### 3.5.2 Transcript Hash

Computed as: `TranscriptHash = SHA256(concatenation of all log lines)`

**Implementation**: `app/storage/transcript.py` lines 50-63

#### 3.5.3 Session Receipt Generation

Each side generates a signed receipt:

```json
{
  "type": "receipt",
  "peer": "client|server",
  "first_seq": 1,
  "last_seq": 5,
  "transcript_sha256": "hex-string",
  "sig": "base64-encoded-signature"
}
```

**Signature**: `RSA_SIGN(transcript_sha256)`

- Client receipt: `app/client.py` lines 304-319
- Server receipt: `app/server.py` lines 336-351

#### 3.5.4 Receipt Exchange

- Client sends receipt to server: `app/client.py` line 322
- Server receives and verifies client receipt: `app/server.py` lines 354-367
- Server sends receipt to client: `app/server.py` line 372
- Client receives server receipt: `app/client.py` lines 329-336

#### 3.5.5 Offline Verification

The `scripts/verify_transcript.py` script provides offline verification:

1. **Message Verification**: Verifies all message signatures in transcript
2. **Receipt Verification**: Verifies receipt signature over transcript hash
3. **Tamper Detection**: Detects any modifications to transcript

**Usage**:
```bash
python scripts/verify_transcript.py \
  --transcript transcripts/client_session_XXXXX.txt \
  --peer-cert certs/client_cert.pem \
  --receipt receipt_client.json \
  --signer-cert certs/client_cert.pem
```

---

## 4. Public Key Infrastructure and Certificate Management

### 4.1 Certificate Authority (CA) Setup

#### 4.1.1 Root CA Creation

The Root CA is a self-signed X.509 certificate that serves as the trust anchor:

**Key Specifications**:
- Algorithm: RSA
- Key Size: 2048 bits
- Public Exponent: 65537

**Certificate Specifications**:
- Version: X.509 v3
- Validity: 10 years
- Subject/Issuer: "FAST-NU Root CA"
- Extensions:
  - `BasicConstraints`: CA=True, pathLength=None
  - `KeyUsage`: keyCertSign, crlSign, digitalSignature

**Storage**: `certs/ca_cert.pem` (public), `certs/ca_key.pem` (private, 600 permissions)

**Implementation**: `scripts/gen_ca.py`

#### 4.1.2 Certificate Issuance Process

Certificates are issued using `scripts/gen_cert.py`:

1. **Load CA credentials**: CA private key and certificate
2. **Generate entity keypair**: RSA 2048-bit for server/client
3. **Create certificate request**: Subject with CN matching hostname
4. **Sign with CA**: RSA signature with SHA-256
5. **Add extensions**: SAN with DNS name, KeyUsage
6. **Save**: Certificate and private key to `certs/` folder

**Example**:
```bash
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client
```

### 4.2 Certificate Validation Process

#### 4.2.1 Validation Steps

When a certificate is received, the following checks are performed:

1. **Self-Signed Check**: Reject if `subject == issuer`
   - Implementation: `app/crypto/pki.py` lines 191-201

2. **Signature Chain Verification**: Verify certificate is signed by trusted CA
   - Extract signature algorithm OID
   - Map to hash algorithm (SHA-256, SHA-384, SHA-512, SHA-1)
   - Verify using CA public key with PKCS#1v15 padding
   - Implementation: `app/crypto/pki.py` lines 84-136

3. **Validity Period Check**: Ensure certificate is within validity window
   - Check `not_valid_before <= now <= not_valid_after`
   - Implementation: `app/crypto/pki.py` lines 139-164

4. **Common Name Verification**: Validate CN matches expected value
   - Server expects: `server.local`
   - Client CN: Optional (any valid CN accepted)
   - Implementation: `app/crypto/pki.py` lines 167-188

#### 4.2.2 Comprehensive Validation Function

The `validate_certificate()` function performs all checks:

```python
def validate_certificate(cert, ca_cert, expected_cn=None):
    if is_self_signed(cert):
        raise BadCertError("Certificate is self-signed")
    verify_certificate_chain(cert, ca_cert)
    check_certificate_validity(cert)
    if expected_cn:
        check_certificate_cn(cert, expected_cn)
    return True
```

**Implementation**: `app/crypto/pki.py` lines 204-233

### 4.3 Certificate Exchange Protocol

#### 4.3.1 Mutual Authentication Flow

```
1. Client → Server: HelloMessage {cert: base64(client_cert)}
2. Server validates client certificate
   - If invalid: Server → Client: ErrorMessage {error: "BAD_CERT"}
   - If valid: Continue
3. Server → Client: ServerHelloMessage {cert: base64(server_cert)}
4. Client validates server certificate
   - If invalid: Client disconnects with error
   - If valid: Continue to next phase
```

**Implementation**:
- Client: `app/client.py` lines 105-143
- Server: `app/server.py` lines 72-127

#### 4.3.2 Error Handling

Invalid certificates result in `BAD_CERT` error:

- **Self-signed certificates**: Detected and rejected
- **Expired certificates**: Validity check fails
- **Untrusted certificates**: Signature verification fails
- **CN mismatch**: Server certificate must match `server.local`

**Error Response**: `ErrorMessage {error: "BAD_CERT"}`

### 4.4 Certificate Inspection

#### 4.4.1 Inspection Tool

The `scripts/inspect_cert.py` script provides certificate details:

**Features**:
- Certificate version and serial number
- Issuer and subject information
- Validity period
- Public key algorithm and size
- X.509v3 extensions
- Signature algorithm
- Additional info (CA status, self-signed status, CN)

**Usage**:
```bash
python scripts/inspect_cert.py certs/ca_cert.pem
python scripts/inspect_cert.py certs/server_cert.pem
python scripts/inspect_cert.py certs/client_cert.pem
```

**Output Example**:
```
Certificate:
    Data:
        Version: 3 (v3)
        Serial Number: 1234567890
    Issuer:
        countryName=US
        organizationName=FAST-NU
        commonName=FAST-NU Root CA
    Validity
        Not Before: 2025-11-14 13:02:14
        Not After: 2035-11-14 13:02:14
    Subject:
        commonName=server.local
    Subject Public Key Info:
        Public Key Algorithm: RSAPublicKey
        Key Size: 2048 bits
    X509v3 extensions:
        basicConstraints:
            CA:False
        keyUsage:
            Digital Signature, Key Encipherment
        subjectAlternativeName:
            DNS:server.local
```

### 4.5 Certificate Storage and Security

#### 4.5.1 File Organization

```
certs/
├── ca_cert.pem          # Root CA certificate (public)
├── ca_key.pem           # Root CA private key (600 permissions)
├── server_cert.pem      # Server certificate (public)
├── server_key.pem       # Server private key (600 permissions)
├── client_cert.pem      # Client certificate (public)
└── client_key.pem       # Client private key (600 permissions)
```

#### 4.5.2 Security Measures

- **Private Keys**: Stored with 600 permissions (owner read/write only)
- **Git Ignore**: All certificates and keys excluded from version control
- **No Hardcoded Secrets**: All keys loaded from files at runtime
- **Certificate Validation**: Comprehensive checks before use

---

## 5. Conclusion

### 5.1 Implementation Summary

This project successfully implements a complete secure chat system demonstrating all four fundamental security properties:

1. **Confidentiality**: Achieved through AES-128 encryption of all sensitive data (credentials and messages)
2. **Integrity**: Ensured via SHA-256 hashing and RSA signatures on all messages
3. **Authenticity**: Provided through PKI-based mutual certificate authentication
4. **Non-Repudiation**: Established via signed transcripts and session receipts

### 5.2 Key Achievements

#### 5.2.1 Security Properties

- ✅ **PKI Implementation**: Complete certificate authority with certificate issuance and validation
- ✅ **Encrypted Credentials**: User registration and login with AES-128 encrypted transmission
- ✅ **Secure Password Storage**: Salted SHA-256 hashing in MySQL database
- ✅ **Session Key Establishment**: Unique Diffie-Hellman keys for each chat session
- ✅ **Message Integrity**: RSA signatures on all messages with replay protection
- ✅ **Non-Repudiation**: Signed transcripts and receipts for audit trail

#### 5.2.2 Protocol Correctness

- ✅ All cryptographic operations implemented at application layer (no TLS/SSL)
- ✅ Correct key derivation: `K = Trunc16(SHA256(big-endian(Ks)))`
- ✅ Proper password hashing: `pwd_hash = hex(SHA256(salt || password))`
- ✅ Message format matches specification exactly
- ✅ Error handling for all failure cases (BAD_CERT, SIG_FAIL, REPLAY)

#### 5.2.3 Code Quality

- ✅ Modular design with clear separation of concerns
- ✅ Comprehensive error handling and logging
- ✅ Well-documented code with docstrings
- ✅ 24+ meaningful commits showing progressive development
- ✅ Complete documentation (README, verification checklist)

### 5.3 Security Analysis

#### 5.3.1 Threat Mitigation

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping | AES-128 encryption of all sensitive data |
| Message Tampering | RSA signatures with SHA-256 hashing |
| Replay Attacks | Strictly increasing sequence numbers |
| Man-in-the-Middle | PKI certificate validation |
| Password Theft | Salted SHA-256 hashing, no plaintext storage |
| Denial of Communication | Signed transcripts and receipts |

#### 5.3.2 Security Strengths

1. **Forward Secrecy**: Each session uses fresh DH keypair
2. **Comprehensive Validation**: Multiple certificate checks prevent various attacks
3. **Replay Protection**: Sequence numbers prevent message replay
4. **Non-Repudiation**: Signed transcripts provide legal proof
5. **Defense in Depth**: Multiple security layers (encryption, signatures, certificates)

#### 5.3.3 Known Limitations

1. **ECB Mode**: AES-128 ECB is used (CBC or GCM would be more secure, but ECB meets assignment requirements)
2. **No Perfect Forward Secrecy for Credentials**: First DH key used for credentials is not ephemeral
3. **Single CA**: Only one Root CA (no certificate revocation list)
4. **No Key Rotation**: Session keys valid for entire session duration

### 5.4 Testing Evidence

The following evidence has been collected:

- ✅ **Certificate Inspection**: All certificates verified and documented
- ✅ **BAD_CERT Testing**: Invalid certificates properly rejected
- ✅ **Encrypted Payloads**: Wireshark captures show only encrypted data
- ✅ **Replay Protection**: Duplicate sequence numbers rejected
- ✅ **Signature Verification**: Tampered messages detected
- ✅ **Transcript Verification**: Offline verification script confirms integrity
- ✅ **Database Evidence**: Salted password hashes stored correctly

### 5.5 Lessons Learned

1. **Application-Layer Security**: Implementing security at the application layer provides full control but requires careful attention to protocol details
2. **Cryptographic Primitives**: Understanding how to combine primitives (AES, RSA, DH, SHA) is crucial for building secure systems
3. **PKI Complexity**: Certificate validation involves multiple checks that must all pass
4. **Non-Repudiation**: Signed transcripts provide strong evidence but require careful implementation
5. **Testing**: Comprehensive testing (including error cases) is essential for security

### 5.6 Future Enhancements

Potential improvements for production use:

1. **CBC/GCM Mode**: Replace ECB with CBC or authenticated encryption (GCM)
2. **Certificate Revocation**: Implement CRL or OCSP
3. **Perfect Forward Secrecy**: Use ephemeral keys for credential encryption
4. **Key Rotation**: Implement periodic key refresh during long sessions
5. **Multi-User Chat**: Extend to support group messaging
6. **Message History**: Encrypted message storage with search capability

### 5.7 Conclusion

This SecureChat system successfully demonstrates how cryptographic primitives can be combined to achieve comprehensive security properties without relying on TLS/SSL. The implementation provides:

- Strong authentication through PKI
- Confidential communication via encryption
- Message integrity through signatures
- Replay protection via sequence numbers
- Non-repudiation through signed transcripts

All requirements from Tasks 2.1 through 2.5 have been fully implemented and verified. The system is ready for deployment in environments requiring application-layer security.

---

## Appendix A: File Structure

```
securechat-skeleton/
├── app/
│   ├── client.py                 # Client application (350+ lines)
│   ├── server.py                 # Server application (450+ lines)
│   ├── crypto/
│   │   ├── aes.py                # AES-128 ECB + PKCS#7 (79 lines)
│   │   ├── dh.py                 # Diffie-Hellman (69 lines)
│   │   ├── pki.py                # Certificate validation (262 lines)
│   │   └── sign.py                # RSA signing (88 lines)
│   ├── common/
│   │   ├── protocol.py            # Message models (71 lines)
│   │   └── utils.py               # Utilities (31 lines)
│   └── storage/
│       ├── db.py                  # MySQL interface (165 lines)
│       └── transcript.py           # Transcript management (108 lines)
├── scripts/
│   ├── gen_ca.py                  # CA generation (116 lines)
│   ├── gen_cert.py                # Certificate issuance (167 lines)
│   ├── inspect_cert.py            # Certificate inspection (167 lines)
│   └── verify_transcript.py       # Offline verification (206 lines)
├── certs/                          # Certificates (gitignored)
├── transcripts/                    # Session transcripts (gitignored)
├── README.md                       # Complete documentation
├── VERIFICATION_CHECKLIST.md       # Verification checklist
├── REPORT.md                       # This report
└── requirements.txt                # Dependencies
```

## Appendix B: Key Algorithms and Formulas

### Key Derivation
```
K = Trunc16(SHA256(big-endian(Ks)))
```

### Password Hashing
```
pwd_hash = hex(SHA256(salt || password))
```

### Message Hash
```
h = SHA256(seqno || timestamp || ciphertext)
```

### Transcript Hash
```
TranscriptHash = SHA256(concatenation of all log lines)
```

## Appendix C: Error Codes

- `BAD_CERT`: Invalid, expired, or untrusted certificate
- `SIG_FAIL`: Signature verification failed
- `REPLAY`: Duplicate sequence number detected
- `LOGIN_FAIL`: Invalid username or password
- `USER_EXISTS`: Username or email already registered

---

**End of Report**

