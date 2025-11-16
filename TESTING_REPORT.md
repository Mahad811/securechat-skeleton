# Testing Report - Secure Chat System

This document provides concise descriptions and procedures for testing the security features of the Secure Chat System.

---

## Test 1: Wireshark - Encrypted Payload Verification

### Purpose
Verify that all network traffic is encrypted and no plaintext credentials or messages are visible in transit.

### Procedure
1. Start Wireshark and select **"Adapter for loopback traffic capture"**
2. Set capture filter: `tcp.port == 8888`
3. Start capturing
4. Run server: `python -m app.server`
5. Run client: `python -m app.client` and complete registration/login/chat
6. Stop capture

### Expected Results
- All application-layer messages show Base64-encoded ciphertext in `"ct"` fields
- No plaintext passwords, usernames, or chat messages visible
- JSON structure visible but payload content encrypted
- Hex view shows random-looking bytes (encrypted data)

### Evidence
- Screenshot: Packet list filtered by `tcp.port == 8888`
- Screenshot: TCP Stream showing JSON with encrypted `"ct"` fields
- Screenshot: Hex view of encrypted packet payload

---

## Test 2: Invalid Certificate Test (BAD_CERT)

### Purpose
Verify that the server rejects untrusted, expired, or self-signed certificates.

### Procedure
1. Generate an untrusted CA: `python scripts/gen_ca.py --output certs/evil_ca`
2. Generate certificate signed by untrusted CA: `python scripts/gen_cert.py --cn client --ca-key certs/evil_ca_key.pem --ca-cert certs/evil_ca_cert.pem --output certs/evil_client`
3. Replace client certificate: `Copy-Item certs\evil_client_cert.pem certs\client_cert.pem -Force`
4. Start server: `python -m app.server`
5. Run client: `python -m app.client`

### Expected Results
- Server detects untrusted certificate
- Server logs: `ERROR: Certificate validation failed: untrusted certificate`
- Server sends: `ErrorMessage {error: "BAD_CERT"}`
- Client receives error and disconnects

### Evidence
- Screenshot: Server console showing certificate validation failure
- Screenshot: Error message with `BAD_CERT`
- Screenshot: Certificate inspection showing untrusted issuer

---

## Test 3: Message Tampering Test (SIG_FAIL)

### Purpose
Verify that any modification to encrypted messages is detected through signature verification failure.

### Procedure
1. Modify `app/client.py` after line 261 (after computing signature):
   ```python
   # TAMPERING TEST: Flip a bit in ciphertext
   ciphertext = bytearray(ciphertext)
   ciphertext[0] ^= 0x01  # Flip least significant bit
   ciphertext = bytes(ciphertext)
   ```
2. Start server: `python -m app.server`
3. Run client: `python -m app.client`
4. Login and send a chat message
5. Restore `app/client.py` to normal operation

### Expected Results
- Server receives tampered ciphertext
- Server recomputes hash: `SHA256(seqno || timestamp || tampered_ciphertext)`
- Signature verification fails (hash mismatch)
- Server logs: `ERROR: Signature verification failed`
- Server sends: `ErrorMessage {error: "SIG_FAIL"}`
- Client disconnects or shows error

### Evidence
- Screenshot: Modified client code showing bit flip
- Screenshot: Server console showing signature verification failure
- Screenshot: Error message with `SIG_FAIL`

---

## Test 4: Replay Attack Test (REPLAY)

### Purpose
Verify that duplicate sequence numbers are rejected to prevent replay attacks.

### Procedure
1. Start server: `python -m app.server`
2. Run automated test: `python scripts/test_replay.py`
3. Enter credentials when prompted

### Expected Results
- Test script sends message with `seqno=1` → accepted
- Test script sends message with `seqno=2` → accepted
- Test script resends message with `seqno=1` → rejected
- Server logs: `ERROR: Replay detected - seqno 1 <= last 2`
- Server sends: `ErrorMessage {error: "REPLAY"}`
- Test script confirms: `[SUCCESS] REPLAY attack detected and rejected!`

### Evidence
- Screenshot: Test script output showing REPLAY detection
- Screenshot: Server console showing replay detection
- Screenshot: Error message with `REPLAY`

---

## Test 5: Non-Repudiation and Offline Verification

### Purpose
Verify that chat transcripts are tamper-evident and session receipts provide cryptographic proof of conversation.

### Procedure
1. Complete a chat session (client and server exchange messages)
2. Session receipts are automatically generated and exchanged
3. Transcript files are saved in `transcripts/` directory
4. Verify transcript offline: `python scripts/verify_transcript.py transcripts/client_session_<timestamp>.txt`
5. Verify receipt: `python scripts/verify_transcript.py transcripts/client_session_<timestamp>.txt --receipt transcripts/client_session_<timestamp>_receipt.json`

### Expected Results
- Transcript file contains: `seqno | timestamp | ciphertext | sig | peer-cert-fingerprint`
- All message signatures in transcript are valid
- Transcript hash computed: `SHA256(concatenation of all log lines)`
- Session receipt contains signed transcript hash
- Receipt signature verifies against sender's public key
- Any modification to transcript invalidates receipt signature

### Evidence
- Screenshot: Transcript file content showing message entries
- Screenshot: Verification script output showing all signatures valid
- Screenshot: Receipt JSON with transcript hash and signature
- Screenshot: Receipt verification success message

---

## Summary

| Test | Security Property | Expected Error | Status |
|------|-------------------|----------------|--------|
| Test 1: Wireshark | Confidentiality | N/A (verification) | ✅ |
| Test 2: BAD_CERT | Authenticity | `BAD_CERT` | ✅ |
| Test 3: SIG_FAIL | Integrity | `SIG_FAIL` | ✅ |
| Test 4: REPLAY | Freshness | `REPLAY` | ✅ |
| Test 5: Offline Verification | Non-Repudiation | N/A (verification) | ✅ |

All tests demonstrate that the Secure Chat System correctly implements:
- **Confidentiality**: Encrypted payloads (no plaintext in transit)
- **Integrity**: Tampering detection via signature verification
- **Authenticity**: Certificate validation and rejection of untrusted certificates
- **Non-Repudiation**: Signed transcripts and session receipts
- **Freshness**: Replay protection via sequence numbers

