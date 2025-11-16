# Security Testing Guide

This guide provides step-by-step instructions for testing the security features of the SecureChat system, specifically:

1. **Tampering Detection (SIG_FAIL)**: Verify that message tampering is detected
2. **Replay Protection (REPLAY)**: Verify that duplicate sequence numbers are rejected

---

## Test 1: Tampering Detection (SIG_FAIL)

### Objective
Demonstrate that flipping a bit in the ciphertext causes signature verification to fail.

### Prerequisites
- Server running: `python -m app.server`
- Valid user account registered
- Certificates generated

### Method 1: Manual Code Modification (Recommended)

1. **Backup the client file:**
   ```powershell
   Copy-Item app\client.py app\client.py.backup
   ```

2. **Open `app/client.py` and locate line ~261** (where `aes_encrypt_ecb` is called)

3. **Add tampering code** right after the encryption:
   ```python
   # Encrypt plaintext with AES-128
   plaintext_bytes = plaintext.encode('utf-8')
   ciphertext = aes_encrypt_ecb(chat_session_key, plaintext_bytes)
   
   # TAMPERING TEST: Flip a bit in ciphertext
   ciphertext = bytearray(ciphertext)
   ciphertext[0] ^= 0x01  # Flip least significant bit of first byte
   ciphertext = bytes(ciphertext)
   
   ciphertext_b64 = b64e(ciphertext)
   ```

4. **Start the server** (in one terminal):
   ```powershell
   python -m app.server
   ```

5. **Run the modified client** (in another terminal):
   ```powershell
   python -m app.client
   ```

6. **Complete login** and send a message (e.g., "Hello")

7. **Expected Result:**
   - **Server console** should show:
     ```
     ERROR: Signature verification failed
     Sending error: SIG_FAIL
     ```
   - **Client** may disconnect or show an error

8. **Restore the original client:**
   ```powershell
   Copy-Item app\client.py.backup app\client.py -Force
   ```

### Method 2: Using Test Script

1. **Run the test script:**
   ```powershell
   python scripts\test_tamper_simple.py
   ```
   This will display detailed instructions.

### Expected Evidence

**Server Output:**
```
[INFO] Client connected from ('127.0.0.1', 54321)
[INFO] Validating client certificate...
[OK] Client certificate valid
[INFO] Received chat message: seqno=1
[ERROR] Signature verification failed
[INFO] Sending error: SIG_FAIL
```

**Screenshot Points:**
- Server console showing "Signature verification failed"
- Server console showing "SIG_FAIL" error message
- Client showing connection error or disconnect

---

## Test 2: Replay Attack Detection (REPLAY)

### Objective
Demonstrate that resending a message with a duplicate sequence number is rejected.

### Prerequisites
- Server running: `python -m app.server`
- Valid user account registered
- Certificates generated

### Method 1: Using Test Script (Recommended)

1. **Start the server** (in one terminal):
   ```powershell
   python -m app.server
   ```

2. **Run the replay test script** (in another terminal):
   ```powershell
   python scripts\test_replay.py
   ```

3. **Follow the prompts:**
   - Enter your username and password when prompted
   - The script will:
     - Complete authentication
     - Send message with seqno=1 (accepted)
     - Send message with seqno=2 (accepted)
     - **Resend message with seqno=1** (should be rejected with REPLAY)

4. **Expected Result:**
   ```
   REPLAY ATTACK: Resending message with seqno=1 (duplicate)
   [SUCCESS] REPLAY attack detected and rejected!
   Server response: {'error': 'REPLAY'}
   ```

### Method 2: Manual Testing

1. **Backup the client file:**
   ```powershell
   Copy-Item app\client.py app\client.py.backup
   ```

2. **Open `app/client.py` and locate the message sending loop** (around line 255)

3. **Modify to send duplicate seqno:**
   - After sending the first message, add code to resend it with the same seqno
   - Or modify the seqno increment logic to skip incrementing once

4. **Run client and send messages**

5. **Expected: Second message with duplicate seqno rejected**

6. **Restore backup**

### Expected Evidence

**Server Output:**
```
[INFO] Received chat message: seqno=1
[OK] Message verified and decrypted
[INFO] Received chat message: seqno=2
[OK] Message verified and decrypted
[INFO] Received chat message: seqno=1
[ERROR] Replay detected: seqno=1 <= last_seqno=2
[INFO] Sending error: REPLAY
```

**Test Script Output:**
```
REPLAY ATTACK: Resending message with seqno=1 (duplicate)
[SUCCESS] REPLAY attack detected and rejected!
Server response: {'error': 'REPLAY'}
```

**Screenshot Points:**
- Server console showing "Replay detected"
- Server console showing "REPLAY" error message
- Test script showing successful detection

---

## Verification Checklist

### Tampering Test (SIG_FAIL)
- [ ] Modified client code to flip bit in ciphertext
- [ ] Server detected signature verification failure
- [ ] Server sent SIG_FAIL error message
- [ ] Screenshot of server console showing error
- [ ] Restored original client code

### Replay Test (REPLAY)
- [ ] Sent message with seqno=1 (accepted)
- [ ] Sent message with seqno=2 (accepted)
- [ ] Resent message with seqno=1 (rejected)
- [ ] Server detected replay attack
- [ ] Server sent REPLAY error message
- [ ] Screenshot of server console showing error
- [ ] Screenshot of test script output

---

## Troubleshooting

### Tampering Test Issues

**Problem:** Server doesn't show SIG_FAIL error
- **Solution:** Check that you modified the ciphertext AFTER encryption but BEFORE base64 encoding
- **Solution:** Verify the server is checking signatures (check `app/server.py` line ~280)

**Problem:** Client crashes
- **Solution:** This is expected - the server rejects the message and may close the connection

### Replay Test Issues

**Problem:** Test script fails to connect
- **Solution:** Ensure server is running on port 8888
- **Solution:** Check firewall settings

**Problem:** REPLAY not detected
- **Solution:** Verify server tracks `last_seqno` (check `app/server.py` line ~271)
- **Solution:** Ensure sequence numbers are strictly increasing

---

## Additional Notes

- Both tests modify the normal flow to demonstrate security features
- Always restore backups after testing
- These tests prove the system correctly implements security controls
- Document all test results with screenshots for your report

---

## Quick Test Commands

```powershell
# Start server
python -m app.server

# Test replay (in another terminal)
python scripts\test_replay.py

# Test tampering (modify client.py first, then)
python -m app.client
```

