# Quick Security Tests - SIG_FAIL and REPLAY

## Test 1: Tampering Detection (SIG_FAIL)

### Step-by-Step Instructions

1. **Start the server:**
   ```powershell
   python -m app.server
   ```
   Keep this terminal open.

2. **Open `app/client.py` in your editor** and find line 261 (around the `aes_encrypt_ecb` call)

3. **Add these 3 lines RIGHT AFTER line 261:**
   ```python
   # TAMPERING TEST: Flip a bit in ciphertext
   ciphertext = bytearray(ciphertext)
   ciphertext[0] ^= 0x01  # Flip least significant bit
   ciphertext = bytes(ciphertext)
   ```

   The code should look like this:
   ```python
   # Encrypt plaintext with AES-128
   plaintext_bytes = plaintext.encode('utf-8')
   ciphertext = aes_encrypt_ecb(chat_session_key, plaintext_bytes)
   
   # TAMPERING TEST: Flip a bit in ciphertext
   ciphertext = bytearray(ciphertext)
   ciphertext[0] ^= 0x01  # Flip least significant bit
   ciphertext = bytes(ciphertext)
   
   ciphertext_b64 = b64e(ciphertext)
   ```

4. **In a NEW terminal, run the client:**
   ```powershell
   python -m app.client
   ```

5. **Complete login** and send a message (e.g., type "Hello" and press Enter)

6. **Expected Result:**
   - **Server terminal** will show:
     ```
     [Client 127.0.0.1:XXXXX] ERROR: Signature verification failed
     [Client 127.0.0.1:XXXXX] Sending error: SIG_FAIL
     ```
   - **Client** may disconnect or show an error

7. **Take a screenshot** of the server console showing the SIG_FAIL error

8. **Remove the 3 lines you added** (restore original code)

---

## Test 2: Replay Attack Detection (REPLAY)

### Step-by-Step Instructions

1. **Start the server:**
   ```powershell
   python -m app.server
   ```
   Keep this terminal open.

2. **In a NEW terminal, run the replay test:**
   ```powershell
   python scripts\test_replay.py
   ```

3. **Follow the prompts:**
   - Enter your username when prompted
   - Enter your password when prompted
   - The script will automatically:
     - Complete authentication
     - Send message with seqno=1 ✅
     - Send message with seqno=2 ✅
     - **Resend message with seqno=1** ❌ (should be rejected)

4. **Expected Result:**
   ```
   REPLAY ATTACK: Resending message with seqno=1 (duplicate)
   ============================================================
   This should be rejected with REPLAY error...
   
   [SUCCESS] REPLAY attack detected and rejected!
   Server response: {'error': 'REPLAY'}
   ```

5. **Check the server terminal** - it should show:
   ```
   [Client 127.0.0.1:XXXXX] Received chat message: seqno=1
   [Client 127.0.0.1:XXXXX] Message (seqno=1): First message
   [Client 127.0.0.1:XXXXX] Received chat message: seqno=2
   [Client 127.0.0.1:XXXXX] Message (seqno=2): Second message
   [Client 127.0.0.1:XXXXX] Received chat message: seqno=1
   [Client 127.0.0.1:XXXXX] ERROR: Replay detected - seqno 1 <= last 2
   ```

6. **Take screenshots:**
   - Test script output showing REPLAY detection
   - Server console showing "Replay detected"

---

## Screenshot Checklist

### For Tampering Test (SIG_FAIL):
- [ ] Server console showing "Signature verification failed"
- [ ] Server console showing "SIG_FAIL" error message
- [ ] Modified client code (showing the 3 added lines)

### For Replay Test (REPLAY):
- [ ] Test script output showing "REPLAY attack detected and rejected!"
- [ ] Server console showing "Replay detected"
- [ ] Server console showing "REPLAY" error message

---

## Troubleshooting

### Tampering Test:
- **Server doesn't show error?** Make sure you added the code AFTER encryption but BEFORE base64 encoding
- **Client crashes?** This is expected - the server rejects the tampered message

### Replay Test:
- **Script fails to connect?** Make sure server is running on port 8888
- **REPLAY not detected?** Check that server is running and test script completes authentication first

---

## Quick Commands Summary

```powershell
# Terminal 1: Start server
python -m app.server

# Terminal 2: Test replay (easiest)
python scripts\test_replay.py

# Terminal 2: Test tampering (modify client.py first)
python -m app.client
```

