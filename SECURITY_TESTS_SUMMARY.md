# Security Tests Summary

This document provides quick instructions for testing two critical security features:

1. **Tampering Detection (SIG_FAIL)**: Flipping a bit in ciphertext → signature verification fails
2. **Replay Protection (REPLAY)**: Resending old sequence number → rejected

---

## Test 1: Tampering Detection (SIG_FAIL)

### What We're Testing
When a message's ciphertext is tampered with (bit flipped), the signature verification should fail because:
- The signature was computed over the original ciphertext
- The hash of the tampered ciphertext won't match
- RSA signature verification will fail → **SIG_FAIL** error

### Quick Steps

1. **Modify `app/client.py`** - Add 3 lines after line 261:
   ```python
   # TAMPERING TEST: Flip a bit in ciphertext
   ciphertext = bytearray(ciphertext)
   ciphertext[0] ^= 0x01  # Flip least significant bit
   ciphertext = bytes(ciphertext)
   ```

2. **Start server:**
   ```powershell
   python -m app.server
   ```

3. **Run client:**
   ```powershell
   python -m app.client
   ```

4. **Login and send a message** (e.g., "Hello")

5. **Expected Result:**
   - Server shows: `ERROR: Signature verification failed`
   - Server sends: `ErrorMessage {error: "SIG_FAIL"}`
   - Client disconnects or shows error

6. **Remove the 3 added lines** to restore normal operation

### Evidence to Capture
- Screenshot of server console showing "Signature verification failed"
- Screenshot showing "SIG_FAIL" error message
- Screenshot of modified client code

---

## Test 2: Replay Protection (REPLAY)

### What We're Testing
When a message with a duplicate sequence number is sent, the server should reject it because:
- Sequence numbers must be strictly increasing
- Replayed messages have old sequence numbers
- Server tracks `last_seqno` and rejects duplicates → **REPLAY** error

### Quick Steps

1. **Start server:**
   ```powershell
   python -m app.server
   ```

2. **Run test script:**
   ```powershell
   python scripts\test_replay.py
   ```

3. **Enter credentials** when prompted

4. **Script automatically:**
   - Completes authentication
   - Sends message with seqno=1 ✅ (accepted)
   - Sends message with seqno=2 ✅ (accepted)
   - Resends message with seqno=1 ❌ (rejected with REPLAY)

5. **Expected Result:**
   - Test script shows: `[SUCCESS] REPLAY attack detected and rejected!`
   - Server shows: `ERROR: Replay detected - seqno 1 <= last 2`
   - Server sends: `ErrorMessage {error: "REPLAY"}`

### Evidence to Capture
- Screenshot of test script output showing REPLAY detection
- Screenshot of server console showing "Replay detected"
- Screenshot showing "REPLAY" error message

---

## Implementation Details

### Tampering Detection (Server Code)
**Location**: `app/server.py` lines 280-297

```python
# Recompute hash: SHA256(seqno || timestamp || ciphertext)
hash_input = seqno_bytes + ts_bytes + ct_bytes
message_hash = sha256_bytes(hash_input)

# Verify signature
if not rsa_verify(client_public_key, message_hash, signature):
    print("ERROR: Signature verification failed")
    err = ErrorMessage(error="SIG_FAIL")
    send_message(conn, err.model_dump())
    return
```

**How it works:**
1. Server receives message with tampered ciphertext
2. Server recomputes hash: `SHA256(seqno || timestamp || tampered_ciphertext)`
3. Server verifies signature using original hash (from sender)
4. Hashes don't match → signature verification fails → SIG_FAIL

### Replay Protection (Server Code)
**Location**: `app/server.py` lines 271-278

```python
# Check sequence number (replay protection)
if chat_msg.seqno <= last_seqno:
    print(f"ERROR: Replay detected - seqno {chat_msg.seqno} <= last {last_seqno}")
    err = ErrorMessage(error="REPLAY")
    send_message(conn, err.model_dump())
    return

last_seqno = chat_msg.seqno
```

**How it works:**
1. Server tracks `last_seqno` for each session
2. For each message, checks: `seqno > last_seqno`
3. If `seqno <= last_seqno`, message is a replay → REPLAY error
4. Otherwise, update `last_seqno = seqno` and process message

---

## Test Results Template

### Tampering Test Results
- [ ] Test performed: ✅
- [ ] Bit flipped in ciphertext: ✅
- [ ] Server detected tampering: ✅
- [ ] SIG_FAIL error sent: ✅
- [ ] Screenshots captured: ✅

**Server Output:**
```
[Client 127.0.0.1:XXXXX] Received chat message: seqno=1
[Client 127.0.0.1:XXXXX] ERROR: Signature verification failed
[Client 127.0.0.1:XXXXX] Sending error: SIG_FAIL
```

### Replay Test Results
- [ ] Test performed: ✅
- [ ] Message with seqno=1 sent: ✅
- [ ] Message with seqno=2 sent: ✅
- [ ] Message with seqno=1 resent: ✅
- [ ] REPLAY error detected: ✅
- [ ] Screenshots captured: ✅

**Server Output:**
```
[Client 127.0.0.1:XXXXX] Received chat message: seqno=1
[Client 127.0.0.1:XXXXX] Message (seqno=1): First message
[Client 127.0.0.1:XXXXX] Received chat message: seqno=2
[Client 127.0.0.1:XXXXX] Message (seqno=2): Second message
[Client 127.0.0.1:XXXXX] Received chat message: seqno=1
[Client 127.0.0.1:XXXXX] ERROR: Replay detected - seqno 1 <= last 2
```

---

## Files Created for Testing

1. **`scripts/test_replay.py`**: Automated replay attack test script
2. **`scripts/test_tamper_simple.py`**: Instructions for tampering test
3. **`TESTING_GUIDE.md`**: Comprehensive testing guide
4. **`QUICK_TESTS.md`**: Quick reference for both tests
5. **`SECURITY_TESTS_SUMMARY.md`**: This file

---

## Quick Reference

### Tampering Test
```powershell
# 1. Modify app/client.py (add 3 lines after line 261)
# 2. Start server
python -m app.server

# 3. Run client
python -m app.client
# Login and send message → SIG_FAIL expected
```

### Replay Test
```powershell
# 1. Start server
python -m app.server

# 2. Run test script
python scripts\test_replay.py
# Enter credentials → REPLAY expected on duplicate seqno
```

---

## For Your Report

Include these sections:

1. **Tampering Test:**
   - Description: "Flipped a bit in the ciphertext to simulate message tampering"
   - Expected: "Signature verification should fail because hash mismatch"
   - Result: "Server correctly detected tampering and sent SIG_FAIL error"
   - Evidence: Screenshots of server console and error message

2. **Replay Test:**
   - Description: "Resent a message with duplicate sequence number"
   - Expected: "Server should reject duplicate sequence numbers"
   - Result: "Server correctly detected replay attack and sent REPLAY error"
   - Evidence: Screenshots of test script output and server console

---

**Ready to test!** Follow the steps above and capture screenshots for your report.

