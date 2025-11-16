# Commands to Run Security Tests

## Test 1: Tampering Detection (SIG_FAIL)

### Step 1: Backup and Modify Client Code

```powershell
# Navigate to project directory
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton

# Backup client file
Copy-Item app\client.py app\client.py.backup

# Open client.py in your editor and add these 3 lines AFTER line 261:
# (Right after: ciphertext = aes_encrypt_ecb(chat_session_key, plaintext_bytes))
#
# # TAMPERING TEST: Flip a bit in ciphertext
# ciphertext = bytearray(ciphertext)
# ciphertext[0] ^= 0x01  # Flip least significant bit
# ciphertext = bytes(ciphertext)
```

### Step 2: Start Server (Terminal 1)

```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python -m app.server
```

**Expected output:**
```
[OK] Server certificate loaded and validated
[OK] Server listening on 0.0.0.0:8888
Waiting for connections...
```

### Step 3: Run Client (Terminal 2)

```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python -m app.client
```

**Then:**
1. Enter your username
2. Enter your password
3. Type a message (e.g., "Hello") and press Enter

### Step 4: Check Results

**Server Terminal should show:**
```
[Client 127.0.0.1:XXXXX] Received chat message: seqno=1
[Client 127.0.0.1:XXXXX] ERROR: Signature verification failed
[Client 127.0.0.1:XXXXX] Sending error: SIG_FAIL
```

**Client Terminal may show:**
```
ERROR: Connection closed or error message
```

### Step 5: Restore Original Code

```powershell
# Restore backup
Copy-Item app\client.py.backup app\client.py -Force
```

---

## Test 2: Replay Attack Detection (REPLAY)

### Step 1: Start Server (Terminal 1)

```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python -m app.server
```

**Expected output:**
```
[OK] Server certificate loaded and validated
[OK] Server listening on 0.0.0.0:8888
Waiting for connections...
```

### Step 2: Run Replay Test Script (Terminal 2)

```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python scripts\test_replay.py
```

**When prompted:**
- Enter your username
- Enter your password

### Step 3: Check Results

**Test Script Output should show:**
```
REPLAY ATTACK: Resending message with seqno=1 (duplicate)
============================================================
This should be rejected with REPLAY error...

[SUCCESS] REPLAY attack detected and rejected!
Server response: {'error': 'REPLAY'}
```

**Server Terminal should show:**
```
[Client 127.0.0.1:XXXXX] Received chat message: seqno=1
[Client 127.0.0.1:XXXXX] Message (seqno=1): First message
[Client 127.0.0.1:XXXXX] Received chat message: seqno=2
[Client 127.0.0.1:XXXXX] Message (seqno=2): Second message
[Client 127.0.0.1:XXXXX] Received chat message: seqno=1
[Client 127.0.0.1:XXXXX] ERROR: Replay detected - seqno 1 <= last 2
```

---

## Quick Test Commands (Copy-Paste Ready)

### For Tampering Test:

**Terminal 1 (Server):**
```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python -m app.server
```

**Terminal 2 (Client - after modifying client.py):**
```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python -m app.client
```

### For Replay Test:

**Terminal 1 (Server):**
```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python -m app.server
```

**Terminal 2 (Test Script):**
```powershell
cd C:\Users\Mahad\Desktop\info-sec_A2\securechat-skeleton
python scripts\test_replay.py
```

---

## Verification Checklist

### Tampering Test ✓
- [ ] Server shows "Signature verification failed"
- [ ] Server shows "SIG_FAIL" error
- [ ] Screenshot captured

### Replay Test ✓
- [ ] Test script shows "REPLAY attack detected"
- [ ] Server shows "Replay detected"
- [ ] Server shows "REPLAY" error
- [ ] Screenshot captured

---

## Troubleshooting

### If server doesn't start:
```powershell
# Check if certificates exist
dir certs\*.pem

# If missing, generate them:
python scripts\gen_ca.py --name "FAST-NU Root CA"
python scripts\gen_cert.py --cn server.local --out certs/server
python scripts\gen_cert.py --cn client.local --out certs/client
```

### If test_replay.py fails:
```powershell
# Check if you have a registered user
# If not, register first using normal client:
python -m app.client
# Choose registration option
```

### If connection refused:
```powershell
# Make sure server is running first
# Check port 8888 is not in use
netstat -an | findstr 8888
```

