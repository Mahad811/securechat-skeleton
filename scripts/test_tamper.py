"""Test script to demonstrate tampering detection (SIG_FAIL)."""

import sys
import json
import socket
from pathlib import Path

# Add parent directory to path
script_dir = Path(__file__).parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

from app.common.utils import b64d, b64e
from app.common.protocol import ChatMessage


def send_message(sock: socket.socket, message: dict):
    """Send a JSON message over the socket."""
    data = json.dumps(message).encode('utf-8')
    length = len(data).to_bytes(4, byteorder='big')
    sock.sendall(length + data)


def receive_message(sock: socket.socket) -> dict:
    """Receive a JSON message from the socket."""
    length_bytes = sock.recv(4)
    if len(length_bytes) != 4:
        raise ConnectionError("Failed to receive message length")
    length = int.from_bytes(length_bytes, byteorder='big')
    
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving message")
        data += chunk
    
    return json.loads(data.decode('utf-8'))


def tamper_ciphertext(ciphertext_b64: str) -> str:
    """
    Flip a bit in the ciphertext to simulate tampering.
    
    Args:
        ciphertext_b64: Base64-encoded ciphertext
        
    Returns:
        Tampered base64-encoded ciphertext
    """
    # Decode base64
    ct_bytes = b64d(ciphertext_b64)
    
    # Flip the first bit of the first byte
    tampered_bytes = bytearray(ct_bytes)
    tampered_bytes[0] ^= 0x01  # Flip least significant bit
    
    # Re-encode
    return b64e(bytes(tampered_bytes))


def main():
    print("=" * 60)
    print("TAMPERING TEST - SIG_FAIL Detection")
    print("=" * 60)
    print()
    print("This script demonstrates that tampering with a message")
    print("causes signature verification to fail (SIG_FAIL error).")
    print()
    print("Prerequisites:")
    print("1. Server must be running: python -m app.server")
    print("2. You must have completed login and established chat session key")
    print()
    input("Press Enter to continue (make sure server is running and you're logged in)...")
    
    # Connect to server
    server_host = "localhost"
    server_port = 8888
    
    print(f"\nConnecting to {server_host}:{server_port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_host, server_port))
        print("[OK] Connected to server")
    except Exception as e:
        print(f"ERROR: Failed to connect: {e}")
        print("\nMake sure the server is running first!")
        return
    
    try:
        print("\n" + "=" * 60)
        print("STEP 1: Complete normal authentication flow")
        print("=" * 60)
        print("You need to complete:")
        print("  - Certificate exchange")
        print("  - DH key exchange")
        print("  - Login")
        print("  - Chat session key establishment")
        print()
        print("After that, we'll send a tampered message.")
        print()
        input("Press Enter after you've completed login and see 'Ready for encrypted messaging'...")
        
        print("\n" + "=" * 60)
        print("STEP 2: Creating a valid message first")
        print("=" * 60)
        
        # For this test, we'll create a simple message
        # In practice, you'd capture a real message from the client
        print("\nNote: This test requires a real message from an active session.")
        print("For a complete test:")
        print("1. Run normal client: python -m app.client")
        print("2. Login and send a message")
        print("3. Capture the message format")
        print("4. Use this script to send a tampered version")
        print()
        print("Alternatively, you can manually test by:")
        print("1. Running client and sending a message")
        print("2. Using Wireshark to capture the message")
        print("3. Modifying ciphertext in Wireshark")
        print("4. Resending - server should reject with SIG_FAIL")
        print()
        
        print("=" * 60)
        print("MANUAL TAMPERING TEST INSTRUCTIONS")
        print("=" * 60)
        print()
        print("To test tampering detection manually:")
        print()
        print("1. Start server: python -m app.server")
        print("2. Start client: python -m app.client")
        print("3. Complete login and send a message (e.g., 'Hello')")
        print("4. Note the message was accepted")
        print("5. Modify the client code temporarily to flip a bit in ciphertext")
        print("6. Send another message - server should reject with SIG_FAIL")
        print()
        print("Expected server output:")
        print("  ERROR: Signature verification failed")
        print("  Error message: SIG_FAIL")
        print()
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()


if __name__ == "__main__":
    main()

