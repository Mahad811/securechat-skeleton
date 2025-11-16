"""Test script to demonstrate replay attack detection (REPLAY)."""

import sys
import json
import socket
from pathlib import Path

# Add parent directory to path
script_dir = Path(__file__).parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

from app.common.utils import b64d, b64e, now_ms
from app.common.protocol import ChatMessage
from app.crypto.sign import load_private_key
from app.crypto.aes import aes_encrypt_ecb
from app.crypto.dh import generate_dh_keypair, compute_shared_secret, ks_to_key
from app.common.utils import sha256_bytes
from app.crypto.pki import load_certificate, load_certificate_from_bytes, validate_certificate, load_ca_certificate
from app.common.protocol import HelloMessage, ServerHelloMessage, ErrorMessage, DHClientMessage, DHServerMessage, LoginMessage
from app.common.utils import b64e, b64d


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


def main():
    print("=" * 60)
    print("REPLAY ATTACK TEST - REPLAY Detection")
    print("=" * 60)
    print()
    print("This script demonstrates that replaying a message with")
    print("a duplicate sequence number is rejected (REPLAY error).")
    print()
    print("Prerequisites:")
    print("1. Server must be running: python -m app.server")
    print("2. You must have a registered user account")
    print()
    input("Press Enter to continue (make sure server is running)...")
    
    server_host = "localhost"
    server_port = 8888
    
    print(f"\nConnecting to {server_host}:{server_port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_host, server_port))
        print("[OK] Connected to server")
    except Exception as e:
        print(f"ERROR: Failed to connect: {e}")
        return
    
    try:
        # Load certificates
        client_cert_path = Path("certs/client_cert.pem")
        ca_cert_path = Path("certs/ca_cert.pem")
        client_key_path = Path("certs/client_key.pem")
        
        if not all([client_cert_path.exists(), ca_cert_path.exists(), client_key_path.exists()]):
            print("ERROR: Certificates not found. Please generate them first.")
            return
        
        from cryptography.hazmat.primitives import serialization
        client_cert = load_certificate(client_cert_path)
        client_cert_data = client_cert.public_bytes(encoding=serialization.Encoding.PEM)
        ca_cert = load_ca_certificate(ca_cert_path)
        client_private_key = load_private_key(client_key_path)
        
        # Certificate exchange
        print("\n[1/6] Sending client certificate...")
        hello_msg = HelloMessage(cert=b64e(client_cert_data))
        send_message(sock, hello_msg.model_dump())
        
        print("[2/6] Receiving server certificate...")
        response = receive_message(sock)
        if "error" in response:
            print(f"ERROR: {response}")
            return
        
        server_hello = ServerHelloMessage(**response)
        server_cert_data = b64d(server_hello.cert)
        server_cert = load_certificate_from_bytes(server_cert_data)
        validate_certificate(server_cert, ca_cert, expected_cn="server.local")
        print("[OK] Certificates exchanged")
        
        # DH exchange for login
        print("[3/6] Performing DH key exchange...")
        cli_priv, cli_pub = generate_dh_keypair()
        send_message(sock, DHClientMessage(pub=str(cli_pub)).model_dump())
        
        dh_resp = receive_message(sock)
        dh_server = DHServerMessage(**dh_resp)
        srv_pub = int(dh_server.pub)
        shared_secret = compute_shared_secret(cli_priv, srv_pub)
        aes_key = ks_to_key(shared_secret)
        print("[OK] DH key exchange completed")
        
        # Login
        print("[4/6] Logging in...")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        import json
        payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        from app.crypto.aes import aes_encrypt_ecb
        ct = aes_encrypt_ecb(aes_key, payload)
        login_msg = LoginMessage(ct=b64e(ct))
        send_message(sock, login_msg.model_dump())
        
        resp = receive_message(sock)
        if resp.get("type") != "login_ok":
            print(f"ERROR: Login failed: {resp}")
            return
        print("[OK] Login successful")
        
        # Chat session key
        print("[5/6] Establishing chat session key...")
        chat_priv, chat_pub = generate_dh_keypair()
        send_message(sock, DHClientMessage(pub=str(chat_pub)).model_dump())
        
        chat_resp = receive_message(sock)
        chat_dh_server = DHServerMessage(**chat_resp)
        chat_srv_pub = int(chat_dh_server.pub)
        chat_shared_secret = compute_shared_secret(chat_priv, chat_srv_pub)
        chat_session_key = ks_to_key(chat_shared_secret)
        print("[OK] Chat session key established")
        
        # Send first message (seqno=1)
        print("\n[6/6] Sending first message (seqno=1)...")
        seqno = 1
        timestamp = now_ms()
        plaintext = "First message"
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aes_encrypt_ecb(chat_session_key, plaintext_bytes)
        ciphertext_b64 = b64e(ciphertext)
        
        seqno_bytes = seqno.to_bytes(8, byteorder='big')
        ts_bytes = timestamp.to_bytes(8, byteorder='big')
        ct_bytes = b64d(ciphertext_b64)
        hash_input = seqno_bytes + ts_bytes + ct_bytes
        message_hash = sha256_bytes(hash_input)
        signature = client_private_key.sign(message_hash, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = b64e(signature)
        
        msg1 = ChatMessage(seqno=seqno, ts=timestamp, ct=ciphertext_b64, sig=signature_b64)
        send_message(sock, msg1.model_dump())
        
        # Wait for response (server doesn't send response for valid messages)
        print("[OK] First message sent (seqno=1)")
        
        # Send second message (seqno=2) - should be accepted
        print("\nSending second message (seqno=2)...")
        seqno = 2
        timestamp = now_ms()
        plaintext = "Second message"
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aes_encrypt_ecb(chat_session_key, plaintext_bytes)
        ciphertext_b64 = b64e(ciphertext)
        
        seqno_bytes = seqno.to_bytes(8, byteorder='big')
        ts_bytes = timestamp.to_bytes(8, byteorder='big')
        ct_bytes = b64d(ciphertext_b64)
        hash_input = seqno_bytes + ts_bytes + ct_bytes
        message_hash = sha256_bytes(hash_input)
        signature = client_private_key.sign(message_hash, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = b64e(signature)
        
        msg2 = ChatMessage(seqno=seqno, ts=timestamp, ct=ciphertext_b64, sig=signature_b64)
        send_message(sock, msg2.model_dump())
        print("[OK] Second message sent (seqno=2)")
        
        # REPLAY ATTACK: Resend message with seqno=1 (duplicate)
        print("\n" + "=" * 60)
        print("REPLAY ATTACK: Resending message with seqno=1 (duplicate)")
        print("=" * 60)
        print("This should be rejected with REPLAY error...")
        print()
        
        # Resend the first message (same seqno=1)
        send_message(sock, msg1.model_dump())
        
        response = receive_message(sock)
        if response.get("error") == "REPLAY":
            print("[SUCCESS] REPLAY attack detected and rejected!")
            print(f"Server response: {response}")
        else:
            print(f"[FAIL] Expected REPLAY error, got: {response}")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()
        print("\nConnection closed")


if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    main()

