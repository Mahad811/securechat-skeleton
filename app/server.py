"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import json
import socket
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from app.crypto.pki import (
    load_certificate,
    load_certificate_from_bytes,
    validate_certificate,
    load_ca_certificate,
    BadCertError,
)
from app.crypto.dh import generate_dh_keypair, compute_shared_secret, ks_to_key
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.sign import get_public_key_from_cert, rsa_verify, load_private_key, rsa_sign
from app.storage.db import UserDB
from app.storage.transcript import Transcript, get_cert_fingerprint
from app.common.utils import b64e, b64d, sha256_bytes, now_ms
from app.common.protocol import (
    HelloMessage,
    ServerHelloMessage,
    ErrorMessage,
    DHClientMessage,
    DHServerMessage,
    RegisterMessage,
    LoginMessage,
    ChatMessage,
    ReceiptMessage,
)


def send_message(sock: socket.socket, message: dict):
    """Send a JSON message over the socket."""
    data = json.dumps(message).encode('utf-8')
    # Send length prefix
    length = len(data).to_bytes(4, byteorder='big')
    sock.sendall(length + data)


def receive_message(sock: socket.socket) -> dict:
    """Receive a JSON message from the socket."""
    # Receive length prefix
    length_bytes = sock.recv(4)
    if len(length_bytes) != 4:
        raise ConnectionError("Failed to receive message length")
    length = int.from_bytes(length_bytes, byteorder='big')
    
    # Receive message data
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving message")
        data += chunk
    
    return json.loads(data.decode('utf-8'))


def handle_client(conn: socket.socket, addr: tuple):
    """Handle a client connection."""
    print(f"\n[Client {addr[0]}:{addr[1]}] Connected")
    
    # Track sequence number for replay protection
    last_seqno = 0
    client_cert_data = None
    chat_session_key = None
    
    try:
        # Receive client certificate
        print(f"[Client {addr[0]}:{addr[1]}] Waiting for client certificate...")
        request = receive_message(conn)
        
        # Parse client hello
        try:
            client_hello = HelloMessage(**request)
        except Exception as e:
            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Invalid hello message: {e}")
            error_msg = ErrorMessage(error="BAD_CERT")
            send_message(conn, error_msg.model_dump())
            return
        
        client_cert_data = b64d(client_hello.cert)
        
        # Store client cert data for later signature verification
        stored_client_cert_data = client_cert_data
        
        # Validate client certificate
        print(f"[Client {addr[0]}:{addr[1]}] Validating client certificate...")
        try:
            client_cert = load_certificate_from_bytes(client_cert_data)
            ca_cert = load_ca_certificate()
            
            # Validate certificate (CN check optional for client)
            validate_certificate(client_cert, ca_cert)
            
            client_cn = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            print(f"[Client {addr[0]}:{addr[1]}] [OK] Client certificate validated")
            print(f"  Client CN: {client_cn}")
            
        except BadCertError as e:
            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Client certificate validation failed: {e}")
            error_msg = ErrorMessage(error="BAD_CERT")
            send_message(conn, error_msg.model_dump())
            return
        except Exception as e:
            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Unexpected error: {e}")
            error_msg = ErrorMessage(error="BAD_CERT")
            send_message(conn, error_msg.model_dump())
            return
        
        # Send server certificate
        print(f"[Client {addr[0]}:{addr[1]}] Sending server certificate...")
        server_cert_path = Path("certs/server_cert.pem")
        
        if not server_cert_path.exists():
            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Server certificate not found")
            error_msg = ErrorMessage(error="BAD_CERT")
            send_message(conn, error_msg.model_dump())
            return
        
        try:
            server_cert = load_certificate(server_cert_path)
            server_cert_data = server_cert.public_bytes(encoding=serialization.Encoding.PEM)
            server_hello = ServerHelloMessage(cert=b64e(server_cert_data))
            send_message(conn, server_hello.model_dump())
            print(f"[Client {addr[0]}:{addr[1]}] [OK] Server certificate sent")
        except Exception as e:
            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Failed to send server certificate: {e}")
            error_msg = ErrorMessage(error="BAD_CERT")
            send_message(conn, error_msg.model_dump())
            return
        
        print(f"[Client {addr[0]}:{addr[1]}] [OK] Certificate exchange completed successfully")
        print("  Both parties authenticated")

        # -----------------------------
        # Diffie–Hellman key exchange
        # -----------------------------
        print(f"[Client {addr[0]}:{addr[1]}] Starting DH key exchange...")

        # Receive DH client message (client public value)
        dh_req = receive_message(conn)
        dh_client = DHClientMessage(**dh_req)
        client_pub = int(dh_client.pub)

        # Generate server keypair and compute shared secret
        srv_priv, srv_pub = generate_dh_keypair()
        shared_secret = compute_shared_secret(srv_priv, client_pub)
        aes_key = ks_to_key(shared_secret)

        # Send server DH public value
        dh_server = DHServerMessage(pub=str(srv_pub))
        send_message(conn, dh_server.model_dump())
        print(f"[Client {addr[0]}:{addr[1]}] [OK] DH key exchange completed")

        # -----------------------------
        # Encrypted registration/login
        # -----------------------------
        db = UserDB()

        # Receive encrypted registration or login message
        msg = receive_message(conn)
        msg_type = msg.get("type")

        if msg_type == "register":
            reg = RegisterMessage(**msg)
            ciphertext = b64d(reg.ct)
            # Decrypt registration payload
            plaintext = aes_decrypt_ecb(aes_key, ciphertext)
            data = json.loads(plaintext.decode("utf-8"))
            email = data.get("email")
            username = data.get("username")
            password = data.get("password")

            print(f"[Client {addr[0]}:{addr[1]}] Registration attempt for username='{username}' email='{email}'")

            if not email or not username or not password:
                err = ErrorMessage(error="INVALID_REG")
                send_message(conn, err.model_dump())
                return

            ok = db.create_user(email=email, username=username, password=password)
            if not ok:
                err = ErrorMessage(error="USER_EXISTS")
                send_message(conn, err.model_dump())
                print(f"[Client {addr[0]}:{addr[1]}] Registration failed: user exists")
                return

            # Registration successful
            send_message(conn, {"type": "register_ok"})
            print(f"[Client {addr[0]}:{addr[1]}] [OK] Registration succeeded")

        elif msg_type == "login":
            login = LoginMessage(**msg)
            ciphertext = b64d(login.ct)
            plaintext = aes_decrypt_ecb(aes_key, ciphertext)
            data = json.loads(plaintext.decode("utf-8"))
            username = data.get("username")
            password = data.get("password")

            print(f"[Client {addr[0]}:{addr[1]}] Login attempt for username='{username}'")

            if not username or not password:
                err = ErrorMessage(error="INVALID_LOGIN")
                send_message(conn, err.model_dump())
                return

            # At this point, certificate is already validated (from earlier)
            # Now verify salted password hash from DB.
            if db.verify_user(username=username, password=password):
                send_message(conn, {"type": "login_ok"})
                print(f"[Client {addr[0]}:{addr[1]}] [OK] Login succeeded")
                
                # -----------------------------
                # Establish chat session key (second DH exchange)
                # -----------------------------
                print(f"[Client {addr[0]}:{addr[1]}] Establishing chat session key...")
                
                # Receive client's chat DH public value
                dh_chat_req = receive_message(conn)
                dh_chat_client = DHClientMessage(**dh_chat_req)
                chat_client_pub = int(dh_chat_client.pub)
                
                # Generate server chat keypair and compute shared secret
                chat_srv_priv, chat_srv_pub = generate_dh_keypair()
                chat_shared_secret = compute_shared_secret(chat_srv_priv, chat_client_pub)
                chat_session_key = ks_to_key(chat_shared_secret)
                
                # Send server's chat DH public value
                dh_chat_server = DHServerMessage(pub=str(chat_srv_pub))
                send_message(conn, dh_chat_server.model_dump())
                print(f"[Client {addr[0]}:{addr[1]}] [OK] Chat session key established")
                print("  Ready for encrypted messaging")
                
                # chat_session_key is already set above
                
                # Initialize transcript
                transcript_path = Path("transcripts") / f"server_session_{addr[0]}_{addr[1]}_{now_ms()}.txt"
                transcript = Transcript(transcript_path)
                client_cert_fingerprint = get_cert_fingerprint(stored_client_cert_data)
                
                # Load server private key for receipt signing
                server_key_path = Path("certs/server_key.pem")
                if not server_key_path.exists():
                    print(f"[Client {addr[0]}:{addr[1]}] ERROR: Server private key not found")
                    return
                server_private_key = load_private_key(server_key_path)
                
                # -----------------------------
                # Receive and verify encrypted chat messages
                # -----------------------------
                print(f"[Client {addr[0]}:{addr[1]}] Waiting for chat messages...")
                
                while True:
                    try:
                        # Receive chat message
                        msg = receive_message(conn)
                        
                        # Check if it's a chat message
                        if msg.get("type") != "msg":
                            # Not a chat message, might be other protocol message
                            continue
                        
                        chat_msg = ChatMessage(**msg)
                        
                        # 1. Check sequence number (replay protection)
                        if chat_msg.seqno <= last_seqno:
                            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Replay detected - seqno {chat_msg.seqno} <= last {last_seqno}")
                            err = ErrorMessage(error="REPLAY")
                            send_message(conn, err.model_dump())
                            return
                        
                        last_seqno = chat_msg.seqno
                        
                        # 2. Verify signature
                        # Recompute hash: SHA256(seqno || timestamp || ciphertext)
                        seqno_bytes = chat_msg.seqno.to_bytes(8, byteorder='big')
                        ts_bytes = chat_msg.ts.to_bytes(8, byteorder='big')
                        ct_bytes = b64d(chat_msg.ct)
                        hash_input = seqno_bytes + ts_bytes + ct_bytes
                        message_hash = sha256_bytes(hash_input)
                        
                        # Get client's public key from certificate
                        client_public_key = get_public_key_from_cert(stored_client_cert_data)
                        signature = b64d(chat_msg.sig)
                        
                        # Verify signature
                        if not rsa_verify(client_public_key, message_hash, signature):
                            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Signature verification failed")
                            err = ErrorMessage(error="SIG_FAIL")
                            send_message(conn, err.model_dump())
                            return
                        
                        # 3. Decrypt ciphertext
                        plaintext_bytes = aes_decrypt_ecb(chat_session_key, ct_bytes)
                        plaintext = plaintext_bytes.decode('utf-8')
                        
                        # 4. Display message
                        print(f"[Client {addr[0]}:{addr[1]}] Message (seqno={chat_msg.seqno}): {plaintext}")
                        
                        # 5. Store in transcript
                        transcript.append(
                            seqno=chat_msg.seqno,
                            timestamp=chat_msg.ts,
                            ciphertext=chat_msg.ct,
                            signature=chat_msg.sig,
                            peer_cert_fingerprint=client_cert_fingerprint
                        )
                        
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print(f"[Client {addr[0]}:{addr[1]}] ERROR processing message: {e}")
                        import traceback
                        traceback.print_exc()
                        break
                
                # -----------------------------
                # Generate and exchange Session Receipt
                # -----------------------------
                print(f"[Client {addr[0]}:{addr[1]}] Generating session receipt...")
                
                # Check if we received client's receipt first
                try:
                    # Try to receive client receipt (non-blocking check)
                    # In practice, we'd wait for it, but for simplicity, generate our receipt
                    pass
                except:
                    pass
                
                # Generate server receipt
                transcript_hash = transcript.get_transcript_hash()
                transcript_hash_bytes = transcript.get_transcript_hash_bytes()
                
                # Sign transcript hash
                receipt_signature = rsa_sign(server_private_key, transcript_hash_bytes)
                receipt_sig_b64 = b64e(receipt_signature)
                
                # Create receipt
                server_receipt = ReceiptMessage(
                    peer="server",
                    first_seq=transcript.get_first_seqno() or 0,
                    last_seq=transcript.get_last_seqno() or 0,
                    transcript_sha256=transcript_hash,
                    sig=receipt_sig_b64
                )
                
                # Try to receive client receipt if available
                try:
                    client_receipt_data = receive_message(conn)
                    if client_receipt_data.get("type") == "receipt":
                        client_receipt = ReceiptMessage(**client_receipt_data)
                        print(f"[Client {addr[0]}:{addr[1]}] [OK] Received client receipt")
                        print(f"  Client transcript hash: {client_receipt.transcript_sha256}")
                        
                        # Verify client receipt signature
                        client_public_key = get_public_key_from_cert(stored_client_cert_data)
                        client_receipt_hash_bytes = bytes.fromhex(client_receipt.transcript_sha256)
                        if rsa_verify(client_public_key, client_receipt_hash_bytes, b64d(client_receipt.sig)):
                            print(f"[Client {addr[0]}:{addr[1]}] [OK] Client receipt signature verified")
                        else:
                            print(f"[Client {addr[0]}:{addr[1]}] WARNING: Client receipt signature verification failed")
                except Exception as e:
                    print(f"[Client {addr[0]}:{addr[1]}] Note: Could not receive client receipt: {e}")
                
                # Send server receipt
                send_message(conn, server_receipt.model_dump())
                print(f"[Client {addr[0]}:{addr[1]}] [OK] Server receipt sent")
                print(f"  Transcript hash: {transcript_hash}")
                print(f"  Sequence range: {server_receipt.first_seq} - {server_receipt.last_seq}")
                print(f"  Transcript saved to: {transcript_path}")
                
            else:
                err = ErrorMessage(error="LOGIN_FAIL")
                send_message(conn, err.model_dump())
                print(f"[Client {addr[0]}:{addr[1]}] Login failed (bad credentials)")
                return

        else:
            err = ErrorMessage(error="UNKNOWN_MSG")
            send_message(conn, err.model_dump())
            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Unknown message type: {msg_type}")
            return

    except Exception as e:
        print(f"[Client {addr[0]}:{addr[1]}] ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()
        print(f"[Client {addr[0]}:{addr[1]}] Connection closed")


def main():
    # Configuration
    server_host = "0.0.0.0"
    server_port = 8888
    server_cert_path = Path("certs/server_cert.pem")
    ca_cert_path = Path("certs/ca_cert.pem")
    
    # Check if certificates exist
    if not server_cert_path.exists():
        print(f"ERROR: Server certificate not found at {server_cert_path}")
        print("Please run: python scripts/gen_cert.py --cn server.local --out certs/server")
        sys.exit(1)
    
    if not ca_cert_path.exists():
        print(f"ERROR: CA certificate not found at {ca_cert_path}")
        print("Please run: python scripts/gen_ca.py --name 'FAST-NU Root CA'")
        sys.exit(1)
    
    # Load and validate server certificate
    try:
        server_cert = load_certificate(server_cert_path)
        ca_cert = load_ca_certificate(ca_cert_path)
        validate_certificate(server_cert, ca_cert, expected_cn="server.local")
        print("[OK] Server certificate loaded and validated")
    except Exception as e:
        print(f"ERROR: Server certificate validation failed: {e}")
        sys.exit(1)
    
    # Create server socket
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((server_host, server_port))
        server_sock.listen(5)
        print(f"[OK] Server listening on {server_host}:{server_port}")
        print("Waiting for connections...")
    except Exception as e:
        print(f"ERROR: Failed to start server: {e}")
        sys.exit(1)
    
    try:
        while True:
            conn, addr = server_sock.accept()
            handle_client(conn, addr)
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
