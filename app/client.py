"""Client skeleton — plain TCP; no TLS. See assignment spec."""

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
from app.crypto.sign import load_private_key, rsa_sign
from app.storage.transcript import Transcript, get_cert_fingerprint
from app.common.utils import b64e, b64d, now_ms, sha256_bytes
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


def main():
    # Configuration
    server_host = "localhost"
    server_port = 8888
    client_cert_path = Path("certs/client_cert.pem")
    ca_cert_path = Path("certs/ca_cert.pem")
    
    # Check if certificates exist
    if not client_cert_path.exists():
        print(f"ERROR: Client certificate not found at {client_cert_path}")
        print("Please run: python scripts/gen_cert.py --cn client.local --out certs/client")
        sys.exit(1)
    
    if not ca_cert_path.exists():
        print(f"ERROR: CA certificate not found at {ca_cert_path}")
        print("Please run: python scripts/gen_ca.py --name 'FAST-NU Root CA'")
        sys.exit(1)
    
    # Load client certificate
    try:
        client_cert = load_certificate(client_cert_path)
        client_cert_data = client_cert.public_bytes(encoding=serialization.Encoding.PEM)
    except Exception as e:
        print(f"ERROR: Failed to load client certificate: {e}")
        sys.exit(1)
    
    # Load CA certificate
    try:
        ca_cert = load_ca_certificate(ca_cert_path)
    except Exception as e:
        print(f"ERROR: Failed to load CA certificate: {e}")
        sys.exit(1)
    
    # Connect to server
    print(f"Connecting to {server_host}:{server_port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_host, server_port))
        print("[OK] Connected to server")
    except Exception as e:
        print(f"ERROR: Failed to connect to server: {e}")
        sys.exit(1)
    
    try:
        # Send client certificate
        print("Sending client certificate...")
        hello_msg = HelloMessage(cert=b64e(client_cert_data))
        send_message(sock, hello_msg.model_dump())
        print("[OK] Client certificate sent")
        
        # Receive server certificate
        print("Waiting for server certificate...")
        response = receive_message(sock)
        
        # Check for error message
        if "error" in response:
            error_msg = ErrorMessage(**response)
            print(f"ERROR: Server returned error: {error_msg.error}")
            sys.exit(1)
        
        # Parse server hello
        server_hello = ServerHelloMessage(**response)
        server_cert_data = b64d(server_hello.cert)
        
        # Validate server certificate
        print("Validating server certificate...")
        try:
            server_cert = load_certificate_from_bytes(server_cert_data)
            validate_certificate(server_cert, ca_cert, expected_cn="server.local")
            print("[OK] Server certificate validated successfully")
            print(f"  Server CN: {server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        except BadCertError as e:
            print(f"ERROR: Server certificate validation failed: {e}")
            # Send error acknowledgment
            error_ack = ErrorMessage(error="BAD_CERT")
            send_message(sock, error_ack.model_dump())
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: Unexpected error during certificate validation: {e}")
            sys.exit(1)
        
        print("\n[OK] Certificate exchange completed successfully!")
        print("  Both parties authenticated")

        # -----------------------------
        # Diffie–Hellman key exchange
        # -----------------------------
        print("Starting DH key exchange...")
        # Generate client DH keypair
        cli_priv, cli_pub = generate_dh_keypair()
        dh_client = DHClientMessage(pub=str(cli_pub))
        send_message(sock, dh_client.model_dump())

        # Receive server DH response
        dh_resp = receive_message(sock)
        dh_server = DHServerMessage(**dh_resp)
        srv_pub = int(dh_server.pub)

        # Compute shared secret and derive AES-128 key
        shared_secret = compute_shared_secret(cli_priv, srv_pub)
        aes_key = ks_to_key(shared_secret)
        print("[OK] DH key exchange completed; AES session key established")

        # -----------------------------
        # Encrypted registration/login
        # -----------------------------
        mode = input("Do you want to [r]egister or [l]ogin? ").strip().lower()

        if mode.startswith("r"):
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()

            payload = json.dumps(
                {"email": email, "username": username, "password": password}
            ).encode("utf-8")
            ct = aes_encrypt_ecb(aes_key, payload)
            reg_msg = RegisterMessage(ct=b64e(ct))
            send_message(sock, reg_msg.model_dump())

            # Wait for response
            resp = receive_message(sock)
            if resp.get("type") == "register_ok":
                print("[OK] Registration successful")
            elif resp.get("error") == "USER_EXISTS":
                print("ERROR: Username or email already registered")
            else:
                print(f"ERROR: Registration failed: {resp}")

        else:
            username = input("Username: ").strip()
            password = input("Password: ").strip()

            payload = json.dumps(
                {"username": username, "password": password}
            ).encode("utf-8")
            ct = aes_encrypt_ecb(aes_key, payload)
            login_msg = LoginMessage(ct=b64e(ct))
            send_message(sock, login_msg.model_dump())

            resp = receive_message(sock)
            if resp.get("type") == "login_ok":
                print("[OK] Login successful")
                
                # -----------------------------
                # Establish chat session key (second DH exchange)
                # -----------------------------
                print("Establishing chat session key...")
                # Generate new DH keypair for chat session
                chat_priv, chat_pub = generate_dh_keypair()
                dh_chat_client = DHClientMessage(pub=str(chat_pub))
                send_message(sock, dh_chat_client.model_dump())
                
                # Receive server's chat DH public value
                dh_chat_resp = receive_message(sock)
                dh_chat_server = DHServerMessage(**dh_chat_resp)
                chat_srv_pub = int(dh_chat_server.pub)
                
                # Compute shared secret and derive chat session key
                chat_shared_secret = compute_shared_secret(chat_priv, chat_srv_pub)
                chat_session_key = ks_to_key(chat_shared_secret)
                print("[OK] Chat session key established")
                print("  Ready for encrypted messaging")
                
                # Load client private key for signing messages
                client_key_path = Path("certs/client_key.pem")
                if not client_key_path.exists():
                    print("ERROR: Client private key not found for message signing")
                    sys.exit(1)
                client_private_key = load_private_key(client_key_path)
                
                # Initialize transcript
                transcript_path = Path("transcripts") / f"client_session_{now_ms()}.txt"
                transcript = Transcript(transcript_path)
                server_cert_fingerprint = get_cert_fingerprint(server_cert_data)
                
                # -----------------------------
                # Encrypted chat messaging
                # -----------------------------
                seqno = 0
                print("\n--- Chat Session Started ---")
                print("Type messages (or 'quit' to exit):")
                
                while True:
                    try:
                        # Read plaintext from console
                        plaintext = input("You: ").strip()
                        if not plaintext:
                            continue
                        if plaintext.lower() == 'quit':
                            break
                        
                        # Increment sequence number
                        seqno += 1
                        timestamp = now_ms()
                        
                        # Encrypt plaintext with AES-128
                        plaintext_bytes = plaintext.encode('utf-8')
                        ciphertext = aes_encrypt_ecb(chat_session_key, plaintext_bytes)
                        ciphertext_b64 = b64e(ciphertext)
                        
                        # Compute hash: SHA256(seqno || timestamp || ciphertext)
                        seqno_bytes = seqno.to_bytes(8, byteorder='big')
                        ts_bytes = timestamp.to_bytes(8, byteorder='big')
                        ct_bytes = b64d(ciphertext_b64)
                        hash_input = seqno_bytes + ts_bytes + ct_bytes
                        message_hash = sha256_bytes(hash_input)
                        
                        # Sign hash with RSA private key
                        signature = rsa_sign(client_private_key, message_hash)
                        signature_b64 = b64e(signature)
                        
                        # Send message
                        chat_msg = ChatMessage(
                            seqno=seqno,
                            ts=timestamp,
                            ct=ciphertext_b64,
                            sig=signature_b64
                        )
                        send_message(sock, chat_msg.model_dump())
                        
                        # Store in transcript
                        transcript.append(
                            seqno=seqno,
                            timestamp=timestamp,
                            ciphertext=ciphertext_b64,
                            signature=signature_b64,
                            peer_cert_fingerprint=server_cert_fingerprint
                        )
                        
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print(f"ERROR sending message: {e}")
                        break
                
                print("\n--- Chat Session Ended ---")
                
                # -----------------------------
                # Generate and exchange Session Receipt
                # -----------------------------
                print("Generating session receipt...")
                transcript_hash = transcript.get_transcript_hash()
                transcript_hash_bytes = transcript.get_transcript_hash_bytes()
                
                # Sign transcript hash
                receipt_signature = rsa_sign(client_private_key, transcript_hash_bytes)
                receipt_sig_b64 = b64e(receipt_signature)
                
                # Create receipt
                receipt = ReceiptMessage(
                    peer="client",
                    first_seq=transcript.get_first_seqno() or 0,
                    last_seq=transcript.get_last_seqno() or 0,
                    transcript_sha256=transcript_hash,
                    sig=receipt_sig_b64
                )
                
                # Send receipt to server
                send_message(sock, receipt.model_dump())
                print(f"[OK] Session receipt sent")
                print(f"  Transcript hash: {transcript_hash}")
                print(f"  Sequence range: {receipt.first_seq} - {receipt.last_seq}")
                print(f"  Transcript saved to: {transcript_path}")
                
                # Receive server's receipt
                try:
                    server_receipt_data = receive_message(sock)
                    if server_receipt_data.get("type") == "receipt":
                        server_receipt = ReceiptMessage(**server_receipt_data)
                        print(f"[OK] Received server receipt")
                        print(f"  Server transcript hash: {server_receipt.transcript_sha256}")
                except Exception as e:
                    print(f"Warning: Could not receive server receipt: {e}")
                
            elif resp.get("error") == "LOGIN_FAIL":
                print("ERROR: Invalid username or password")
            else:
                print(f"ERROR: Login failed: {resp}")

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()
        print("Connection closed")


if __name__ == "__main__":
    main()
