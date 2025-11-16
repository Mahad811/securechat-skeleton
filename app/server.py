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
from app.storage.db import UserDB
from app.common.utils import b64e, b64d
from app.common.protocol import (
    HelloMessage,
    ServerHelloMessage,
    ErrorMessage,
    DHClientMessage,
    DHServerMessage,
    RegisterMessage,
    LoginMessage,
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
