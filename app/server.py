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
    BadCertError
)
from app.common.utils import b64e, b64d
from app.common.protocol import HelloMessage, ServerHelloMessage, ErrorMessage


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
            print(f"[Client {addr[0]}:{addr[1]}] ✓ Client certificate validated")
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
            print(f"[Client {addr[0]}:{addr[1]}] ✓ Server certificate sent")
        except Exception as e:
            print(f"[Client {addr[0]}:{addr[1]}] ERROR: Failed to send server certificate: {e}")
            error_msg = ErrorMessage(error="BAD_CERT")
            send_message(conn, error_msg.model_dump())
            return
        
        print(f"[Client {addr[0]}:{addr[1]}] ✓ Certificate exchange completed successfully")
        print("  Both parties authenticated")
        
        # TODO: Continue with login/DH key exchange/messaging
        
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
        print("✓ Server certificate loaded and validated")
    except Exception as e:
        print(f"ERROR: Server certificate validation failed: {e}")
        sys.exit(1)
    
    # Create server socket
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((server_host, server_port))
        server_sock.listen(5)
        print(f"✓ Server listening on {server_host}:{server_port}")
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
