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
        print("✓ Connected to server")
    except Exception as e:
        print(f"ERROR: Failed to connect to server: {e}")
        sys.exit(1)
    
    try:
        # Send client certificate
        print("Sending client certificate...")
        hello_msg = HelloMessage(cert=b64e(client_cert_data))
        send_message(sock, hello_msg.model_dump())
        print("✓ Client certificate sent")
        
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
            print("✓ Server certificate validated successfully")
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
        
        print("\n✓ Certificate exchange completed successfully!")
        print("  Both parties authenticated")
        
        # TODO: Continue with login/DH key exchange/messaging
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()
        print("Connection closed")


if __name__ == "__main__":
    main()
