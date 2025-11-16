"""Inspect X.509 certificates - alternative to openssl x509 -text -noout."""

import argparse
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend


def format_name(name):
    """Format X.509 name object as string."""
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def inspect_certificate(cert_path: Path):
    """Inspect and display certificate details."""
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        print(f"ERROR: Failed to load certificate: {e}")
        sys.exit(1)
    
    print("=" * 80)
    print(f"Certificate: {cert_path}")
    print("=" * 80)
    print()
    
    # Version
    print("Certificate:")
    print(f"    Data:")
    print(f"        Version: {cert.version.value} ({cert.version.name})")
    print(f"        Serial Number:")
    print(f"            {cert.serial_number}")
    print()
    
    # Signature Algorithm
    print(f"    Signature Algorithm: {cert.signature_algorithm_oid._name}")
    print()
    
    # Issuer
    print(f"    Issuer:")
    for attr in cert.issuer:
        print(f"        {attr.oid._name}={attr.value}")
    print()
    
    # Validity
    print(f"    Validity")
    print(f"        Not Before: {cert.not_valid_before}")
    print(f"        Not After : {cert.not_valid_after}")
    print()
    
    # Subject
    print(f"    Subject:")
    for attr in cert.subject:
        print(f"        {attr.oid._name}={attr.value}")
    print()
    
    # Subject Public Key Info
    print(f"    Subject Public Key Info:")
    public_key = cert.public_key()
    if hasattr(public_key, 'key_size'):
        print(f"        Public Key Algorithm: {public_key.__class__.__name__}")
        print(f"        Key Size: {public_key.key_size} bits")
    print()
    
    # Extensions
    try:
        extensions = cert.extensions
        if extensions:
            print(f"    X509v3 extensions:")
            for ext in extensions:
                print(f"        {ext.oid._name}:")
                if ext.critical:
                    print(f"            Critical: Yes")
                
                # Handle specific extensions
                if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                    bc = ext.value
                    print(f"            CA:{bc.ca}")
                    if bc.path_length is not None:
                        print(f"            pathlen:{bc.path_length}")
                
                elif ext.oid == ExtensionOID.KEY_USAGE:
                    ku = ext.value
                    flags = []
                    if ku.digital_signature:
                        flags.append("Digital Signature")
                    if ku.content_commitment:
                        flags.append("Content Commitment")
                    if ku.key_encipherment:
                        flags.append("Key Encipherment")
                    if ku.data_encipherment:
                        flags.append("Data Encipherment")
                    if ku.key_agreement:
                        flags.append("Key Agreement")
                    if ku.key_cert_sign:
                        flags.append("Certificate Sign")
                    if ku.crl_sign:
                        flags.append("CRL Sign")
                    if ku.encipher_only:
                        flags.append("Encipher Only")
                    if ku.decipher_only:
                        flags.append("Decipher Only")
                    print(f"            {', '.join(flags)}")
                
                elif ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    san = ext.value
                    for name in san:
                        print(f"            {name}")
                
                else:
                    print(f"            {ext.value}")
            print()
    except Exception as e:
        pass
    
    # Signature
    print(f"    Signature Algorithm: {cert.signature_algorithm_oid._name}")
    sig_hex = cert.signature.hex()
    # Format signature in chunks
    sig_formatted = ' '.join(sig_hex[i:i+2] for i in range(0, min(64, len(sig_hex)), 2))
    print(f"    Signature Value:")
    print(f"        {sig_formatted}...")
    print()
    
    # Additional Info
    print("=" * 80)
    print("Additional Information:")
    print(f"  - Is CA: {any(ext.oid == ExtensionOID.BASIC_CONSTRAINTS and ext.value.ca for ext in cert.extensions)}")
    print(f"  - Is Self-Signed: {cert.subject == cert.issuer}")
    
    # Get CN
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print(f"  - Common Name (CN): {cn}")
    except:
        pass
    
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Inspect X.509 certificate")
    parser.add_argument(
        "cert_path",
        type=str,
        help="Path to certificate file (PEM format)"
    )
    args = parser.parse_args()
    
    cert_path = Path(args.cert_path)
    if not cert_path.exists():
        print(f"ERROR: Certificate file not found: {cert_path}")
        sys.exit(1)
    
    inspect_certificate(cert_path)


if __name__ == "__main__":
    main()

