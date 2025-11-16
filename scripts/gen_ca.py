"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


def create_root_ca(name: str, output_dir: Path = Path("certs")):
    """
    Create a root CA with RSA keypair and self-signed X.509 certificate.
    
    Args:
        name: Common Name for the CA
        output_dir: Directory to store CA key and certificate
    """
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    # Certificate valid for 10 years
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_path = output_dir / "ca_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[OK] CA private key saved to: {key_path}")
    os.chmod(key_path, 0o600)  # Restrict permissions
    
    # Save certificate
    cert_path = output_dir / "ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[OK] CA certificate saved to: {cert_path}")
    
    print(f"\n[OK] Root CA '{name}' created successfully!")
    print(f"  Certificate: {cert_path}")
    print(f"  Private Key: {key_path}")
    print(f"  Valid until: {cert.not_valid_after}")


def main():
    parser = argparse.ArgumentParser(description="Create Root CA")
    parser.add_argument(
        "--name",
        type=str,
        default="FAST-NU Root CA",
        help="Common Name for the CA"
    )
    parser.add_argument(
        "--out",
        type=str,
        default="certs",
        help="Output directory for CA files (default: certs)"
    )
    args = parser.parse_args()
    
    create_root_ca(args.name, Path(args.out))


if __name__ == "__main__":
    main()
