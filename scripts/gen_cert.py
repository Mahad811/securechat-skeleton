"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


def issue_certificate(
    cn: str,
    ca_key_path: Path,
    ca_cert_path: Path,
    output_prefix: Path,
    valid_days: int = 365
):
    """
    Issue an RSA X.509 certificate signed by the root CA.
    
    Args:
        cn: Common Name (hostname) for the certificate
        ca_key_path: Path to CA private key
        ca_cert_path: Path to CA certificate
        output_prefix: Prefix for output files (e.g., certs/server -> certs/server_key.pem, certs/server_cert.pem)
        valid_days: Certificate validity period in days
    """
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Generate RSA private key for the entity (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Build certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # Issued by CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=valid_days)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),  # SAN with DNS name matching CN
        ]),
        critical=False,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False,
        ),
        critical=True,
    )
    
    # Sign certificate with CA private key
    cert = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Ensure output directory exists
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    
    # Save private key
    key_path = Path(f"{output_prefix}_key.pem")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[OK] Private key saved to: {key_path}")
    os.chmod(key_path, 0o600)  # Restrict permissions
    
    # Save certificate
    cert_path = Path(f"{output_prefix}_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[OK] Certificate saved to: {cert_path}")
    
    print(f"\n[OK] Certificate for '{cn}' issued successfully!")
    print(f"  Certificate: {cert_path}")
    print(f"  Private Key: {key_path}")
    print(f"  Valid until: {cert.not_valid_after}")
    print(f"  Signed by: {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")


def main():
    parser = argparse.ArgumentParser(description="Issue certificate signed by Root CA")
    parser.add_argument(
        "--cn",
        type=str,
        required=True,
        help="Common Name (hostname) for the certificate"
    )
    parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output prefix for certificate files (e.g., certs/server -> certs/server_key.pem, certs/server_cert.pem)"
    )
    parser.add_argument(
        "--ca-key",
        type=str,
        default="certs/ca_key.pem",
        help="Path to CA private key (default: certs/ca_key.pem)"
    )
    parser.add_argument(
        "--ca-cert",
        type=str,
        default="certs/ca_cert.pem",
        help="Path to CA certificate (default: certs/ca_cert.pem)"
    )
    parser.add_argument(
        "--valid-days",
        type=int,
        default=365,
        help="Certificate validity period in days (default: 365)"
    )
    args = parser.parse_args()
    
    issue_certificate(
        args.cn,
        Path(args.ca_key),
        Path(args.ca_cert),
        Path(args.out),
        args.valid_days
    )


if __name__ == "__main__":
    main()
