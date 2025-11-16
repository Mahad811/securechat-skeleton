"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from pathlib import Path


def load_private_key(key_path: Path) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: Path to private key file
        
    Returns:
        RSA private key object
    """
    with open(key_path, "rb") as f:
        key_data = f.read()
    return load_pem_private_key(key_data, password=None, backend=default_backend())


def rsa_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """
    Sign a message using RSA with SHA-256 and PKCS#1 v1.5 padding.
    
    Args:
        private_key: RSA private key
        message: Message bytes to sign
        
    Returns:
        Signature bytes
    """
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def rsa_verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """
    Verify an RSA signature using SHA-256 and PKCS#1 v1.5 padding.
    
    Args:
        public_key: RSA public key
        message: Original message bytes
        signature: Signature bytes to verify
        
    Returns:
        True if signature is valid, False otherwise
        
    Raises:
        Exception: If signature verification fails
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def get_public_key_from_cert(cert_data: bytes) -> rsa.RSAPublicKey:
    """
    Extract RSA public key from X.509 certificate.
    
    Args:
        cert_data: Certificate data in PEM format
        
    Returns:
        RSA public key object
    """
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()
    
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Certificate does not contain an RSA public key")
    
    return public_key
