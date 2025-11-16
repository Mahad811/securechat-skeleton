"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime


class PKIError(Exception):
    """Base exception for PKI validation errors."""
    pass


class BadCertError(PKIError):
    """Certificate validation failed."""
    pass


def load_certificate(cert_path: Path) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Loaded X.509 certificate
        
    Raises:
        BadCertError: If certificate cannot be loaded
    """
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        raise BadCertError(f"Failed to load certificate: {e}")


def load_certificate_from_bytes(cert_data: bytes) -> x509.Certificate:
    """
    Load an X.509 certificate from bytes.
    
    Args:
        cert_data: Certificate data in PEM format
        
    Returns:
        Loaded X.509 certificate
        
    Raises:
        BadCertError: If certificate cannot be loaded
    """
    try:
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        raise BadCertError(f"Failed to parse certificate: {e}")


def get_certificate_cn(cert: x509.Certificate) -> str:
    """
    Extract Common Name (CN) from certificate.
    
    Args:
        cert: X.509 certificate
        
    Returns:
        Common Name string
        
    Raises:
        BadCertError: If CN not found
    """
    try:
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attr:
            raise BadCertError("Certificate has no Common Name (CN)")
        return cn_attr[0].value
    except Exception as e:
        raise BadCertError(f"Failed to extract CN: {e}")


def verify_certificate_chain(
    cert: x509.Certificate,
    ca_cert: x509.Certificate
) -> bool:
    """
    Verify that a certificate is signed by the CA.
    
    Args:
        cert: Certificate to verify
        ca_cert: CA certificate
        
    Returns:
        True if certificate is signed by CA
        
    Raises:
        BadCertError: If verification fails
    """
    try:
        # Get CA public key
        ca_public_key = ca_cert.public_key()
        
        # Extract hash algorithm from signature algorithm
        # The signature_algorithm is a SignatureAlgorithm object
        # We need to get the hash algorithm from it
        sig_alg = cert.signature_algorithm_oid
        
        # Map signature algorithm OID to hash algorithm
        # For RSA with SHA-256 (most common)
        if sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA256:
            hash_alg = hashes.SHA256()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA384:
            hash_alg = hashes.SHA384()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA512:
            hash_alg = hashes.SHA512()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA1:
            hash_alg = hashes.SHA1()
        else:
            # Try to extract from the signature algorithm directly
            # This is a fallback for other algorithms
            raise BadCertError(f"Unsupported signature algorithm: {sig_alg}")
        
        # Verify signature using PKCS1v15 padding (standard for RSA)
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_alg,
        )
        return True
    except BadCertError:
        raise
    except Exception as e:
        raise BadCertError(f"Certificate signature verification failed: {e}")


def check_certificate_validity(cert: x509.Certificate) -> bool:
    """
    Check if certificate is within its validity period.
    
    Args:
        cert: Certificate to check
        
    Returns:
        True if certificate is valid
        
    Raises:
        BadCertError: If certificate is expired or not yet valid
    """
    now = datetime.utcnow()
    
    if now < cert.not_valid_before:
        raise BadCertError(
            f"Certificate not yet valid. Valid from: {cert.not_valid_before}"
        )
    
    if now > cert.not_valid_after:
        raise BadCertError(
            f"Certificate expired. Expired on: {cert.not_valid_after}"
        )
    
    return True


def check_certificate_cn(cert: x509.Certificate, expected_cn: str) -> bool:
    """
    Check if certificate CN matches expected value.
    
    Args:
        cert: Certificate to check
        expected_cn: Expected Common Name
        
    Returns:
        True if CN matches
        
    Raises:
        BadCertError: If CN doesn't match
    """
    cert_cn = get_certificate_cn(cert)
    
    if cert_cn != expected_cn:
        raise BadCertError(
            f"CN mismatch: expected '{expected_cn}', got '{cert_cn}'"
        )
    
    return True


def is_self_signed(cert: x509.Certificate) -> bool:
    """
    Check if certificate is self-signed.
    
    Args:
        cert: Certificate to check
        
    Returns:
        True if certificate is self-signed
    """
    return cert.subject == cert.issuer


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: str = None
) -> bool:
    """
    Comprehensive certificate validation.
    
    Validates:
    1. Certificate is not self-signed
    2. Certificate is signed by CA
    3. Certificate is within validity period
    4. CN matches expected value (if provided)
    
    Args:
        cert: Certificate to validate
        ca_cert: Trusted CA certificate
        expected_cn: Expected Common Name (optional)
        
    Returns:
        True if all validations pass
        
    Raises:
        BadCertError: If any validation fails
    """
    # Check if self-signed
    if is_self_signed(cert):
        raise BadCertError("Certificate is self-signed (not trusted)")
    
    # Verify signature chain
    verify_certificate_chain(cert, ca_cert)
    
    # Check validity period
    check_certificate_validity(cert)
    
    # Check CN if provided
    if expected_cn:
        check_certificate_cn(cert, expected_cn)
    
    return True


def load_ca_certificate(ca_cert_path: Path = Path("certs/ca_cert.pem")) -> x509.Certificate:
    """
    Load the CA certificate from default location.
    
    Args:
        ca_cert_path: Path to CA certificate
        
    Returns:
        Loaded CA certificate
        
    Raises:
        BadCertError: If CA certificate cannot be loaded
    """
    if not ca_cert_path.exists():
        raise BadCertError(f"CA certificate not found at: {ca_cert_path}")
    
    return load_certificate(ca_cert_path)
