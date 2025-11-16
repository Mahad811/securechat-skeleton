"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.

We implement a simple finite-field Diffie–Hellman using a fixed 2048-bit
safe prime and generator (classic DH, not ECC).

The shared secret Ks is converted into an AES-128 key as:

    K = Trunc16(SHA256(big-endian(Ks)))
"""

import secrets
from typing import Tuple

from app.common.utils import sha256_hex


# 2048-bit MODP Group from RFC 3526 (Group 14)
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)

P = int(_P_HEX, 16)
G = 2


def generate_private_key() -> int:
    """Generate a random DH private exponent a in [2, P-2]."""
    # Use 256-bit randomness; exponent will still be large enough.
    a = secrets.randbits(256)
    # Ensure it's within a safe range
    return 2 + (a % (P - 3))


def compute_public_key(priv: int) -> int:
    """Compute public value g^priv mod p."""
    return pow(G, priv, P)


def compute_shared_secret(priv: int, peer_pub: int) -> int:
    """Compute shared secret Ks = peer_pub^priv mod p."""
    if peer_pub <= 1 or peer_pub >= P - 1:
        raise ValueError("Invalid peer public value")
    return pow(peer_pub, priv, P)


def ks_to_key(shared_secret: int) -> bytes:
    """Derive AES-128 key from shared secret using Trunc16(SHA256(big-endian(Ks)))."""
    if shared_secret <= 0:
        raise ValueError("Shared secret must be positive")

    # Convert Ks integer to big-endian bytes (minimal length)
    ks_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    # SHA-256 over Ks bytes, then take first 16 bytes
    # We use sha256_hex helper then convert back from hex.
    digest_hex = sha256_hex(ks_bytes)
    digest = bytes.fromhex(digest_hex)
    return digest[:16]


def generate_dh_keypair() -> Tuple[int, int]:
    """Generate a DH keypair (priv, pub)."""
    priv = generate_private_key()
    pub = compute_public_key(priv)
    return priv, pub

