"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


BLOCK_SIZE = 16  # AES block size in bytes


def _pkcs7_pad(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding to data to make its length a multiple of BLOCK_SIZE.
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.

    Raises:
        ValueError: If padding is invalid.
    """
    if not data:
        raise ValueError("Invalid padding: empty data")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-pad_len]


def aes_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding.

    Args:
        key: 16-byte AES key.
        plaintext: Data to encrypt.

    Returns:
        Ciphertext bytes.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    padded = _pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode with PKCS#7 padding.

    Args:
        key: 16-byte AES key.
        ciphertext: Data to decrypt.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If padding is invalid.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)
