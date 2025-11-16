"""Offline transcript and receipt verification script."""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path so we can import app modules
script_dir = Path(__file__).parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.crypto.sign import get_public_key_from_cert, rsa_verify
from app.storage.transcript import Transcript, get_cert_fingerprint
from app.common.utils import b64d, sha256_bytes


def verify_message_signature(seqno: int, timestamp: int, ciphertext: str, signature: str, 
                            peer_cert_path: Path) -> bool:
    """
    Verify a single message signature.
    
    Args:
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Base64-encoded ciphertext
        signature: Base64-encoded signature
        peer_cert_path: Path to peer's certificate
        
    Returns:
        True if signature is valid
    """
    # Recompute hash: SHA256(seqno || timestamp || ciphertext)
    seqno_bytes = seqno.to_bytes(8, byteorder='big')
    ts_bytes = timestamp.to_bytes(8, byteorder='big')
    ct_bytes = b64d(ciphertext)
    hash_input = seqno_bytes + ts_bytes + ct_bytes
    message_hash = sha256_bytes(hash_input)
    
    # Load peer certificate and get public key
    with open(peer_cert_path, 'rb') as f:
        cert_data = f.read()
    peer_public_key = get_public_key_from_cert(cert_data)
    
    # Verify signature
    sig_bytes = b64d(signature)
    return rsa_verify(peer_public_key, message_hash, sig_bytes)


def verify_transcript(transcript_path: Path, peer_cert_path: Path) -> bool:
    """
    Verify all messages in a transcript.
    
    Args:
        transcript_path: Path to transcript file
        peer_cert_path: Path to peer's certificate
        
    Returns:
        True if all messages are valid
    """
    transcript = Transcript(transcript_path)
    entries = transcript.get_all_entries()
    
    if not entries:
        print("ERROR: Transcript is empty")
        return False
    
    print(f"Verifying {len(entries)} messages in transcript...")
    
    all_valid = True
    for i, entry in enumerate(entries, 1):
        parts = entry.split('|')
        if len(parts) != 5:
            print(f"ERROR: Invalid entry format at line {i}: {entry}")
            all_valid = False
            continue
        
        seqno, timestamp, ciphertext, signature, cert_fingerprint = parts
        seqno = int(seqno)
        timestamp = int(timestamp)
        
        if verify_message_signature(seqno, timestamp, ciphertext, signature, peer_cert_path):
            print(f"  [OK] Message {i} (seqno={seqno}) signature verified")
        else:
            print(f"  [FAIL] Message {i} (seqno={seqno}) signature verification failed")
            all_valid = False
    
    return all_valid


def verify_receipt(receipt_path: Path, transcript_path: Path, signer_cert_path: Path) -> bool:
    """
    Verify a session receipt.
    
    Args:
        receipt_path: Path to receipt JSON file
        transcript_path: Path to transcript file
        signer_cert_path: Path to signer's certificate
        
    Returns:
        True if receipt is valid
    """
    # Load receipt
    with open(receipt_path, 'r') as f:
        receipt_data = json.load(f)
    
    peer = receipt_data.get('peer')
    first_seq = receipt_data.get('first_seq')
    last_seq = receipt_data.get('last_seq')
    transcript_sha256 = receipt_data.get('transcript_sha256')
    sig = receipt_data.get('sig')
    
    print(f"Verifying receipt from {peer}:")
    print(f"  Sequence range: {first_seq} - {last_seq}")
    print(f"  Transcript hash: {transcript_sha256}")
    
    # Compute transcript hash
    transcript = Transcript(transcript_path)
    computed_hash = transcript.get_transcript_hash()
    
    if computed_hash != transcript_sha256:
        print(f"  [FAIL] Transcript hash mismatch!")
        print(f"    Expected: {transcript_sha256}")
        print(f"    Computed: {computed_hash}")
        return False
    
    print(f"  [OK] Transcript hash matches")
    
    # Verify receipt signature
    with open(signer_cert_path, 'rb') as f:
        cert_data = f.read()
    signer_public_key = get_public_key_from_cert(cert_data)
    
    hash_bytes = bytes.fromhex(transcript_sha256)
    sig_bytes = b64d(sig)
    
    if rsa_verify(signer_public_key, hash_bytes, sig_bytes):
        print(f"  [OK] Receipt signature verified")
        return True
    else:
        print(f"  [FAIL] Receipt signature verification failed")
        return False


def main():
    parser = argparse.ArgumentParser(description="Verify transcript and receipt")
    parser.add_argument("--transcript", type=str, required=True, help="Path to transcript file")
    parser.add_argument("--peer-cert", type=str, required=True, help="Path to peer's certificate")
    parser.add_argument("--receipt", type=str, help="Path to receipt JSON file")
    parser.add_argument("--signer-cert", type=str, help="Path to signer's certificate (for receipt verification)")
    
    args = parser.parse_args()
    
    transcript_path = Path(args.transcript)
    peer_cert_path = Path(args.peer_cert)
    
    if not transcript_path.exists():
        print(f"ERROR: Transcript file not found: {transcript_path}")
        sys.exit(1)
    
    if not peer_cert_path.exists():
        print(f"ERROR: Peer certificate not found: {peer_cert_path}")
        sys.exit(1)
    
    # Verify transcript
    print("=" * 60)
    print("VERIFYING TRANSCRIPT")
    print("=" * 60)
    transcript_valid = verify_transcript(transcript_path, peer_cert_path)
    
    if args.receipt and args.signer_cert:
        receipt_path = Path(args.receipt)
        signer_cert_path = Path(args.signer_cert)
        
        if not receipt_path.exists():
            print(f"ERROR: Receipt file not found: {receipt_path}")
            sys.exit(1)
        
        if not signer_cert_path.exists():
            print(f"ERROR: Signer certificate not found: {signer_cert_path}")
            sys.exit(1)
        
        print("\n" + "=" * 60)
        print("VERIFYING RECEIPT")
        print("=" * 60)
        receipt_valid = verify_receipt(receipt_path, transcript_path, signer_cert_path)
    else:
        receipt_valid = True
        print("\n(Receipt verification skipped - provide --receipt and --signer-cert)")
    
    print("\n" + "=" * 60)
    if transcript_valid and receipt_valid:
        print("VERIFICATION RESULT: SUCCESS")
        print("=" * 60)
        sys.exit(0)
    else:
        print("VERIFICATION RESULT: FAILED")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()

