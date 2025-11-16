"""Append-only transcript + TranscriptHash helpers."""

import hashlib
from pathlib import Path
from typing import List, Optional
from app.common.utils import sha256_hex, sha256_bytes


class Transcript:
    """Append-only transcript for chat session."""
    
    def __init__(self, transcript_path: Path):
        """
        Initialize transcript.
        
        Args:
            transcript_path: Path to transcript file
        """
        self.transcript_path = transcript_path
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: List[str] = []
        self._load_existing()
    
    def _load_existing(self):
        """Load existing transcript entries if file exists."""
        if self.transcript_path.exists():
            with open(self.transcript_path, 'r', encoding='utf-8') as f:
                self.entries = [line.rstrip('\n') for line in f if line.strip()]
    
    def append(self, seqno: int, timestamp: int, ciphertext: str, signature: str, peer_cert_fingerprint: str):
        """
        Append a message entry to the transcript.
        
        Format: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64-encoded ciphertext
            signature: Base64-encoded signature
            peer_cert_fingerprint: SHA-256 hex fingerprint of peer's certificate
        """
        entry = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}"
        self.entries.append(entry)
        
        # Append to file (append-only)
        with open(self.transcript_path, 'a', encoding='utf-8') as f:
            f.write(entry + '\n')
    
    def get_transcript_hash(self) -> str:
        """
        Compute transcript hash: SHA256(concatenation of all log lines).
        
        Returns:
            Hex string of transcript hash
        """
        if not self.entries:
            # Empty transcript -> hash of empty string
            return sha256_hex(b'')
        
        # Concatenate all entries with newlines
        transcript_content = '\n'.join(self.entries) + '\n'
        return sha256_hex(transcript_content.encode('utf-8'))
    
    def get_transcript_hash_bytes(self) -> bytes:
        """
        Compute transcript hash as bytes.
        
        Returns:
            Bytes of transcript hash
        """
        if not self.entries:
            return sha256_bytes(b'')
        
        transcript_content = '\n'.join(self.entries) + '\n'
        return sha256_bytes(transcript_content.encode('utf-8'))
    
    def get_first_seqno(self) -> Optional[int]:
        """Get first sequence number in transcript."""
        if not self.entries:
            return None
        first_entry = self.entries[0]
        return int(first_entry.split('|')[0])
    
    def get_last_seqno(self) -> Optional[int]:
        """Get last sequence number in transcript."""
        if not self.entries:
            return None
        last_entry = self.entries[-1]
        return int(last_entry.split('|')[0])
    
    def get_all_entries(self) -> List[str]:
        """Get all transcript entries."""
        return self.entries.copy()


def get_cert_fingerprint(cert_data: bytes) -> str:
    """
    Compute SHA-256 fingerprint of certificate.
    
    Args:
        cert_data: Certificate data in PEM format
        
    Returns:
        Hex string of certificate fingerprint
    """
    return sha256_hex(cert_data)
