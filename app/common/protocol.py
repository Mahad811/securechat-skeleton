"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello message with certificate."""
    cert: str  # Base64-encoded certificate


class ServerHelloMessage(BaseModel):
    """Server hello message with certificate."""
    cert: str  # Base64-encoded certificate


class ErrorMessage(BaseModel):
    """Error message from server."""
    error: str  # Error code: BAD_CERT, SIG_FAIL, REPLAY, etc.


class DHClientMessage(BaseModel):
    """Diffie–Hellman client message (client → server)."""
    type: str = "dh_client"
    pub: str  # Client public value A as decimal string


class DHServerMessage(BaseModel):
    """Diffie–Hellman server message (server → client)."""
    type: str = "dh_server"
    pub: str  # Server public value B as decimal string


class RegisterMessage(BaseModel):
    """Encrypted registration payload (email, username, password)."""
    type: str = "register"
    ct: str  # Base64-encoded ciphertext of JSON {email, username, password}


class LoginMessage(BaseModel):
    """Encrypted login payload (username, password)."""
    type: str = "login"
    ct: str  # Base64-encoded ciphertext of JSON {username, password}


class ChatMessage(BaseModel):
    """Encrypted chat message with integrity signature.
    
    Format: { "type":"msg", "seqno":n, "ts":unix_ms, "ct":base64, "sig":base64 }
    """
    type: str = "msg"
    seqno: int  # Sequence number (strictly increasing)
    ts: int  # Unix timestamp in milliseconds
    ct: str  # Base64-encoded AES-encrypted ciphertext
    sig: str  # Base64-encoded RSA signature of SHA256(seqno || ts || ct)


class ReceiptMessage(BaseModel):
    """Session receipt with signed transcript hash.
    
    Format: { "type":"receipt", "peer":"client|server", "first_seq":n, 
              "last_seq":n, "transcript_sha256":hex, "sig":base64 }
    """
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int  # First sequence number in transcript
    last_seq: int  # Last sequence number in transcript
    transcript_sha256: str  # Hex string of transcript hash
    sig: str  # Base64-encoded RSA signature of transcript hash

