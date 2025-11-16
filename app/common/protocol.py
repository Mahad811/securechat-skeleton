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
    """Chat message (placeholder for later)."""
    type: str = "msg"
    # Will be filled in task 2.3


class ReceiptMessage(BaseModel):
    """Session receipt message (placeholder for later)."""
    type: str = "receipt"
    # Will be filled in later tasks

