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


# Placeholder for other message types (to be implemented later)
class RegisterMessage(BaseModel):
    """User registration message."""
    pass


class LoginMessage(BaseModel):
    """User login message."""
    pass


class DHClientMessage(BaseModel):
    """Diffie-Hellman client message."""
    pass


class DHServerMessage(BaseModel):
    """Diffie-Hellman server message."""
    pass


class ChatMessage(BaseModel):
    """Chat message."""
    pass


class ReceiptMessage(BaseModel):
    """Session receipt message."""
    pass
