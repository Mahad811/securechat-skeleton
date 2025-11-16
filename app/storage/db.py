"""MySQL users table + salted hashing (no chat storage).

This module provides a small DB layer around a `users` table:

    users(
        email      VARCHAR(255),
        username   VARCHAR(255) UNIQUE,
        salt       VARBINARY(16),
        pwd_hash   CHAR(64)
    )

Passwords are stored as:

    pwd_hash = hex(SHA256(salt || password))

Chat messages are NOT stored here (see transcript module for that).
"""

import os
import secrets
from dataclasses import dataclass
from typing import Optional

import pymysql
from pymysql.connections import Connection

from app.common.utils import sha256_hex


@dataclass
class DBConfig:
    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "scuser"
    password: str = "scpass"
    database: str = "securechat"

    @classmethod
    def from_env(cls) -> "DBConfig":
        """Load DB config from environment variables with sensible defaults."""
        return cls(
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=int(os.getenv("DB_PORT", "3306")),
            user=os.getenv("DB_USER", "scuser"),
            password=os.getenv("DB_PASS", "scpass"),
            database=os.getenv("DB_NAME", "securechat"),
        )


class UserDB:
    """Thin wrapper around the MySQL users table."""

    def __init__(self, config: Optional[DBConfig] = None):
        self.config = config or DBConfig.from_env()

    def _connect(self) -> Connection:
        return pymysql.connect(
            host=self.config.host,
            port=self.config.port,
            user=self.config.user,
            password=self.config.password,
            database=self.config.database,
            autocommit=True,
        )

    def init_schema(self) -> None:
        """Create the users table if it does not exist."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        email      VARCHAR(255) NOT NULL,
                        username   VARCHAR(255) NOT NULL UNIQUE,
                        salt       VARBINARY(16) NOT NULL,
                        pwd_hash   CHAR(64) NOT NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """
                )
        finally:
            conn.close()

    def create_user(self, email: str, username: str, password: str) -> bool:
        """Register a new user.

        Returns:
            True on success, False if username/email already exists or on error.
        """
        salt = secrets.token_bytes(16)
        pwd_hash = sha256_hex(salt + password.encode("utf-8"))

        conn = self._connect()
        try:
            with conn.cursor() as cur:
                # First, check if username or email already exists
                cur.execute(
                    "SELECT 1 FROM users WHERE username = %s OR email = %s LIMIT 1",
                    (username, email),
                )
                if cur.fetchone():
                    return False

                # Insert new user
                cur.execute(
                    "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                    (email, username, salt, pwd_hash),
                )
            return True
        except Exception:
            # In a real system you'd log this; for assignment, just fail closed.
            return False
        finally:
            conn.close()

    def verify_user(self, username: str, password: str) -> bool:
        """Verify username + password using stored salted hash."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT salt, pwd_hash FROM users WHERE username = %s LIMIT 1",
                    (username,),
                )
                row = cur.fetchone()
                if not row:
                    return False

                salt, stored_hash = row
                if not isinstance(salt, (bytes, bytearray)):
                    return False

                computed_hash = sha256_hex(salt + password.encode("utf-8"))
                return computed_hash == stored_hash
        except Exception:
            return False
        finally:
            conn.close()


def _cli_init():
    """Command-line entry point for initializing DB schema."""
    db = UserDB()
    db.init_schema()
    print("[OK] users table ensured in database")


if __name__ == "__main__":
    # Simple CLI: python -m app.storage.db --init
    import argparse

    parser = argparse.ArgumentParser(description="User DB management")
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize users table schema",
    )
    args = parser.parse_args()

    if args.init:
        _cli_init()
    else:
        parser.print_help()

