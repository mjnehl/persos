"""Secure random number generation utilities."""

import secrets
import base64
from typing import Optional
import nacl.utils
from nacl.utils import random


def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    if length <= 0:
        raise ValueError("Length must be positive")
    return nacl.utils.random(length)


def generate_salt(length: int = 32) -> bytes:
    """Generate a random salt for key derivation."""
    return generate_random_bytes(length)


def generate_nonce(length: int = 12) -> bytes:
    """Generate a random nonce for encryption."""
    return generate_random_bytes(length)


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    token_bytes = generate_random_bytes(length)
    return base64.urlsafe_b64encode(token_bytes).decode('ascii').rstrip('=')


def generate_uuid() -> str:
    """Generate a random UUID v4."""
    import uuid
    return str(uuid.uuid4())


def secure_compare(a: bytes, b: bytes) -> bool:
    """Securely compare two byte strings in constant time."""
    return secrets.compare_digest(a, b)