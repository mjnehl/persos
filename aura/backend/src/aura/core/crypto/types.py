"""Type definitions for cryptographic operations."""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class EncryptedData(BaseModel):
    """Encrypted data container."""
    
    ciphertext: str = Field(..., description="Base64 encoded ciphertext")
    nonce: str = Field(..., description="Base64 encoded nonce")
    salt: Optional[str] = Field(None, description="Base64 encoded salt")
    algorithm: str = Field(..., description="Encryption algorithm used")
    version: int = Field(default=1, description="Encryption version")


class DerivedKey(BaseModel):
    """Derived key container."""
    
    key: bytes = Field(..., description="Derived key bytes")
    salt: bytes = Field(..., description="Salt used for derivation")
    iterations: int = Field(..., description="Number of iterations")
    algorithm: str = Field(..., description="Key derivation algorithm")


class CryptoConfig(BaseModel):
    """Cryptographic configuration."""
    
    default_algorithm: str = Field(default="aes-256-gcm")
    key_derivation_iterations: int = Field(default=100000)
    key_length: int = Field(default=32)  # 256 bits
    salt_length: int = Field(default=32)  # 256 bits
    nonce_length: int = Field(default=12)  # 96 bits for GCM


# Global crypto configuration
CRYPTO_CONFIG = CryptoConfig()

# Argon2 configuration
ARGON2_CONFIG = {
    "time_cost": 3,
    "memory_cost": 65536,  # 64 MB
    "parallelism": 4,
    "hash_len": 32,
    "salt_len": 32,
}

ENCRYPTION_VERSION = 1