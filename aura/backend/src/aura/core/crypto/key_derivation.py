"""Key derivation functions for Aura."""

import hashlib
from typing import Optional
import argon2
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

from .types import DerivedKey, ARGON2_CONFIG
from .random import generate_salt, secure_compare


async def derive_key_argon2(
    password: str,
    salt: Optional[bytes] = None,
    iterations: Optional[int] = None,
    key_length: int = 32,
) -> DerivedKey:
    """Derive a key from a password using Argon2id."""
    if salt is None:
        salt = generate_salt(ARGON2_CONFIG["salt_len"])
    
    time_cost = iterations or ARGON2_CONFIG["time_cost"]
    
    # Use argon2-cffi for key derivation
    derived_key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=ARGON2_CONFIG["memory_cost"],
        parallelism=ARGON2_CONFIG["parallelism"],
        hash_len=key_length,
        type=Type.ID  # Argon2id
    )
    
    return DerivedKey(
        key=derived_key,
        salt=salt,
        iterations=time_cost,
        algorithm="argon2id"
    )


async def derive_key_pbkdf2(
    password: str,
    salt: Optional[bytes] = None,
    iterations: int = 100000,
    key_length: int = 32,
) -> DerivedKey:
    """Derive a key from a password using PBKDF2 (fallback)."""
    if salt is None:
        salt = generate_salt(32)
    
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        key_length
    )
    
    return DerivedKey(
        key=derived_key,
        salt=salt,
        iterations=iterations,
        algorithm="pbkdf2"
    )


async def derive_key(
    password: str,
    salt: Optional[bytes] = None,
    iterations: Optional[int] = None,
    key_length: int = 32,
    algorithm: str = "argon2id",
) -> DerivedKey:
    """Derive a key from a password using the specified algorithm."""
    if algorithm == "argon2id":
        return await derive_key_argon2(password, salt, iterations, key_length)
    elif algorithm == "pbkdf2":
        return await derive_key_pbkdf2(password, salt, iterations or 100000, key_length)
    else:
        raise ValueError(f"Unsupported key derivation algorithm: {algorithm}")


async def verify_password(password: str, derived_key: DerivedKey) -> bool:
    """Verify a password against a derived key."""
    new_derived_key = await derive_key(
        password,
        salt=derived_key.salt,
        iterations=derived_key.iterations,
        key_length=len(derived_key.key),
        algorithm=derived_key.algorithm,
    )
    
    return secure_compare(new_derived_key.key, derived_key.key)


async def generate_master_key(
    derived_key: bytes,
    info: str = "aura-master-key",
) -> bytes:
    """Generate a master key from a derived key using HKDF."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info.encode('utf-8'),
    )
    
    return hkdf.derive(derived_key)