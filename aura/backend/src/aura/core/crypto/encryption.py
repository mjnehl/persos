"""Encryption and decryption utilities for Aura."""

import base64
import json
from typing import Union, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .types import EncryptedData, CRYPTO_CONFIG, ENCRYPTION_VERSION
from .random import generate_nonce


class AuraEncryption:
    """Main encryption class for Aura."""
    
    def __init__(self):
        self.config = CRYPTO_CONFIG
    
    async def encrypt_aes_gcm(
        self,
        plaintext: Union[str, bytes],
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedData:
        """Encrypt data using AES-256-GCM."""
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        
        # Convert string to bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate nonce
        nonce = generate_nonce(12)  # 96 bits for GCM
        
        # Encrypt
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        return EncryptedData(
            ciphertext=base64.b64encode(ciphertext).decode('ascii'),
            nonce=base64.b64encode(nonce).decode('ascii'),
            algorithm="aes-256-gcm",
            version=ENCRYPTION_VERSION,
        )
    
    async def decrypt_aes_gcm(
        self,
        encrypted_data: EncryptedData,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt data using AES-256-GCM."""
        if encrypted_data.algorithm != "aes-256-gcm":
            raise ValueError(f"Invalid algorithm: {encrypted_data.algorithm}")
        
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        
        # Decode data
        ciphertext = base64.b64decode(encrypted_data.ciphertext)
        nonce = base64.b64decode(encrypted_data.nonce)
        
        # Decrypt
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except InvalidTag:
            raise ValueError("Decryption failed: Invalid key or corrupted data")
    
    async def encrypt_chacha20_poly1305(
        self,
        plaintext: Union[str, bytes],
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedData:
        """Encrypt data using ChaCha20-Poly1305."""
        if len(key) != 32:
            raise ValueError("ChaCha20 requires a 32-byte key")
        
        # Convert string to bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate nonce
        nonce = generate_nonce(12)  # 96 bits
        
        # Encrypt
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
        
        return EncryptedData(
            ciphertext=base64.b64encode(ciphertext).decode('ascii'),
            nonce=base64.b64encode(nonce).decode('ascii'),
            algorithm="chacha20-poly1305",
            version=ENCRYPTION_VERSION,
        )
    
    async def decrypt_chacha20_poly1305(
        self,
        encrypted_data: EncryptedData,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt data using ChaCha20-Poly1305."""
        if encrypted_data.algorithm != "chacha20-poly1305":
            raise ValueError(f"Invalid algorithm: {encrypted_data.algorithm}")
        
        if len(key) != 32:
            raise ValueError("ChaCha20 requires a 32-byte key")
        
        # Decode data
        ciphertext = base64.b64decode(encrypted_data.ciphertext)
        nonce = base64.b64decode(encrypted_data.nonce)
        
        # Decrypt
        chacha = ChaCha20Poly1305(key)
        try:
            plaintext = chacha.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except InvalidTag:
            raise ValueError("Decryption failed: Invalid key or corrupted data")
    
    async def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: bytes,
        algorithm: Optional[str] = None,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedData:
        """Encrypt data using the specified algorithm."""
        algo = algorithm or self.config.default_algorithm
        
        if algo == "aes-256-gcm":
            return await self.encrypt_aes_gcm(plaintext, key, associated_data)
        elif algo == "chacha20-poly1305":
            return await self.encrypt_chacha20_poly1305(plaintext, key, associated_data)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algo}")
    
    async def decrypt(
        self,
        encrypted_data: EncryptedData,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt data using the algorithm specified in the encrypted data."""
        if encrypted_data.algorithm == "aes-256-gcm":
            return await self.decrypt_aes_gcm(encrypted_data, key, associated_data)
        elif encrypted_data.algorithm == "chacha20-poly1305":
            return await self.decrypt_chacha20_poly1305(encrypted_data, key, associated_data)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {encrypted_data.algorithm}")
    
    async def encrypt_json(
        self,
        data: dict,
        key: bytes,
        algorithm: Optional[str] = None,
    ) -> str:
        """Encrypt a JSON object and return as string."""
        json_str = json.dumps(data, separators=(',', ':'))
        encrypted = await self.encrypt(json_str, key, algorithm)
        return encrypted.model_dump_json()
    
    async def decrypt_json(
        self,
        encrypted_json: str,
        key: bytes,
    ) -> dict:
        """Decrypt a JSON string and return as dict."""
        encrypted_data = EncryptedData.model_validate_json(encrypted_json)
        decrypted_bytes = await self.decrypt(encrypted_data, key)
        return json.loads(decrypted_bytes.decode('utf-8'))


# Global encryption instance
aura_encryption = AuraEncryption()