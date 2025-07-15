"""Tests for cryptographic functions."""

import pytest
import asyncio
from aura.core.crypto.encryption import AuraEncryption
from aura.core.crypto.key_derivation import derive_key, verify_password
from aura.core.crypto.random import (
    generate_random_bytes,
    generate_salt,
    generate_nonce,
    generate_token,
    secure_compare,
)


class TestRandomGeneration:
    """Test random number generation functions."""
    
    def test_generate_random_bytes(self):
        """Test random bytes generation."""
        # Test different lengths
        for length in [16, 32, 64]:
            result = generate_random_bytes(length)
            assert len(result) == length
            assert isinstance(result, bytes)
        
        # Test that two calls produce different results
        bytes1 = generate_random_bytes(32)
        bytes2 = generate_random_bytes(32)
        assert bytes1 != bytes2
    
    def test_generate_random_bytes_invalid_length(self):
        """Test error handling for invalid lengths."""
        with pytest.raises(ValueError):
            generate_random_bytes(0)
        
        with pytest.raises(ValueError):
            generate_random_bytes(-1)
    
    def test_generate_salt(self):
        """Test salt generation."""
        salt = generate_salt()
        assert len(salt) == 32  # default length
        assert isinstance(salt, bytes)
        
        # Test custom length
        salt_custom = generate_salt(16)
        assert len(salt_custom) == 16
    
    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce = generate_nonce()
        assert len(nonce) == 12  # default length
        assert isinstance(nonce, bytes)
        
        # Test custom length
        nonce_custom = generate_nonce(16)
        assert len(nonce_custom) == 16
    
    def test_generate_token(self):
        """Test token generation."""
        token = generate_token()
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Test custom length
        token_custom = generate_token(16)
        assert isinstance(token_custom, str)
    
    def test_secure_compare(self):
        """Test secure comparison."""
        data1 = b"test data"
        data2 = b"test data"
        data3 = b"different"
        
        assert secure_compare(data1, data2) is True
        assert secure_compare(data1, data3) is False
        assert secure_compare(data1, b"") is False


class TestKeyDerivation:
    """Test key derivation functions."""
    
    @pytest.mark.asyncio
    async def test_derive_key_argon2(self):
        """Test Argon2id key derivation."""
        password = "test_password"
        
        # Test with default parameters
        derived = await derive_key(password, algorithm="argon2id")
        
        assert len(derived.key) == 32  # 256 bits
        assert len(derived.salt) == 32
        assert derived.algorithm == "argon2id"
        assert derived.iterations > 0
    
    @pytest.mark.asyncio
    async def test_derive_key_pbkdf2(self):
        """Test PBKDF2 key derivation."""
        password = "test_password"
        
        # Test with default parameters
        derived = await derive_key(password, algorithm="pbkdf2")
        
        assert len(derived.key) == 32  # 256 bits
        assert len(derived.salt) == 32
        assert derived.algorithm == "pbkdf2"
        assert derived.iterations == 100000
    
    @pytest.mark.asyncio
    async def test_derive_key_with_salt(self):
        """Test key derivation with provided salt."""
        password = "test_password"
        salt = generate_salt(32)
        
        derived1 = await derive_key(password, salt=salt)
        derived2 = await derive_key(password, salt=salt)
        
        # Same password and salt should produce same key
        assert derived1.key == derived2.key
        assert derived1.salt == derived2.salt
    
    @pytest.mark.asyncio
    async def test_verify_password(self):
        """Test password verification."""
        password = "test_password"
        wrong_password = "wrong_password"
        
        # Derive key
        derived = await derive_key(password)
        
        # Verify correct password
        assert await verify_password(password, derived) is True
        
        # Verify wrong password
        assert await verify_password(wrong_password, derived) is False
    
    @pytest.mark.asyncio
    async def test_derive_key_invalid_algorithm(self):
        """Test error handling for invalid algorithm."""
        with pytest.raises(ValueError):
            await derive_key("password", algorithm="invalid")


class TestEncryption:
    """Test encryption and decryption functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encryption = AuraEncryption()
        self.key = generate_random_bytes(32)
        self.plaintext = "This is a test message"
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_aes_gcm(self):
        """Test AES-256-GCM encryption and decryption."""
        # Encrypt
        encrypted = await self.encryption.encrypt_aes_gcm(self.plaintext, self.key)
        
        assert encrypted.algorithm == "aes-256-gcm"
        assert encrypted.version == 1
        assert len(encrypted.ciphertext) > 0
        assert len(encrypted.nonce) > 0
        
        # Decrypt
        decrypted = await self.encryption.decrypt_aes_gcm(encrypted, self.key)
        assert decrypted.decode('utf-8') == self.plaintext
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_chacha20_poly1305(self):
        """Test ChaCha20-Poly1305 encryption and decryption."""
        # Encrypt
        encrypted = await self.encryption.encrypt_chacha20_poly1305(self.plaintext, self.key)
        
        assert encrypted.algorithm == "chacha20-poly1305"
        assert encrypted.version == 1
        assert len(encrypted.ciphertext) > 0
        assert len(encrypted.nonce) > 0
        
        # Decrypt
        decrypted = await self.encryption.decrypt_chacha20_poly1305(encrypted, self.key)
        assert decrypted.decode('utf-8') == self.plaintext
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_generic(self):
        """Test generic encrypt/decrypt methods."""
        # Test with default algorithm
        encrypted = await self.encryption.encrypt(self.plaintext, self.key)
        decrypted = await self.encryption.decrypt(encrypted, self.key)
        
        assert decrypted.decode('utf-8') == self.plaintext
        
        # Test with specific algorithm
        encrypted_aes = await self.encryption.encrypt(
            self.plaintext, self.key, algorithm="aes-256-gcm"
        )
        decrypted_aes = await self.encryption.decrypt(encrypted_aes, self.key)
        
        assert decrypted_aes.decode('utf-8') == self.plaintext
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_json(self):
        """Test JSON encryption and decryption."""
        data = {"message": "test", "number": 42, "array": [1, 2, 3]}
        
        # Encrypt
        encrypted_json = await self.encryption.encrypt_json(data, self.key)
        assert isinstance(encrypted_json, str)
        
        # Decrypt
        decrypted_data = await self.encryption.decrypt_json(encrypted_json, self.key)
        assert decrypted_data == data
    
    @pytest.mark.asyncio
    async def test_encrypt_bytes(self):
        """Test encryption with bytes input."""
        plaintext_bytes = self.plaintext.encode('utf-8')
        
        encrypted = await self.encryption.encrypt(plaintext_bytes, self.key)
        decrypted = await self.encryption.decrypt(encrypted, self.key)
        
        assert decrypted == plaintext_bytes
    
    @pytest.mark.asyncio
    async def test_invalid_key_length(self):
        """Test error handling for invalid key length."""
        invalid_key = generate_random_bytes(16)  # Too short
        
        with pytest.raises(ValueError):
            await self.encryption.encrypt_aes_gcm(self.plaintext, invalid_key)
    
    @pytest.mark.asyncio
    async def test_decrypt_with_wrong_key(self):
        """Test decryption with wrong key."""
        wrong_key = generate_random_bytes(32)
        
        encrypted = await self.encryption.encrypt(self.plaintext, self.key)
        
        with pytest.raises(ValueError):
            await self.encryption.decrypt(encrypted, wrong_key)
    
    @pytest.mark.asyncio
    async def test_unsupported_algorithm(self):
        """Test error handling for unsupported algorithm."""
        with pytest.raises(ValueError):
            await self.encryption.encrypt(self.plaintext, self.key, algorithm="invalid")
    
    @pytest.mark.asyncio
    async def test_decrypt_wrong_algorithm(self):
        """Test decryption with wrong algorithm specified."""
        from aura.core.crypto.types import EncryptedData
        
        # Create encrypted data with wrong algorithm
        encrypted = EncryptedData(
            ciphertext="invalid",
            nonce="invalid",
            algorithm="invalid",
            version=1,
        )
        
        with pytest.raises(ValueError):
            await self.encryption.decrypt(encrypted, self.key)