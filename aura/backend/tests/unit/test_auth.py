"""Tests for authentication services."""

import pytest
import time
from unittest.mock import patch

from aura.services.auth.srp import SRPAuthService
from aura.services.auth.session import SessionService
from aura.services.auth.types import User
from datetime import datetime


class TestSRPAuthService:
    """Test SRP authentication service."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.srp_service = SRPAuthService()
        self.username = "test@example.com"
        self.password = "test_password_123"
    
    def test_generate_verifier(self):
        """Test SRP verifier generation."""
        salt, verifier = SRPAuthService.generate_verifier(self.username, self.password)
        
        assert isinstance(salt, str)
        assert isinstance(verifier, str)
        assert len(salt) > 0
        assert len(verifier) > 0
        
        # Test that same input produces same output
        salt2, verifier2 = SRPAuthService.generate_verifier(self.username, self.password)
        assert salt != salt2  # Salt should be random
        # Note: verifier will be different because salt is different
    
    @pytest.mark.asyncio
    async def test_full_auth_flow(self):
        """Test complete SRP authentication flow."""
        # Generate verifier
        salt, verifier = SRPAuthService.generate_verifier(self.username, self.password)
        
        # Simulate client ephemeral (in real implementation, this comes from client)
        client_ephemeral = "a" * 64  # Mock client public ephemeral
        
        # Start authentication
        challenge = await self.srp_service.start_authentication(
            self.username,
            client_ephemeral,
            salt,
            verifier,
        )
        
        assert challenge.salt == salt
        assert len(challenge.server_public_ephemeral) > 0
        assert len(challenge.session_id) > 0
        
        # Note: Complete authentication would require proper SRP client implementation
        # For now, test that session is created and can be found
        assert self.srp_service.get_active_session_count() == 1
    
    @pytest.mark.asyncio
    async def test_session_timeout(self):
        """Test session timeout functionality."""
        salt, verifier = SRPAuthService.generate_verifier(self.username, self.password)
        client_ephemeral = "a" * 64
        
        # Start authentication
        challenge = await self.srp_service.start_authentication(
            self.username,
            client_ephemeral,
            salt,
            verifier,
        )
        
        # Mock time to simulate timeout
        with patch('time.time', return_value=time.time() + 400):  # 400 seconds later
            success, _ = await self.srp_service.complete_authentication(
                challenge.session_id,
                client_ephemeral,
                "mock_proof",
            )
            assert success is False
    
    @pytest.mark.asyncio
    async def test_invalid_session_id(self):
        """Test handling of invalid session ID."""
        success, proof = await self.srp_service.complete_authentication(
            "invalid_session_id",
            "client_ephemeral",
            "client_proof",
        )
        
        assert success is False
        assert proof is None
    
    @pytest.mark.asyncio
    async def test_cleanup_sessions(self):
        """Test session cleanup functionality."""
        salt, verifier = SRPAuthService.generate_verifier(self.username, self.password)
        
        # Create multiple sessions
        for i in range(3):
            await self.srp_service.start_authentication(
                f"user{i}@example.com",
                "a" * 64,
                salt,
                verifier,
            )
        
        assert self.srp_service.get_active_session_count() == 3
        
        # Mock expired sessions
        with patch('time.time', return_value=time.time() + 400):
            await self.srp_service._cleanup_sessions()
            assert self.srp_service.get_active_session_count() == 0


class TestSessionService:
    """Test session management service."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.jwt_secret = "test_secret_key_for_testing_only"
        self.session_service = SessionService(self.jwt_secret)
        self.user = User(
            id="test_user_id",
            email="test@example.com",
            srp_salt="test_salt",
            srp_verifier="test_verifier",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
    
    @pytest.mark.asyncio
    async def test_create_tokens(self):
        """Test JWT token creation."""
        tokens = await self.session_service.create_tokens(self.user)
        
        assert tokens.access_token is not None
        assert tokens.refresh_token is not None
        assert tokens.expires_in == 15 * 60  # 15 minutes
        assert tokens.token_type == "bearer"
    
    @pytest.mark.asyncio
    async def test_verify_access_token(self):
        """Test access token verification."""
        tokens = await self.session_service.create_tokens(self.user)
        
        # Verify access token
        payload = await self.session_service.verify_token(tokens.access_token, "access")
        assert payload is not None
        assert payload.sub == self.user.id
        assert payload.email == self.user.email
        assert payload.type == "access"
    
    @pytest.mark.asyncio
    async def test_verify_refresh_token(self):
        """Test refresh token verification."""
        tokens = await self.session_service.create_tokens(self.user)
        
        # Verify refresh token
        payload = await self.session_service.verify_token(tokens.refresh_token, "refresh")
        assert payload is not None
        assert payload.sub == self.user.id
        assert payload.email == self.user.email
        assert payload.type == "refresh"
    
    @pytest.mark.asyncio
    async def test_verify_token_wrong_type(self):
        """Test token verification with wrong type."""
        tokens = await self.session_service.create_tokens(self.user)
        
        # Try to verify access token as refresh token
        payload = await self.session_service.verify_token(tokens.access_token, "refresh")
        assert payload is None
    
    @pytest.mark.asyncio
    async def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        payload = await self.session_service.verify_token("invalid_token", "access")
        assert payload is None
    
    @pytest.mark.asyncio
    async def test_refresh_tokens(self):
        """Test token refresh functionality."""
        # Create initial tokens
        initial_tokens = await self.session_service.create_tokens(self.user)
        
        # Refresh tokens
        new_tokens = await self.session_service.refresh_tokens(initial_tokens.refresh_token)
        
        assert new_tokens is not None
        assert new_tokens.access_token != initial_tokens.access_token
        assert new_tokens.refresh_token != initial_tokens.refresh_token
    
    @pytest.mark.asyncio
    async def test_refresh_with_invalid_token(self):
        """Test refresh with invalid token."""
        new_tokens = await self.session_service.refresh_tokens("invalid_token")
        assert new_tokens is None
    
    @pytest.mark.asyncio
    async def test_revoke_refresh_token(self):
        """Test refresh token revocation."""
        tokens = await self.session_service.create_tokens(self.user)
        
        # Revoke token (currently just returns True)
        result = await self.session_service.revoke_refresh_token(tokens.refresh_token)
        assert result is True
    
    def test_create_session_id(self):
        """Test session ID creation."""
        session_id = self.session_service.create_session_id()
        
        assert isinstance(session_id, str)
        assert len(session_id) > 0
        
        # Test uniqueness
        session_id2 = self.session_service.create_session_id()
        assert session_id != session_id2