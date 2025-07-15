"""Session management for authenticated users."""

import time
from datetime import datetime, timedelta
from typing import Optional
import jwt
from jwt import InvalidTokenError

from .types import User, AuthTokens, JWTPayload


class SessionService:
    """Session management service."""
    
    def __init__(self, jwt_secret: str):
        self.jwt_secret = jwt_secret
        self.access_token_expires = 15 * 60  # 15 minutes
        self.refresh_token_expires = 7 * 24 * 60 * 60  # 7 days
        self.algorithm = "HS256"
    
    async def create_tokens(self, user: User) -> AuthTokens:
        """Create authentication tokens for a user."""
        now = int(time.time())
        
        # Access token payload
        access_payload = {
            "sub": user.id,
            "email": user.email,
            "type": "access",
            "iat": now,
            "exp": now + self.access_token_expires,
        }
        
        # Refresh token payload
        refresh_payload = {
            "sub": user.id,
            "email": user.email,
            "type": "refresh",
            "iat": now,
            "exp": now + self.refresh_token_expires,
        }
        
        # Generate tokens
        access_token = jwt.encode(
            access_payload, self.jwt_secret, algorithm=self.algorithm
        )
        refresh_token = jwt.encode(
            refresh_payload, self.jwt_secret, algorithm=self.algorithm
        )
        
        return AuthTokens(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.access_token_expires,
        )
    
    async def verify_token(self, token: str, token_type: str) -> Optional[JWTPayload]:
        """Verify and decode a token."""
        try:
            payload = jwt.decode(
                token, self.jwt_secret, algorithms=[self.algorithm]
            )
            
            # Validate token type
            if payload.get("type") != token_type:
                return None
            
            return JWTPayload(**payload)
            
        except InvalidTokenError:
            return None
    
    async def refresh_tokens(self, refresh_token: str) -> Optional[AuthTokens]:
        """Refresh authentication tokens."""
        payload = await self.verify_token(refresh_token, "refresh")
        if not payload:
            return None
        
        # Create mock user for token generation
        # In production, fetch user from database
        user = User(
            id=payload.sub,
            email=payload.email,
            srp_salt="",
            srp_verifier="",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        
        return await self.create_tokens(user)
    
    async def revoke_refresh_token(self, token: str) -> bool:
        """
        Revoke a refresh token.
        In production, this would add the token to a blacklist.
        """
        # For now, we rely on JWT expiration
        # In production, implement token blacklist in Redis
        return True
    
    def create_session_id(self) -> str:
        """Create a secure session identifier."""
        from aura.core.crypto.random import generate_token
        return generate_token(32)