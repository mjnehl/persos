"""Authentication type definitions."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr


class User(BaseModel):
    """User model."""
    
    id: str
    email: EmailStr
    srp_salt: str
    srp_verifier: str
    created_at: datetime
    updated_at: datetime


class Session(BaseModel):
    """Session model."""
    
    id: str
    user_id: str
    token: str
    expires_at: datetime
    created_at: datetime


class AuthTokens(BaseModel):
    """Authentication tokens."""
    
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "bearer"


class JWTPayload(BaseModel):
    """JWT payload structure."""
    
    sub: str  # user id
    email: str
    iat: int
    exp: int
    type: str  # 'access' or 'refresh'


class RegisterRequest(BaseModel):
    """User registration request."""
    
    email: EmailStr
    srp_salt: str = Field(..., min_length=32)
    srp_verifier: str = Field(..., min_length=32)


class LoginStartRequest(BaseModel):
    """Login start request."""
    
    email: EmailStr
    client_public_ephemeral: str = Field(..., min_length=32)


class LoginCompleteRequest(BaseModel):
    """Login complete request."""
    
    session_id: str
    client_public_ephemeral: str = Field(..., min_length=32)
    client_proof: str = Field(..., min_length=32)


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""
    
    refresh_token: str


class SRPChallenge(BaseModel):
    """SRP challenge response."""
    
    salt: str
    server_public_ephemeral: str
    session_id: str


class SRPSession(BaseModel):
    """SRP session data."""
    
    identifier: str
    salt: str
    server_ephemeral_secret: str
    server_ephemeral_public: str
    verifier: str
    timestamp: float