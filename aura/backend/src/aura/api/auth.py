"""Authentication API routes."""

from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session

from aura.core.crypto.random import generate_uuid
from aura.models.user import User as UserModel
from aura.services.auth import SRPAuthService, SessionService
from aura.services.auth.types import (
    RegisterRequest,
    LoginStartRequest, 
    LoginCompleteRequest,
    RefreshTokenRequest,
    SRPChallenge,
    AuthTokens,
)
from aura.core.database import get_db
from aura.core.config import get_settings


router = APIRouter(prefix="/auth", tags=["authentication"])

# In-memory user store (replace with database in production)
users_store: Dict[str, Dict[str, Any]] = {}


@router.post("/register", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    db: Session = Depends(get_db),
):
    """Register a new user with SRP verifier."""
    # Check if user exists
    existing_user = db.query(UserModel).filter(UserModel.email == request.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists",
        )
    
    # Create user
    user_id = generate_uuid()
    user = UserModel(
        id=user_id,
        email=request.email,
        srp_salt=request.srp_salt,
        srp_verifier=request.srp_verifier,
    )
    
    db.add(user)
    db.commit()
    
    return {"success": True, "user_id": user_id}


@router.post("/login/start", response_model=SRPChallenge)
async def login_start(
    request: LoginStartRequest,
    db: Session = Depends(get_db),
):
    """Start SRP login - Phase 1."""
    # Get user
    user = db.query(UserModel).filter(UserModel.email == request.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    # Initialize SRP service
    srp_service = SRPAuthService()
    
    try:
        challenge = await srp_service.start_authentication(
            request.email,
            request.client_public_ephemeral,
            user.srp_salt,
            user.srp_verifier,
        )
        return challenge
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authentication request",
        )


@router.post("/login/complete", response_model=Dict[str, Any])
async def login_complete(
    request: LoginCompleteRequest,
    db: Session = Depends(get_db),
):
    """Complete SRP login - Phase 2."""
    settings = get_settings()
    srp_service = SRPAuthService()
    session_service = SessionService(settings.jwt_secret)
    
    try:
        success, server_proof = await srp_service.complete_authentication(
            request.session_id,
            request.client_public_ephemeral,
            request.client_proof,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
            )
        
        # Create mock user for token generation
        # In production, get user from session/database
        mock_user = UserModel(
            id=generate_uuid(),
            email="user@example.com",
            srp_salt="",
            srp_verifier="",
        )
        
        tokens = await session_service.create_tokens(mock_user)
        
        return {
            "success": True,
            "server_proof": server_proof,
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "expires_in": tokens.expires_in,
            "token_type": tokens.token_type,
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
        )


@router.post("/refresh", response_model=AuthTokens)
async def refresh_tokens(
    request: RefreshTokenRequest,
):
    """Refresh access token."""
    settings = get_settings()
    session_service = SessionService(settings.jwt_secret)
    
    tokens = await session_service.refresh_tokens(request.refresh_token)
    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    
    return tokens


@router.post("/logout")
async def logout():
    """Logout user."""
    # In production, invalidate tokens
    return {"success": True}