"""Authentication middleware and dependencies."""

from typing import Dict, Any
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from aura.services.auth import SessionService
from .config import get_settings

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """Get current authenticated user from JWT token."""
    settings = get_settings()
    session_service = SessionService(settings.jwt_secret)
    
    token = credentials.credentials
    payload = await session_service.verify_token(token, "access")
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return {
        "id": payload.sub,
        "email": payload.email,
    }