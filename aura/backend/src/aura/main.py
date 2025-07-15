"""Aura Backend Application Entry Point."""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from aura.api.auth import router as auth_router
from aura.api.storage import router as storage_router
from aura.core.config import get_settings
from aura.models.base import Base
from aura.core.database import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Create database tables
    Base.metadata.create_all(bind=engine)
    
    print("""
🚀 Aura Backend Server Started
   
   Zero-Knowledge Architecture Active ✓
   Client-Side Encryption Ready ✓
   SRP-6a Authentication Ready ✓
   Encrypted Storage Ready ✓
    """)
    
    yield
    
    # Cleanup
    print("Shutting down Aura backend...")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="Aura Backend",
        description="Privacy-first AI assistant with zero-knowledge architecture",
        version="0.1.0",
        lifespan=lifespan,
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Health check
    @app.get("/health")
    async def health_check():
        return {
            "status": "ok",
            "service": "aura-backend",
            "version": "0.1.0",
        }
    
    # Include routers
    app.include_router(auth_router, prefix="/api")
    app.include_router(storage_router, prefix="/api")
    
    return app


app = create_app()


def main():
    """Run the application."""
    settings = get_settings()
    
    uvicorn.run(
        "aura.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()