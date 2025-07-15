"""Application configuration."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    
    # Database
    database_url: str = "postgresql://aura:localdev@localhost:5432/aura_db"
    
    # Redis
    redis_url: str = "redis://:localdev@localhost:6379"
    
    # Vector Database
    qdrant_url: str = "http://localhost:6333"
    
    # Security
    jwt_secret: str = "your-jwt-secret-here"
    
    # API
    api_port: int = 3001
    api_host: str = "0.0.0.0"
    
    # Frontend
    frontend_url: str = "http://localhost:3000"
    
    # Development
    environment: str = "development"
    log_level: str = "info"
    debug: bool = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()