"""Pytest configuration and fixtures."""

import pytest
import asyncio
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient

from aura.main import create_app
from aura.models.base import Base
from aura.core.database import get_db


# Test database URL (in-memory SQLite)
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
def db() -> Generator[Session, None, None]:
    """Create a fresh database for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db: Session) -> TestClient:
    """Create a test client with database override."""
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "email": "test@example.com",
        "srp_salt": "a" * 64,  # 32 bytes hex
        "srp_verifier": "b" * 64,  # 32 bytes hex
    }


@pytest.fixture
def sample_encrypted_data():
    """Sample encrypted data for testing."""
    return {
        "ciphertext": "dGVzdCBjaXBoZXJ0ZXh0",  # base64 encoded
        "nonce": "dGVzdCBub25jZQ==",        # base64 encoded
        "algorithm": "aes-256-gcm",
        "version": 1,
    }