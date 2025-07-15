"""User model."""

from sqlalchemy import Column, String
from sqlalchemy.orm import relationship

from .base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """User model - stores only authentication data."""
    
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    srp_salt = Column(String, nullable=False)
    srp_verifier = Column(String, nullable=False)
    
    # Relationships
    encrypted_data = relationship("EncryptedData", back_populates="user", cascade="all, delete-orphan")
    access_grants = relationship("AccessGrant", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")