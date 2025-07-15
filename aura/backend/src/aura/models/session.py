"""Session model."""

from sqlalchemy import Column, String, DateTime, Index

from .base import Base, TimestampMixin


class Session(Base, TimestampMixin):
    """Session storage for SRP sessions."""
    
    __tablename__ = "sessions"
    
    id = Column(String, primary_key=True)
    session_data = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('ix_sessions_expires', 'expires_at'),
    )