"""Encrypted data model."""

from sqlalchemy import Column, String, Integer, ForeignKey, Index
from sqlalchemy.orm import relationship

from .base import Base, TimestampMixin


class EncryptedData(Base, TimestampMixin):
    """Encrypted data storage - all user data is encrypted."""
    
    __tablename__ = "encrypted_data"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type = Column(String, nullable=False)  # e.g., "note", "task", "preference"
    
    # Encrypted fields
    encrypted_blob = Column(String, nullable=False)  # The actual encrypted data
    search_index = Column(String, nullable=True)     # Encrypted search index
    
    # Metadata (not encrypted)
    data_size = Column(Integer, nullable=False)
    version = Column(Integer, default=1, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="encrypted_data")
    
    # Indexes
    __table_args__ = (
        Index('ix_encrypted_data_user_type', 'user_id', 'type'),
        Index('ix_encrypted_data_user_created', 'user_id', 'created_at'),
    )