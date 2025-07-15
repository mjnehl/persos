"""Access grant model for support access control."""

from sqlalchemy import Column, String, DateTime, ForeignKey, Index, ARRAY
from sqlalchemy.orm import relationship

from .base import Base


class AccessGrant(Base):
    """Support access grants."""
    
    __tablename__ = "access_grants"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    granted_by = Column(String, nullable=False)  # User ID who granted access
    
    # Access parameters
    scope = Column(ARRAY(String), nullable=False)  # What data can be accessed
    purpose = Column(String, nullable=False)       # Why access was requested
    
    # Time bounds
    granted_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    
    # Cryptographic proof
    access_token = Column(String, unique=True, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="access_grants")
    audit_logs = relationship("AuditLog", back_populates="access_grant")
    
    # Indexes
    __table_args__ = (
        Index('ix_access_grants_user', 'user_id'),
        Index('ix_access_grants_token', 'access_token'),
        Index('ix_access_grants_expires', 'expires_at'),
    )