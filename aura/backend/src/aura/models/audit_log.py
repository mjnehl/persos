"""Audit log model."""

from sqlalchemy import Column, String, DateTime, ForeignKey, Index, JSON
from sqlalchemy.orm import relationship

from .base import Base


class AuditLog(Base):
    """Audit log for all access."""
    
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    grant_id = Column(String, ForeignKey("access_grants.id", ondelete="SET NULL"), nullable=True)
    
    # Audit data
    action = Column(String, nullable=False)  # e.g., "data_accessed", "grant_created"
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    metadata = Column(JSON, nullable=True)  # Additional audit information
    
    # Request information
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    
    timestamp = Column(DateTime, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    access_grant = relationship("AccessGrant", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('ix_audit_logs_user', 'user_id'),
        Index('ix_audit_logs_grant', 'grant_id'),
        Index('ix_audit_logs_timestamp', 'timestamp'),
    )