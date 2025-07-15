"""Storage type definitions."""

from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel

from aura.core.crypto.types import EncryptedData


class StorageOptions(BaseModel):
    """Options for storing encrypted data."""
    
    type: str
    encrypted_data: EncryptedData
    search_index: Optional[str] = None


class StorageMetadata(BaseModel):
    """Metadata for stored data."""
    
    id: str
    type: str
    size: int
    created_at: datetime
    updated_at: datetime


class StorageStats(BaseModel):
    """Storage statistics."""
    
    total_items: int
    total_size: int
    by_type: Dict[str, Dict[str, int]]


class SearchResult(BaseModel):
    """Search result container."""
    
    data: list
    total: int