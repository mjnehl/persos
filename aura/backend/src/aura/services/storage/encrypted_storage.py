"""Encrypted storage service for Aura."""

import json
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, asc

from aura.models.encrypted_data import EncryptedData
from aura.core.crypto.random import generate_uuid
from .types import StorageOptions, StorageMetadata, StorageStats, SearchResult


class EncryptedStorageService:
    """Encrypted storage service - all data is encrypted client-side before storage."""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def store(self, user_id: str, options: StorageOptions) -> EncryptedData:
        """
        Store encrypted data.
        The service never sees the plaintext data.
        """
        # Calculate data size
        encrypted_json = options.encrypted_data.model_dump_json()
        data_size = len(encrypted_json.encode('utf-8'))
        
        # Create encrypted data record
        encrypted_data = EncryptedData(
            id=generate_uuid(),
            user_id=user_id,
            type=options.type,
            encrypted_blob=encrypted_json,
            search_index=options.search_index,
            data_size=data_size,
            version=options.encrypted_data.version,
        )
        
        self.db.add(encrypted_data)
        self.db.commit()
        self.db.refresh(encrypted_data)
        
        return encrypted_data
    
    async def retrieve(self, user_id: str, data_id: str) -> Optional[EncryptedData]:
        """Retrieve encrypted data by ID."""
        return (
            self.db.query(EncryptedData)
            .filter(
                EncryptedData.id == data_id,
                EncryptedData.user_id == user_id
            )
            .first()
        )
    
    async def list_data(
        self,
        user_id: str,
        data_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "created_at",
        order: str = "desc",
    ) -> SearchResult:
        """List encrypted data by type."""
        query = self.db.query(EncryptedData).filter(EncryptedData.user_id == user_id)
        
        if data_type:
            query = query.filter(EncryptedData.type == data_type)
        
        # Apply ordering
        order_column = getattr(EncryptedData, order_by, EncryptedData.created_at)
        if order == "desc":
            query = query.order_by(desc(order_column))
        else:
            query = query.order_by(asc(order_column))
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        data = query.offset(offset).limit(limit).all()
        
        return SearchResult(data=data, total=total)
    
    async def update(
        self,
        user_id: str,
        data_id: str,
        options: StorageOptions,
    ) -> Optional[EncryptedData]:
        """Update encrypted data."""
        encrypted_data = await self.retrieve(user_id, data_id)
        if not encrypted_data:
            return None
        
        # Calculate new data size
        encrypted_json = options.encrypted_data.model_dump_json()
        data_size = len(encrypted_json.encode('utf-8'))
        
        # Update fields
        encrypted_data.type = options.type
        encrypted_data.encrypted_blob = encrypted_json
        encrypted_data.search_index = options.search_index
        encrypted_data.data_size = data_size
        encrypted_data.version = options.encrypted_data.version
        
        self.db.commit()
        self.db.refresh(encrypted_data)
        
        return encrypted_data
    
    async def delete(self, user_id: str, data_id: str) -> bool:
        """Delete encrypted data."""
        encrypted_data = await self.retrieve(user_id, data_id)
        if not encrypted_data:
            return False
        
        self.db.delete(encrypted_data)
        self.db.commit()
        
        return True
    
    async def search(
        self,
        user_id: str,
        encrypted_search_token: str,
        data_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> SearchResult:
        """
        Search encrypted data using encrypted search index.
        The search is performed on encrypted indexes without decryption.
        """
        query = (
            self.db.query(EncryptedData)
            .filter(EncryptedData.user_id == user_id)
            .filter(EncryptedData.search_index.contains(encrypted_search_token))
        )
        
        if data_type:
            query = query.filter(EncryptedData.type == data_type)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        data = (
            query.order_by(desc(EncryptedData.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )
        
        return SearchResult(data=data, total=total)
    
    async def get_stats(self, user_id: str) -> StorageStats:
        """Get storage statistics for a user."""
        # Get all data for the user
        data = (
            self.db.query(EncryptedData.type, EncryptedData.data_size)
            .filter(EncryptedData.user_id == user_id)
            .all()
        )
        
        by_type: Dict[str, Dict[str, int]] = {}
        total_size = 0
        
        for item in data:
            data_type, size = item
            
            if data_type not in by_type:
                by_type[data_type] = {"count": 0, "size": 0}
            
            by_type[data_type]["count"] += 1
            by_type[data_type]["size"] += size
            total_size += size
        
        return StorageStats(
            total_items=len(data),
            total_size=total_size,
            by_type=by_type,
        )
    
    async def bulk_delete(self, user_id: str, data_ids: List[str]) -> int:
        """Bulk delete encrypted data."""
        count = (
            self.db.query(EncryptedData)
            .filter(
                EncryptedData.id.in_(data_ids),
                EncryptedData.user_id == user_id
            )
            .delete(synchronize_session=False)
        )
        
        self.db.commit()
        return count