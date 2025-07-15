"""Tests for encrypted storage service."""

import pytest
from sqlalchemy.orm import Session

from aura.services.storage import EncryptedStorageService, StorageOptions
from aura.core.crypto.types import EncryptedData
from aura.models.user import User
from aura.models.encrypted_data import EncryptedData as EncryptedDataModel
from aura.core.crypto.random import generate_uuid


class TestEncryptedStorageService:
    """Test encrypted storage service."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.user_id = generate_uuid()
        self.sample_encrypted_data = EncryptedData(
            ciphertext="dGVzdCBjaXBoZXJ0ZXh0",
            nonce="dGVzdCBub25jZQ==",
            algorithm="aes-256-gcm",
            version=1,
        )
    
    @pytest.mark.asyncio
    async def test_store_data(self, db: Session):
        """Test storing encrypted data."""
        storage_service = EncryptedStorageService(db)
        
        options = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
            search_index="encrypted_search_token",
        )
        
        result = await storage_service.store(self.user_id, options)
        
        assert result.user_id == self.user_id
        assert result.type == "note"
        assert result.search_index == "encrypted_search_token"
        assert result.data_size > 0
        assert result.version == 1
    
    @pytest.mark.asyncio
    async def test_retrieve_data(self, db: Session):
        """Test retrieving encrypted data."""
        storage_service = EncryptedStorageService(db)
        
        # Store data first
        options = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
        )
        stored = await storage_service.store(self.user_id, options)
        
        # Retrieve data
        retrieved = await storage_service.retrieve(self.user_id, stored.id)
        
        assert retrieved is not None
        assert retrieved.id == stored.id
        assert retrieved.user_id == self.user_id
        assert retrieved.type == "note"
    
    @pytest.mark.asyncio
    async def test_retrieve_nonexistent_data(self, db: Session):
        """Test retrieving non-existent data."""
        storage_service = EncryptedStorageService(db)
        
        result = await storage_service.retrieve(self.user_id, "nonexistent_id")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_list_data(self, db: Session):
        """Test listing encrypted data."""
        storage_service = EncryptedStorageService(db)
        
        # Store multiple data items
        for i in range(5):
            options = StorageOptions(
                type="note" if i % 2 == 0 else "task",
                encrypted_data=self.sample_encrypted_data,
            )
            await storage_service.store(self.user_id, options)
        
        # List all data
        result = await storage_service.list_data(self.user_id)
        assert result.total == 5
        assert len(result.data) == 5
        
        # List only notes
        result_notes = await storage_service.list_data(self.user_id, data_type="note")
        assert result_notes.total == 3
        assert len(result_notes.data) == 3
        
        # Test pagination
        result_page = await storage_service.list_data(self.user_id, limit=2, offset=1)
        assert result_page.total == 5
        assert len(result_page.data) == 2
    
    @pytest.mark.asyncio
    async def test_update_data(self, db: Session):
        """Test updating encrypted data."""
        storage_service = EncryptedStorageService(db)
        
        # Store data first
        options = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
        )
        stored = await storage_service.store(self.user_id, options)
        
        # Update data
        new_encrypted_data = EncryptedData(
            ciphertext="bmV3IGNpcGhlcnRleHQ=",
            nonce="bmV3IG5vbmNl",
            algorithm="aes-256-gcm",
            version=1,
        )
        
        update_options = StorageOptions(
            type="updated_note",
            encrypted_data=new_encrypted_data,
        )
        
        updated = await storage_service.update(self.user_id, stored.id, update_options)
        
        assert updated is not None
        assert updated.type == "updated_note"
        assert updated.encrypted_blob != stored.encrypted_blob
    
    @pytest.mark.asyncio
    async def test_update_nonexistent_data(self, db: Session):
        """Test updating non-existent data."""
        storage_service = EncryptedStorageService(db)
        
        options = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
        )
        
        result = await storage_service.update(self.user_id, "nonexistent_id", options)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_delete_data(self, db: Session):
        """Test deleting encrypted data."""
        storage_service = EncryptedStorageService(db)
        
        # Store data first
        options = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
        )
        stored = await storage_service.store(self.user_id, options)
        
        # Delete data
        deleted = await storage_service.delete(self.user_id, stored.id)
        assert deleted is True
        
        # Verify deletion
        retrieved = await storage_service.retrieve(self.user_id, stored.id)
        assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_data(self, db: Session):
        """Test deleting non-existent data."""
        storage_service = EncryptedStorageService(db)
        
        result = await storage_service.delete(self.user_id, "nonexistent_id")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_search_data(self, db: Session):
        """Test searching encrypted data."""
        storage_service = EncryptedStorageService(db)
        
        # Store data with search index
        options1 = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
            search_index="encrypted_token_123",
        )
        options2 = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
            search_index="encrypted_token_456",
        )
        
        await storage_service.store(self.user_id, options1)
        await storage_service.store(self.user_id, options2)
        
        # Search for specific token
        result = await storage_service.search(self.user_id, "token_123")
        assert result.total == 1
        assert len(result.data) == 1
    
    @pytest.mark.asyncio
    async def test_get_stats(self, db: Session):
        """Test getting storage statistics."""
        storage_service = EncryptedStorageService(db)
        
        # Store data of different types
        for i in range(3):
            options_note = StorageOptions(
                type="note",
                encrypted_data=self.sample_encrypted_data,
            )
            options_task = StorageOptions(
                type="task",
                encrypted_data=self.sample_encrypted_data,
            )
            
            await storage_service.store(self.user_id, options_note)
            await storage_service.store(self.user_id, options_task)
        
        # Get stats
        stats = await storage_service.get_stats(self.user_id)
        
        assert stats.total_items == 6
        assert stats.total_size > 0
        assert "note" in stats.by_type
        assert "task" in stats.by_type
        assert stats.by_type["note"]["count"] == 3
        assert stats.by_type["task"]["count"] == 3
    
    @pytest.mark.asyncio
    async def test_bulk_delete(self, db: Session):
        """Test bulk deletion of encrypted data."""
        storage_service = EncryptedStorageService(db)
        
        # Store multiple data items
        stored_ids = []
        for i in range(5):
            options = StorageOptions(
                type="note",
                encrypted_data=self.sample_encrypted_data,
            )
            stored = await storage_service.store(self.user_id, options)
            stored_ids.append(stored.id)
        
        # Bulk delete first 3 items
        deleted_count = await storage_service.bulk_delete(self.user_id, stored_ids[:3])
        assert deleted_count == 3
        
        # Verify remaining items
        result = await storage_service.list_data(self.user_id)
        assert result.total == 2
    
    @pytest.mark.asyncio
    async def test_user_isolation(self, db: Session):
        """Test that users can only access their own data."""
        storage_service = EncryptedStorageService(db)
        
        user1_id = generate_uuid()
        user2_id = generate_uuid()
        
        # Store data for user1
        options = StorageOptions(
            type="note",
            encrypted_data=self.sample_encrypted_data,
        )
        stored = await storage_service.store(user1_id, options)
        
        # Try to retrieve with user2
        retrieved = await storage_service.retrieve(user2_id, stored.id)
        assert retrieved is None
        
        # List data for user2 should be empty
        result = await storage_service.list_data(user2_id)
        assert result.total == 0