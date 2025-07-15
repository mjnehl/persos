"""Encrypted storage API routes."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from aura.services.storage import EncryptedStorageService, StorageOptions
from aura.core.database import get_db
from aura.core.auth import get_current_user
from aura.core.crypto.types import EncryptedData


router = APIRouter(prefix="/storage", tags=["storage"])


class StoreDataRequest(BaseModel):
    """Request to store encrypted data."""
    type: str
    encrypted_data: EncryptedData
    search_index: Optional[str] = None


class StorageResponse(BaseModel):
    """Storage operation response."""
    id: str
    type: str
    size: int
    created_at: str


class DataResponse(BaseModel):
    """Data retrieval response."""
    id: str
    type: str
    encrypted_data: EncryptedData
    created_at: str
    updated_at: str


class ListResponse(BaseModel):
    """List response with pagination."""
    data: List[StorageResponse]
    total: int
    limit: int
    offset: int


@router.post("/store", response_model=StorageResponse, status_code=status.HTTP_201_CREATED)
async def store_data(
    request: StoreDataRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Store encrypted data."""
    storage_service = EncryptedStorageService(db)
    
    options = StorageOptions(
        type=request.type,
        encrypted_data=request.encrypted_data,
        search_index=request.search_index,
    )
    
    data = await storage_service.store(current_user["id"], options)
    
    return StorageResponse(
        id=data.id,
        type=data.type,
        size=data.data_size,
        created_at=data.created_at.isoformat(),
    )


@router.get("/{data_id}", response_model=DataResponse)
async def get_data(
    data_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve encrypted data by ID."""
    storage_service = EncryptedStorageService(db)
    
    data = await storage_service.retrieve(current_user["id"], data_id)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Data not found",
        )
    
    return DataResponse(
        id=data.id,
        type=data.type,
        encrypted_data=EncryptedData.model_validate_json(data.encrypted_blob),
        created_at=data.created_at.isoformat(),
        updated_at=data.updated_at.isoformat(),
    )


@router.get("/", response_model=ListResponse)
async def list_data(
    data_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    order_by: str = Query("created_at"),
    order: str = Query("desc"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List encrypted data with pagination."""
    storage_service = EncryptedStorageService(db)
    
    result = await storage_service.list_data(
        current_user["id"],
        data_type=data_type,
        limit=limit,
        offset=offset,
        order_by=order_by,
        order=order,
    )
    
    return ListResponse(
        data=[
            StorageResponse(
                id=item.id,
                type=item.type,
                size=item.data_size,
                created_at=item.created_at.isoformat(),
            )
            for item in result.data
        ],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.put("/{data_id}", response_model=StorageResponse)
async def update_data(
    data_id: str,
    request: StoreDataRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update encrypted data."""
    storage_service = EncryptedStorageService(db)
    
    options = StorageOptions(
        type=request.type,
        encrypted_data=request.encrypted_data,
        search_index=request.search_index,
    )
    
    data = await storage_service.update(current_user["id"], data_id, options)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Data not found",
        )
    
    return StorageResponse(
        id=data.id,
        type=data.type,
        size=data.data_size,
        created_at=data.updated_at.isoformat(),
    )


@router.delete("/{data_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_data(
    data_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete encrypted data."""
    storage_service = EncryptedStorageService(db)
    
    deleted = await storage_service.delete(current_user["id"], data_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Data not found",
        )


@router.get("/search", response_model=ListResponse)
async def search_data(
    token: str = Query(...),
    data_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Search encrypted data using encrypted tokens."""
    storage_service = EncryptedStorageService(db)
    
    result = await storage_service.search(
        current_user["id"],
        token,
        data_type=data_type,
        limit=limit,
        offset=offset,
    )
    
    return ListResponse(
        data=[
            StorageResponse(
                id=item.id,
                type=item.type,
                size=item.data_size,
                created_at=item.created_at.isoformat(),
            )
            for item in result.data
        ],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=dict)
async def get_storage_stats(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get storage statistics for the user."""
    storage_service = EncryptedStorageService(db)
    stats = await storage_service.get_stats(current_user["id"])
    return stats.model_dump()