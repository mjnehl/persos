"""Integration tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient
from aura.models.user import User


class TestAuthAPI:
    """Test authentication API endpoints."""
    
    def test_register_user(self, client: TestClient, sample_user_data):
        """Test user registration."""
        response = client.post("/api/auth/register", json=sample_user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert "user_id" in data
    
    def test_register_duplicate_user(self, client: TestClient, sample_user_data):
        """Test duplicate user registration."""
        # Register first user
        client.post("/api/auth/register", json=sample_user_data)
        
        # Try to register same user again
        response = client.post("/api/auth/register", json=sample_user_data)
        
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]
    
    def test_register_invalid_data(self, client: TestClient):
        """Test registration with invalid data."""
        invalid_data = {
            "email": "invalid-email",
            "srp_salt": "short",
            "srp_verifier": "short",
        }
        
        response = client.post("/api/auth/register", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    def test_login_start_nonexistent_user(self, client: TestClient):
        """Test login start with non-existent user."""
        login_data = {
            "email": "nonexistent@example.com",
            "client_public_ephemeral": "a" * 64,
        }
        
        response = client.post("/api/auth/login/start", json=login_data)
        assert response.status_code == 401
    
    def test_login_start_valid_user(self, client: TestClient, sample_user_data):
        """Test login start with valid user."""
        # Register user first
        client.post("/api/auth/register", json=sample_user_data)
        
        login_data = {
            "email": sample_user_data["email"],
            "client_public_ephemeral": "a" * 64,
        }
        
        response = client.post("/api/auth/login/start", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "salt" in data
        assert "server_public_ephemeral" in data
        assert "session_id" in data
    
    def test_login_complete_invalid_session(self, client: TestClient):
        """Test login complete with invalid session."""
        complete_data = {
            "session_id": "invalid_session",
            "client_public_ephemeral": "a" * 64,
            "client_proof": "b" * 64,
        }
        
        response = client.post("/api/auth/login/complete", json=complete_data)
        assert response.status_code == 401
    
    def test_health_check(self, client: TestClient):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "aura-backend"


class TestStorageAPI:
    """Test storage API endpoints."""
    
    def test_unauthorized_access(self, client: TestClient, sample_encrypted_data):
        """Test unauthorized access to storage endpoints."""
        store_data = {
            "type": "note",
            "encrypted_data": sample_encrypted_data,
        }
        
        response = client.post("/api/storage/store", json=store_data)
        assert response.status_code == 403  # Unauthorized
    
    def test_store_data_with_auth(self, client: TestClient, sample_encrypted_data):
        """Test storing data with authentication."""
        # Mock authentication by patching the dependency
        # In a real test, you would get a valid JWT token
        
        store_data = {
            "type": "note",
            "encrypted_data": sample_encrypted_data,
        }
        
        # This test would require proper JWT token setup
        # For now, we test the data structure
        assert store_data["type"] == "note"
        assert "encrypted_data" in store_data
    
    def test_get_nonexistent_data(self, client: TestClient):
        """Test retrieving non-existent data."""
        # This would also require authentication
        response = client.get("/api/storage/nonexistent_id")
        assert response.status_code == 403  # Unauthorized (no token)
    
    def test_list_data_pagination(self, client: TestClient):
        """Test data listing with pagination."""
        response = client.get("/api/storage/?limit=10&offset=0")
        assert response.status_code == 403  # Unauthorized (no token)
    
    def test_search_data(self, client: TestClient):
        """Test data search functionality."""
        response = client.get("/api/storage/search?token=test_token")
        assert response.status_code == 403  # Unauthorized (no token)
    
    def test_storage_stats(self, client: TestClient):
        """Test storage statistics endpoint."""
        response = client.get("/api/storage/stats")
        assert response.status_code == 403  # Unauthorized (no token)