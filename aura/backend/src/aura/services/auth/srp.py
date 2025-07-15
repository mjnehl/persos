"""SRP-6a (Secure Remote Password) implementation for zero-knowledge authentication."""

import time
import hmac
import hashlib
from typing import Dict, Optional, Tuple
import srp

from aura.core.crypto.random import generate_token, secure_compare
from .types import SRPSession, SRPChallenge


class SRPAuthService:
    """SRP-6a authentication service."""
    
    def __init__(self):
        self.sessions: Dict[str, SRPSession] = {}
        self.session_timeout = 5 * 60  # 5 minutes
    
    @staticmethod
    def generate_verifier(username: str, password: str) -> Tuple[str, str]:
        """
        Generate SRP verifier from username and password.
        This should be done on the client side.
        """
        salt, verifier = srp.create_salted_verification_key(username, password)
        return salt.hex(), verifier.hex()
    
    async def start_authentication(
        self,
        username: str,
        client_public_ephemeral: str,
        stored_salt: str,
        stored_verifier: str,
    ) -> SRPChallenge:
        """
        Start SRP authentication - Phase 1.
        Client sends username, server responds with salt and challenge.
        """
        # Clean up expired sessions
        await self._cleanup_sessions()
        
        try:
            # Convert hex strings back to bytes
            salt_bytes = bytes.fromhex(stored_salt)
            verifier_bytes = bytes.fromhex(stored_verifier)
            
            # Create SRP server instance
            srv = srp.Server(username, salt_bytes, verifier_bytes)
            
            # Process client's public ephemeral
            client_pub_bytes = bytes.fromhex(client_public_ephemeral)
            server_public_ephemeral = srv.get_challenge()
            
            # Create session
            session_id = generate_token(32)
            session = SRPSession(
                identifier=username,
                salt=stored_salt,
                server_ephemeral_secret=srv.get_ephemeral_secret().hex(),
                server_ephemeral_public=server_public_ephemeral.hex(),
                verifier=stored_verifier,
                timestamp=time.time(),
            )
            
            self.sessions[session_id] = session
            
            return SRPChallenge(
                salt=stored_salt,
                server_public_ephemeral=server_public_ephemeral.hex(),
                session_id=session_id,
            )
            
        except Exception as e:
            raise ValueError(f"Failed to start authentication: {str(e)}")
    
    async def complete_authentication(
        self,
        session_id: str,
        client_public_ephemeral: str,
        client_proof: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Complete SRP authentication - Phase 2.
        Client sends proof, server verifies and responds with proof.
        """
        session = self.sessions.get(session_id)
        if not session:
            return False, None
        
        # Check session timeout
        if time.time() - session.timestamp > self.session_timeout:
            del self.sessions[session_id]
            return False, None
        
        try:
            # Recreate server instance
            salt_bytes = bytes.fromhex(session.salt)
            verifier_bytes = bytes.fromhex(session.verifier)
            srv = srp.Server(session.identifier, salt_bytes, verifier_bytes)
            
            # Set ephemeral values
            server_ephemeral_secret = bytes.fromhex(session.server_ephemeral_secret)
            srv.set_ephemeral_secret(server_ephemeral_secret)
            
            # Process client proof
            client_pub_bytes = bytes.fromhex(client_public_ephemeral)
            client_proof_bytes = bytes.fromhex(client_proof)
            
            # Verify client proof and get server proof
            server_proof = srv.verify_proof(client_pub_bytes, client_proof_bytes)
            
            # Clean up session
            del self.sessions[session_id]
            
            return True, server_proof.hex()
            
        except Exception:
            # Authentication failed
            if session_id in self.sessions:
                del self.sessions[session_id]
            return False, None
    
    async def _cleanup_sessions(self) -> None:
        """Clean up expired sessions."""
        current_time = time.time()
        expired_sessions = [
            session_id
            for session_id, session in self.sessions.items()
            if current_time - session.timestamp > self.session_timeout
        ]
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
    
    def get_active_session_count(self) -> int:
        """Get active session count for monitoring."""
        return len(self.sessions)