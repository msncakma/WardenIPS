"""Authentication service - TOTP, password hashing, session management."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Tuple
import secrets
from wardenips.core.auth import hash_password, verify_password, verify_totp_code


class AuthService:
    """Authentication and session management service."""
    
    def __init__(self, db):
        """Initialize auth service.
        
        Args:
            db: Database manager instance
        """
        self.db = db
        self.sessions = {}  # In-memory session store (production: use Redis)
    
    async def authenticate(self, username: str, password: str, totp_code: Optional[str] = None) -> Tuple[bool, str]:
        """Authenticate user with password and optional TOTP.
        
        Args:
            username: Username
            password: Password
            totp_code: 6-digit TOTP code (if 2FA enabled)
        
        Returns:
            Tuple[is_valid, session_token]
        """
        try:
            user = await self.db.get_admin_user_by_username(username)
            if not user:
                await self.db.record_admin_failed_login(username, lock_seconds=0)
                return False, "invalid credentials"

            locked_until_raw = str(user.get("locked_until") or "").strip()
            if locked_until_raw:
                try:
                    locked_until = datetime.fromisoformat(locked_until_raw.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    if locked_until.tzinfo is None:
                        locked_until = locked_until.replace(tzinfo=timezone.utc)
                    if locked_until > now:
                        return False, "account temporarily locked"
                except Exception:
                    pass

            is_valid = await self._verify_password(password, str(user.get("password_hash") or ""))
            if not is_valid:
                await self.db.record_admin_failed_login(username, lock_seconds=300)
                return False, "invalid credentials"

            if bool(user.get("totp_enabled")):
                secret = str(user.get("totp_secret") or "")
                if not self._verify_totp(str(totp_code or ""), secret):
                    await self.db.record_admin_failed_login(username, lock_seconds=300)
                    return False, "invalid 2FA code"
            
            # Generate session token
            session_token = secrets.token_urlsafe(32)
            
            # Store session
            self.sessions[session_token] = {
                "username": username,
                "created_at": datetime.now(timezone.utc),
                "last_activity": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(hours=8),
            }

            await self.db.record_admin_login(username, "api")
            
            return True, session_token
        
        except Exception as e:
            return False, str(e)
    
    async def validate_session(self, session_token: str) -> Tuple[bool, Optional[str]]:
        """Validate session token.
        
        Args:
            session_token: Session token
        
        Returns:
            Tuple[is_valid, username]
        """
        if session_token not in self.sessions:
            return False, None
        
        session = self.sessions[session_token]
        
        # Check expiration
        if datetime.now(timezone.utc) > session["expires_at"]:
            del self.sessions[session_token]
            return False, None
        
        # Update last activity
        session["last_activity"] = datetime.now(timezone.utc)
        
        return True, session["username"]
    
    async def revoke_session(self, session_token: str) -> bool:
        """Revoke session.
        
        Args:
            session_token: Session token
        
        Returns:
            True if revoked, False if not found
        """
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False
    
    async def get_session_info(self, session_token: str) -> Optional[Dict]:
        """Get session information.
        
        Args:
            session_token: Session token
        
        Returns:
            Session dict or None
        """
        return self.sessions.get(session_token)
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password using argon2 (production-grade).
        
        Args:
            password: Plain text password
        
        Returns:
            Hashed password (argon2)
        """
        return hash_password(password)
    
    @staticmethod
    async def _verify_password(password: str, hash_value: str) -> bool:
        """Verify password against hash using argon2.
        
        Args:
            password: Plain text password
            hash_value: Hashed password (argon2)
        
        Returns:
            True if valid
        """
        return verify_password(hash_value, password)
    
    @staticmethod
    def _verify_totp(code: str, secret: str) -> bool:
        """Verify TOTP code using time-based one-time password.
        
        Args:
            code: 6-digit TOTP code
            secret: TOTP secret key
        
        Returns:
            True if code is valid
        """
        return verify_totp_code(secret, code, valid_window=1)
