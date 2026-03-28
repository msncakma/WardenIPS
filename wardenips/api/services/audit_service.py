"""Audit service - audit logging for all operations."""

from datetime import datetime, timezone
import json
from typing import Dict, Optional, List
from enum import Enum


class AuditAction(Enum):
    """Audit action types."""
    BAN_IP = "ban_ip"
    UNBAN_IP = "unban_ip"
    WHITELIST_ADD = "whitelist_add"
    WHITELIST_REMOVE = "whitelist_remove"
    CONFIG_UPDATE = "config_update"
    CONFIG_RELOAD = "config_reload"
    FIREWALL_SYNC = "firewall_sync"
    PLUGIN_RELOAD = "plugin_reload"
    USER_CREATE = "user_create"
    USER_DELETE = "user_delete"
    USER_UPDATE = "user_update"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    LOGIN_FAILED = "login_failed"


class AuditService:
    """Audit logging service for tracking all operations."""
    
    def __init__(self, db):
        """Initialize audit service.
        
        Args:
            db: Database manager
        """
        self.db = db
    
    async def log_action(
        self,
        action: AuditAction,
        actor: str,
        target: Optional[str] = None,
        details: Optional[Dict] = None,
        status: str = "success",
    ) -> Dict:
        """Log an action to audit log.
        
        Args:
            action: Action type (AuditAction enum)
            actor: Username of the actor
            target: Subject of the action (e.g., IP address, username)
            details: Additional details dict
            status: success/failure/warning
        
        Returns:
            Log entry dict
        """
        try:
            action_value = action.value if isinstance(action, AuditAction) else str(action)
            entry = {
                "action": action_value,
                "actor": actor,
                "target": target,
                "status": status,
                "details": details,
                "timestamp": datetime.now(timezone.utc),
                "level": self._status_to_level(status),
            }

            if self.db and hasattr(self.db, "log_audit_event"):
                db_details = dict(details or {})
                db_details["status"] = status
                await self.db.log_audit_event(
                    action=action_value,
                    actor_username=actor,
                    target=target,
                    details=db_details,
                )
            
            return entry
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def get_audit_log(
        self,
        limit: int = 100,
        offset: int = 0,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
    ) -> List[Dict]:
        """Get audit log entries.
        
        Args:
            limit: Max entries to return
            offset: Pagination offset
            actor: Filter by actor (optional)
            action: Filter by action (optional)
            target: Filter by target (optional)
        
        Returns:
            List of audit entries
        """
        try:
            if not self.db or not hasattr(self.db, "get_audit_events"):
                return []

            events = await self.db.get_audit_events(
                limit=limit + max(0, offset),
                actor=actor or "",
                action=action or "",
            )

            if target:
                events = [e for e in events if str(e.get("target") or "") == str(target)]

            selected = events[offset:offset + limit]
            for event in selected:
                raw = event.get("details_json")
                if isinstance(raw, str) and raw:
                    try:
                        event["details"] = json.loads(raw)
                    except Exception:
                        event["details"] = raw

            return selected
        
        except Exception as e:
            return []
    
    async def get_actor_activity(
        self,
        actor: str,
        limit: int = 50,
    ) -> List[Dict]:
        """Get all activity for a specific actor.
        
        Args:
            actor: Username
            limit: Max entries
        
        Returns:
            List of audit entries
        """
        return await self.get_audit_log(limit=limit, actor=actor)
    
    async def get_target_activity(
        self,
        target: str,
        limit: int = 50,
    ) -> List[Dict]:
        """Get all activity for a specific target (e.g., IP).
        
        Args:
            target: Target identifier (IP, username, etc.)
            limit: Max entries
        
        Returns:
            List of audit entries
        """
        return await self.get_audit_log(limit=limit, target=target)
    
    @staticmethod
    def _status_to_level(status: str) -> str:
        """Convert status to log level.
        
        Args:
            status: success/failure/warning
        
        Returns:
            Log level: INFO/WARNING/ERROR
        """
        if status == "success":
            return "INFO"
        elif status == "warning":
            return "WARNING"
        else:  # failure
            return "ERROR"
