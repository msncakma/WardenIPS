"""Whitelist service - CRUD operations for whitelist entries."""

from datetime import datetime, timezone
from typing import List, Dict, Optional


class WhitelistService:
    """Whitelist management service."""
    
    def __init__(self, db, whitelist=None):
        """Initialize whitelist service.
        
        Args:
            db: Database manager
            whitelist: Whitelist manager (optional)
        """
        self.db = db
        self.whitelist = whitelist
        self._entries: Dict[str, Dict] = {}
    
    async def list_whitelist(self) -> List[Dict]:
        """Get all whitelist entries.
        
        Returns:
            List of whitelist entry dicts
        """
        try:
            if not self.whitelist:
                return []

            entries = []
            for ip in getattr(self.whitelist, "_whitelisted_ips", set()):
                key = str(ip)
                meta = self._entries.get(key, {})
                entries.append(
                    {
                        "id": key,
                        "ip": key,
                        "reason": meta.get("reason", ""),
                        "tag": meta.get("tag", ""),
                        "created_at": meta.get("created_at"),
                        "type": "ip",
                    }
                )

            for network in getattr(self.whitelist, "_whitelisted_networks", []):
                key = str(network)
                meta = self._entries.get(key, {})
                entries.append(
                    {
                        "id": key,
                        "ip": key,
                        "reason": meta.get("reason", ""),
                        "tag": meta.get("tag", ""),
                        "created_at": meta.get("created_at"),
                        "type": "cidr",
                    }
                )

            return entries
        except Exception as e:
            raise Exception(f"Failed to list whitelist: {str(e)}")
    
    async def add_whitelist(
        self,
        ip_or_cidr: str,
        reason: str = "",
        tag: str = "",
    ) -> Dict:
        """Add entry to whitelist.
        
        Args:
            ip_or_cidr: IP address or CIDR range
            reason: Why this IP is whitelisted
            tag: Optional tag for grouping
        
        Returns:
            Result dict with entry ID
        """
        try:
            value = str(ip_or_cidr or "").strip()
            if not value:
                return {"status": "error", "error": "ip_or_cidr is required"}

            if not self.whitelist:
                return {"status": "error", "error": "whitelist manager not available"}

            # For now, whitelist updates are runtime-only and reflected in memory.
            added = await self.whitelist.add_runtime_ips([value])
            entry_id = value
            self._entries[value] = {
                "reason": reason,
                "tag": tag,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            
            return {
                "status": "added" if added > 0 else "exists",
                "id": entry_id,
                "ip": value,
                "reason": reason,
                "tag": tag,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def remove_whitelist(self, entry_id: str) -> Dict:
        """Remove entry from whitelist.
        
        Args:
            entry_id: Whitelist entry ID
        
        Returns:
            Result dict
        """
        try:
            value = str(entry_id or "").strip()
            if not value:
                return {"status": "error", "error": "entry_id is required"}

            if self.whitelist:
                removed = await self.whitelist.remove_runtime_ips([value])
            else:
                removed = 0

            self._entries.pop(value, None)
            
            return {
                "status": "removed" if removed > 0 else "not_found",
                "id": value,
                "removed_at": datetime.now(timezone.utc).isoformat(),
            }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def update_whitelist(
        self,
        entry_id: str,
        reason: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> Dict:
        """Update whitelist entry.
        
        Args:
            entry_id: Entry ID
            reason: New reason (if provided)
            tag: New tag (if provided)
        
        Returns:
            Result dict
        """
        try:
            value = str(entry_id or "").strip()
            if not value:
                return {"status": "error", "error": "entry_id is required"}

            if value not in self._entries:
                self._entries[value] = {
                    "reason": "",
                    "tag": "",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

            if reason is not None:
                self._entries[value]["reason"] = reason
            if tag is not None:
                self._entries[value]["tag"] = tag
            
            return {
                "status": "updated",
                "id": value,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted.
        
        Args:
            ip: IP address to check
        
        Returns:
            True if whitelisted
        """
        try:
            if self.whitelist:
                return await self.whitelist.is_whitelisted(ip)
            return False
        except Exception:
            return False
