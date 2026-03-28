"""Ban service - encapsulate ban-related business logic."""

from typing import Any, Dict, List, Optional
from wardenips.core.logger import get_logger


logger = get_logger(__name__)


class BanService:
    """Service for ban operations (ban/unban IPs)."""
    
    def __init__(self, db, firewall, whitelist=None):
        """
        Initialize ban service.
        
        Args:
            db: DatabaseManager instance
            firewall: FirewallManager instance
            whitelist: WhitelistManager instance (optional)
        """
        self.db = db
        self.firewall = firewall
        self.whitelist = whitelist
    
    async def ban_ip(
        self,
        ip: str,
        duration_seconds: int = 0,
        reason: str = "",
        actor: str = "system",
    ) -> Dict[str, Any]:
        """
        Ban an IP address.
        
        Args:
            ip: IP address to ban
            duration_seconds: Ban duration in seconds (0 = permanent)
            reason: Reason for banning
            actor: Who initiated the ban (for audit logging)
        
        Returns:
            Dict with ban result
        """
        try:
            # Check if already whitelisted
            if self.whitelist and await self.whitelist.is_whitelisted(ip):
                return {
                    "status": "skipped",
                    "reason": "IP is whitelisted",
                    "ip": ip,
                }
            
            # Apply firewall ban
            await self.firewall.apply_ban(ip, duration=duration_seconds)
            
            # Record in database
            await self.db.record_ban(
                source_ip=ip,
                reason=reason or "Manual ban via CLI/API",
                duration_seconds=duration_seconds,
            )
            
            logger.info(f"IP {ip} banned by {actor}: {reason}")
            
            return {
                "status": "ok",
                "ip": ip,
                "duration": duration_seconds,
                "reason": reason,
                "actor": actor,
            }
        
        except Exception as e:
            logger.error(f"Failed to ban IP {ip}: {e}")
            return {
                "status": "error",
                "error": str(e),
                "ip": ip,
            }
    
    async def unban_ip(self, ip: str, actor: str = "system") -> Dict[str, Any]:
        """
        Unban an IP address (remove from firewall and mark as unbanned).
        
        Args:
            ip: IP address to unban
            actor: Who initiated the unban
        
        Returns:
            Dict with unban result
        """
        try:
            # Remove from firewall
            await self.firewall.remove_ban(ip)
            
            # Record in database
            await self.db.record_unban(ip)
            
            logger.info(f"IP {ip} unbanned by {actor}")
            
            return {
                "status": "ok",
                "ip": ip,
                "actor": actor,
            }
        
        except Exception as e:
            logger.error(f"Failed to unban IP {ip}: {e}")
            return {
                "status": "error",
                "error": str(e),
                "ip": ip,
            }
    
    async def get_active_bans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of currently active bans."""
        try:
            bans = await self.db.get_active_bans(limit=limit)
            return bans
        except Exception as e:
            logger.error(f"Failed to get active bans: {e}")
            return []
    
    async def bulk_ban(
        self,
        ips: List[str],
        duration_seconds: int = 0,
        reason: str = "",
        actor: str = "system",
    ) -> Dict[str, Any]:
        """
        Ban multiple IPs.
        
        Args:
            ips: List of IP addresses to ban
            duration_seconds: Ban duration
            reason: Reason for banning
            actor: Who initiated the ban
        
        Returns:
            Dict with bulk ban result
        """
        results = {
            "total": len(ips),
            "successful": 0,
            "failed": 0,
            "skipped": 0,
            "errors": [],
            "details": [],
        }
        
        for ip in ips:
            result = await self.ban_ip(ip, duration_seconds, reason, actor)
            
            if result["status"] == "ok":
                results["successful"] += 1
            elif result["status"] == "skipped":
                results["skipped"] += 1
            else:
                results["failed"] += 1
                results["errors"].append(f"{ip}: {result.get('error', 'Unknown error')}")
            
            results["details"].append(result)
        
        return results
