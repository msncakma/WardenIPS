"""Firewall service - rule management, synchronization, reconciliation."""

from datetime import datetime, timezone
from typing import Dict, Optional


class FirewallService:
    """Firewall management and synchronization service."""
    
    def __init__(self, firewall):
        """Initialize firewall service.
        
        Args:
            firewall: Firewall manager instance
        """
        self.firewall = firewall
    
    async def get_status(self) -> Dict:
        """Get firewall operational status.
        
        Returns:
            Status dict
        """
        try:
            if not self.firewall:
                return {"status": "error", "error": "Firewall not available"}

            status = await self.firewall.get_status()
            return {
                "status": "operational",
                "firewall": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def sync_firewall(self, dry_run: bool = False) -> Dict:
        """Synchronize firewall rules with database.
        
        This reconciles:
        - Active bans in DB vs kernel rules
        - Whitelisted IPs vs kernel rules
        - Rule counts and status
        
        Args:
            dry_run: If True, report changes without applying
        
        Returns:
            Sync result dict with counts
        """
        try:
            if not self.firewall:
                return {"status": "error", "error": "Firewall not available"}

            result = await self.firewall.reconcile(dry_run=dry_run)
            result["timestamp"] = datetime.now(timezone.utc).isoformat()
            return result
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def apply_ban(self, ip: str, duration: int = 0) -> Dict:
        """Apply ban to firewall for an IP.
        
        Args:
            ip: IP address to ban
            duration: Duration in seconds (0 = permanent)
        
        Returns:
            Result dict
        """
        try:
            if not self.firewall:
                return {
                    "status": "error",
                    "error": "Firewall not available",
                }
            
            await self._validate_ip(ip)
            await self.firewall.apply_ban(ip, duration=duration)
            
            return {
                "status": "ok",
                "ip": ip,
                "duration": duration,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def remove_ban(self, ip: str) -> Dict:
        """Remove ban from firewall for an IP.
        
        Args:
            ip: IP address to unban
        
        Returns:
            Result dict
        """
        try:
            if not self.firewall:
                return {
                    "status": "error",
                    "error": "Firewall not available",
                }
            
            await self._validate_ip(ip)
            await self.firewall.remove_ban(ip)
            
            return {
                "status": "ok",
                "ip": ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    @staticmethod
    async def _validate_ip(ip: str) -> bool:
        """Validate IP address format.
        
        Args:
            ip: IP to validate
        
        Returns:
            True if valid IPv4
        
        Raises:
            ValueError if invalid
        """
        import ipaddress
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv4 address: {ip}")
