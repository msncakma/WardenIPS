"""Base client interface for CLI operations."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseClient(ABC):
    """Abstract base class for CLI clients (Direct or API)."""
    
    @abstractmethod
    async def ban_ip(self, ip: str, duration: int = 0, reason: str = "") -> Dict[str, Any]:
        """Ban an IP address."""
        pass
    
    @abstractmethod
    async def unban_ip(self, ip: str) -> Dict[str, Any]:
        """Unban an IP address."""
        pass
    
    @abstractmethod
    async def list_bans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List active bans."""
        pass
    
    @abstractmethod
    async def add_whitelist(self, ip_or_cidr: str, reason: str = "", tag: str = "") -> Dict[str, Any]:
        """Add IP/CIDR to whitelist."""
        pass
    
    @abstractmethod
    async def remove_whitelist(self, ip_or_cidr: str) -> Dict[str, Any]:
        """Remove IP/CIDR from whitelist."""
        pass
    
    @abstractmethod
    async def list_whitelist(self) -> List[Dict[str, Any]]:
        """List whitelist entries."""
        pass
    
    @abstractmethod
    async def get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status."""
        pass
    
    @abstractmethod
    async def sync_firewall(self, dry_run: bool = False) -> Dict[str, Any]:
        """Reconcile firewall state with database."""
        pass
    
    @abstractmethod
    async def get_config(self, key: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration value(s)."""
        pass
    
    @abstractmethod
    async def set_config(self, key: str, value: Any) -> Dict[str, Any]:
        """Set configuration value."""
        pass
    
    @abstractmethod
    async def reload_config(self, components: Optional[List[str]] = None) -> Dict[str, Any]:
        """Reload configuration (hot-reload)."""
        pass
    
    @abstractmethod
    async def get_plugin_list(self) -> List[Dict[str, Any]]:
        """List all plugins."""
        pass
    
    @abstractmethod
    async def get_plugin_status(self, name: str) -> Dict[str, Any]:
        """Get plugin status."""
        pass
    
    @abstractmethod
    async def reload_plugin(self, name: str) -> Dict[str, Any]:
        """Reload plugin configuration."""
        pass
    
    @abstractmethod
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        pass
    
    @abstractmethod
    async def optimize_database(self) -> Dict[str, Any]:
        """Optimize database (VACUUM + ANALYZE)."""
        pass
    
    @abstractmethod
    async def get_system_status(self) -> Dict[str, Any]:
        """Get full system status report."""
        pass
