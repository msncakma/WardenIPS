"""Direct client for local database and firewall access."""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseClient
from .exceptions import DirectClientError


class DirectClient(BaseClient):
    """Client that accesses local database and firewall directly (requires root)."""
    
    def __init__(self, config_path: str = "config.yaml", verbose: bool = False):
        self.config_path = Path(config_path)
        self.verbose = verbose
        self._db = None
        self._firewall = None
        self._config = None
        self._plugin_manager = None
    
    async def _init_components(self):
        """Lazily initialize database and firewall managers."""
        if self._db is None:
            try:
                # Import here to avoid circular imports at module load time
                from wardenips.core.config import ConfigManager
                from wardenips.core.database import DatabaseManager
                from wardenips.core.firewall import FirewallManager
                
                self._config = await ConfigManager.load(self.config_path)
                self._db = await DatabaseManager.create(self._config)
                self._firewall = await FirewallManager.create(self._config, whitelist=None)
            except Exception as e:
                raise DirectClientError(f"Failed to initialize components: {e}")
    
    async def close(self):
        """Close database connections."""
        if self._db:
            await self._db.close()

    async def _init_plugins(self):
        """Lazily initialize plugin manager for plugin-related commands."""
        await self._init_components()
        if self._plugin_manager is not None:
            return

        try:
            from wardenips.plugins.base_plugin import PluginManager
            from wardenips.plugins.authme_plugin import AuthMePlugin
            from wardenips.plugins.minecraft_plugin import MinecraftPlugin
            from wardenips.plugins.nginx_plugin import NginxPlugin
            from wardenips.plugins.portscan_plugin import PortscanPlugin
            from wardenips.plugins.ssh_plugin import SSHPlugin
            from wardenips.plugins.velocity_plugin import VelocityPlugin

            manager = PluginManager(self._config)

            if self._config.get("plugins.ssh.enabled", True):
                manager.register(SSHPlugin(self._config))

            if self._config.get("plugins.minecraft.enabled", True):
                manager.register(MinecraftPlugin(self._config))

            if self._config.get("plugins.authme.enabled", True):
                manager.register(AuthMePlugin(self._config))

            if self._config.get("plugins.minecraft.velocity.enabled", False):
                manager.register(VelocityPlugin(self._config))

            if self._config.get("plugins.nginx.enabled", False):
                manager.register(NginxPlugin(self._config))

            if self._config.get("plugins.portscan.enabled", True):
                manager.register(PortscanPlugin(self._config))

            self._plugin_manager = manager
        except Exception as e:
            raise DirectClientError(f"Failed to initialize plugins: {e}")
    
    async def ban_ip(self, ip: str, duration: int = 0, reason: str = "") -> Dict[str, Any]:
        """Ban an IP address."""
        await self._init_components()
        try:
            # Add to firewall
            await self._firewall.apply_ban(ip, duration=duration)
            # Record in database
            await self._db.record_ban(
                source_ip=ip,
                reason=reason or "CLI manual ban",
                duration_seconds=duration,
            )
            return {
                "status": "ok",
                "ip": ip,
                "duration": duration,
                "reason": reason,
            }
        except Exception as e:
            raise DirectClientError(f"Failed to ban IP {ip}: {e}")
    
    async def unban_ip(self, ip: str) -> Dict[str, Any]:
        """Unban an IP address."""
        await self._init_components()
        try:
            await self._firewall.remove_ban(ip)
            await self._db.record_unban(ip)
            return {
                "status": "ok",
                "ip": ip,
            }
        except Exception as e:
            raise DirectClientError(f"Failed to unban IP {ip}: {e}")
    
    async def list_bans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List active bans."""
        await self._init_components()
        try:
            bans = await self._db.get_active_bans(limit=limit)
            return [
                {
                    "ip": ban["source_ip"],
                    "reason": ban.get("reason"),
                    "banned_at": ban.get("banned_at"),
                    "duration": ban.get("duration_seconds"),
                }
                for ban in bans
            ]
        except Exception as e:
            raise DirectClientError(f"Failed to list bans: {e}")
    
    async def add_whitelist(self, ip_or_cidr: str, reason: str = "", tag: str = "") -> Dict[str, Any]:
        """Add IP/CIDR to whitelist."""
        await self._init_components()
        try:
            from wardenips.core.whitelist import WhitelistManager
            
            whitelist = await WhitelistManager.create(self._config)
            await whitelist.add_runtime_ips({ip_or_cidr})
            
            return {
                "status": "ok",
                "ip": ip_or_cidr,
                "reason": reason,
                "tag": tag,
            }
        except Exception as e:
            raise DirectClientError(f"Failed to add whitelist entry: {e}")
    
    async def remove_whitelist(self, ip_or_cidr: str) -> Dict[str, Any]:
        """Remove IP/CIDR from whitelist."""
        await self._init_components()
        try:
            from wardenips.core.whitelist import WhitelistManager
            
            whitelist = await WhitelistManager.create(self._config)
            removed = await whitelist.remove_runtime_ips([ip_or_cidr])
            
            return {
                "status": "ok",
                "ip": ip_or_cidr,
                "removed": removed > 0,
            }
        except Exception as e:
            raise DirectClientError(f"Failed to remove whitelist entry: {e}")
    
    async def list_whitelist(self) -> List[Dict[str, Any]]:
        """List whitelist entries."""
        await self._init_components()
        try:
            from wardenips.core.whitelist import WhitelistManager
            
            whitelist = await WhitelistManager.create(self._config)
            return [
                {
                    "ip": entry,
                    "type": "whitelist",
                }
                for entry in whitelist._whitelisted_ips
            ]
        except Exception as e:
            raise DirectClientError(f"Failed to list whitelist: {e}")
    
    async def get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status."""
        await self._init_components()
        try:
            status = await self._firewall.get_status()
            return status
        except Exception as e:
            raise DirectClientError(f"Failed to get firewall status: {e}")
    
    async def sync_firewall(self, dry_run: bool = False) -> Dict[str, Any]:
        """Reconcile firewall state with database."""
        await self._init_components()
        try:
            result = await self._firewall.reconcile(dry_run=dry_run)
            return result
        except Exception as e:
            raise DirectClientError(f"Failed to sync firewall: {e}")
    
    async def get_config(self, key: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration value(s)."""
        await self._init_components()
        try:
            if key:
                value = self._config.get(key)
                return {"key": key, "value": value}
            else:
                # Return all config (this is large, consider masking secrets)
                return self._config._data
        except Exception as e:
            raise DirectClientError(f"Failed to get config: {e}")
    
    async def set_config(self, key: str, value: Any) -> Dict[str, Any]:
        """Set configuration value."""
        await self._init_components()
        try:
            self._config.set(key, value)
            await self._config.save()
            return {"status": "ok", "key": key, "value": value}
        except Exception as e:
            raise DirectClientError(f"Failed to set config: {e}")
    
    async def reload_config(self, components: Optional[List[str]] = None) -> Dict[str, Any]:
        """Reload configuration (hot-reload)."""
        await self._init_components()
        try:
            from wardenips.core.hot_reload import HotReloadManager
            
            reloader = HotReloadManager(
                config=self._config,
                db=self._db,
                firewall=self._firewall,
            )
            result = await reloader.reload(components=components)
            return result
        except Exception as e:
            raise DirectClientError(f"Failed to reload config: {e}")
    
    async def get_plugin_list(self) -> List[Dict[str, Any]]:
        """List all plugins."""
        await self._init_plugins()
        try:
            plugins = []
            for plugin in self._plugin_manager.plugins:
                plugins.append(
                    {
                        "name": getattr(plugin, "name", "unknown"),
                        "enabled": bool(getattr(plugin, "is_enabled", False)),
                        "log_file": getattr(plugin, "log_file_path", ""),
                        "stats": getattr(plugin, "stats", {}) or {},
                    }
                )
            return plugins
        except Exception as e:
            raise DirectClientError(f"Failed to list plugins: {e}")
    
    async def get_plugin_status(self, name: str) -> Dict[str, Any]:
        """Get plugin status."""
        await self._init_plugins()
        try:
            plugin = self._plugin_manager.get_plugin(name)
            if not plugin:
                return {"name": name, "status": "not_found"}

            return {
                "name": getattr(plugin, "name", name),
                "enabled": bool(getattr(plugin, "is_enabled", False)),
                "log_file": getattr(plugin, "log_file_path", ""),
                "stats": getattr(plugin, "stats", {}) or {},
            }
        except Exception as e:
            raise DirectClientError(f"Failed to get plugin status: {e}")
    
    async def reload_plugin(self, name: str) -> Dict[str, Any]:
        """Reload plugin configuration."""
        await self._init_plugins()
        try:
            plugin = self._plugin_manager.get_plugin(name)
            if not plugin:
                return {"status": "error", "plugin": name, "error": "plugin not found"}

            if hasattr(plugin, "on_stop"):
                await plugin.on_stop()
            if hasattr(plugin, "on_start"):
                await plugin.on_start()

            return {"status": "ok", "plugin": name}
        except Exception as e:
            raise DirectClientError(f"Failed to reload plugin: {e}")
    
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        await self._init_components()
        try:
            stats = await self._db.get_stats()
            return stats
        except Exception as e:
            raise DirectClientError(f"Failed to get database stats: {e}")
    
    async def optimize_database(self) -> Dict[str, Any]:
        """Optimize database (VACUUM + ANALYZE)."""
        await self._init_components()
        try:
            await self._db.optimize()
            return {"status": "ok", "message": "Database optimized"}
        except Exception as e:
            raise DirectClientError(f"Failed to optimize database: {e}")
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get full system status report."""
        await self._init_components()
        try:
            stats = await self._db.get_stats()
            fw_status = await self._firewall.get_status()
            return {
                "database": stats,
                "firewall": fw_status,
            }
        except Exception as e:
            raise DirectClientError(f"Failed to get system status: {e}")
