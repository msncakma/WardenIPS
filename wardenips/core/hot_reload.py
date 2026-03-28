"""Hot-reload manager for zero-downtime configuration updates."""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from wardenips.core.logger import get_logger


logger = get_logger(__name__)


class HotReloadManager:
    """Manages runtime configuration reloads without restarting the service."""
    
    def __init__(self, config, db, firewall, whitelist=None, plugins=None):
        """
        Initialize hot-reload manager.
        
        Args:
            config: ConfigManager instance
            db: DatabaseManager instance
            firewall: FirewallManager instance
            whitelist: WhitelistManager instance (optional)
            plugins: PluginManager instance (optional)
        """
        self.config = config
        self.db = db
        self.firewall = firewall
        self.whitelist = whitelist
        self.plugins = plugins
        self.last_reload = None
    
    async def reload(self, components: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform hot-reload of specified components.
        
        Args:
            components: List of component names to reload (e.g., ["whitelist", "firewall"])
                       If None, reloads all components
        
        Returns:
            Dict with reload status and results
        """
        reload_start = datetime.utcnow()
        results = {
            "status": "success",
            "timestamp": reload_start.isoformat(),
            "components": components or ["config", "whitelist", "firewall", "plugins"],
            "details": {},
            "errors": [],
        }
        
        if components is None:
            components = ["config", "whitelist", "firewall", "plugins"]
        
        components = [c.lower().strip() for c in components]
        
        try:
            # 1. Reload config first (all other reloads depend on this)
            if "config" in components:
                try:
                    await self._reload_config()
                    results["details"]["config"] = "reloaded"
                    logger.info("Config hot-reloaded successfully")
                except Exception as e:
                    error_msg = f"Failed to reload config: {e}"
                    results["errors"].append(error_msg)
                    logger.error(error_msg)
            
            # 2. Reload whitelist
            if "whitelist" in components and self.whitelist:
                try:
                    await self._reload_whitelist()
                    results["details"]["whitelist"] = "reloaded"
                    logger.info("Whitelist hot-reloaded successfully")
                except Exception as e:
                    error_msg = f"Failed to reload whitelist: {e}"
                    results["errors"].append(error_msg)
                    logger.error(error_msg)
            
            # 3. Reload firewall rules
            if "firewall" in components and self.firewall:
                try:
                    await self._reload_firewall()
                    results["details"]["firewall"] = "reloaded"
                    logger.info("Firewall hot-reloaded successfully")
                except Exception as e:
                    error_msg = f"Failed to reload firewall: {e}"
                    results["errors"].append(error_msg)
                    logger.error(error_msg)
            
            # 4. Reload plugins
            if "plugins" in components and self.plugins:
                try:
                    await self._reload_plugins()
                    results["details"]["plugins"] = "reloaded"
                    logger.info("Plugins hot-reloaded successfully")
                except Exception as e:
                    error_msg = f"Failed to reload plugins: {e}"
                    results["errors"].append(error_msg)
                    logger.error(error_msg)
            
            # 5. Reload notifications
            if "notifications" in components:
                try:
                    await self._reload_notifications()
                    results["details"]["notifications"] = "reloaded"
                    logger.info("Notifications hot-reloaded successfully")
                except Exception as e:
                    error_msg = f"Failed to reload notifications: {e}"
                    results["errors"].append(error_msg)
                    logger.error(error_msg)
            
            # Overall status
            if results["errors"]:
                results["status"] = "partial"  # Some components failed
                logger.warning(f"Hot-reload completed with {len(results['errors'])} errors")
            else:
                results["status"] = "success"
                logger.info("Hot-reload completed successfully")
            
            self.last_reload = reload_start
            return results
        
        except Exception as e:
            logger.error(f"Unexpected error during hot-reload: {e}")
            results["status"] = "failed"
            results["errors"].append(str(e))
            return results
    
    async def _reload_config(self):
        """Reload configuration from config.yaml file."""
        # Re-read config file
        await self.config.reload()
    
    async def _reload_whitelist(self):
        """Reload whitelist from database and config."""
        if self.whitelist is None:
            return
        
        # Reload whitelist from config
        from wardenips.core.whitelist import WhitelistManager
        
        new_whitelist = await WhitelistManager.create(self.config)
        # Update whitelist reference (if possible)
        if hasattr(self.whitelist, "_whitelisted_ips"):
            self.whitelist._whitelisted_ips = new_whitelist._whitelisted_ips
        if hasattr(self.whitelist, "_whitelisted_asns"):
            self.whitelist._whitelisted_asns = new_whitelist._whitelisted_asns
        if hasattr(self.whitelist, "_whitelisted_countries"):
            self.whitelist._whitelisted_countries = new_whitelist._whitelisted_countries
    
    async def _reload_firewall(self):
        """Reload firewall rules."""
        if self.firewall is None:
            return
        
        # Get current bans from database and re-apply to ipset
        # This ensures kernel state matches database
        if hasattr(self.firewall, "reconcile"):
            await self.firewall.reconcile(dry_run=False)
    
    async def _reload_plugins(self):
        """Reload plugin configurations."""
        if self.plugins is None:
            return
        
        # For each running plugin, reload its configuration
        # Plugin managers should support hot-reload of thresholds, log paths, etc.
        if hasattr(self.plugins, "reload_all_configs"):
            await self.plugins.reload_all_configs()
    
    async def _reload_notifications(self):
        """Reload notification backends."""
        # Notification manager should support hot-reload of email/slack/discord configs
        # This is a hook for future implementation
        pass


class HotReloadSignalHandler:
    """Handles SIGHUP signals for hot-reload."""
    
    def __init__(self, hot_reload_manager: HotReloadManager):
        self.manager = hot_reload_manager
        self.logger = get_logger(__name__)
    
    async def on_sighup(self):
        """Called when SIGHUP signal is received."""
        self.logger.info("Received SIGHUP signal, triggering hot-reload...")
        result = await self.manager.reload()
        self.logger.info(f"Hot-reload result: {result['status']}")
    
    def register_signal_handler(self, loop):
        """Register SIGHUP handler with asyncio event loop."""
        import signal
        
        def signal_handler():
            asyncio.create_task(self.on_sighup())
        
        try:
            loop.add_signal_handler(signal.SIGHUP, signal_handler)
            self.logger.info("SIGHUP signal handler registered for hot-reload")
        except NotImplementedError:
            # SIGHUP not supported on Windows
            self.logger.debug("SIGHUP not supported on this platform")
        except Exception as e:
            self.logger.error(f"Failed to register signal handler: {e}")
