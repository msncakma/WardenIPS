"""Configuration service - config CRUD, hot-reload, validation."""

from datetime import datetime, timezone
from typing import Dict, Tuple, Optional, List


class ConfigService:
    """Configuration management service with hot-reload support."""
    
    def __init__(self, config_manager, hot_reload_manager=None):
        """Initialize config service.
        
        Args:
            config_manager: Config manager instance
            hot_reload_manager: Optional hot-reload manager for reloads
        """
        self.config_manager = config_manager
        self.hot_reload_manager = hot_reload_manager
    
    async def get_config(self, key: Optional[str] = None) -> Dict:
        """Get current configuration.
        
        Args:
            key: Specific config key to retrieve (optional)
        
        Returns:
            Config dict (or specific value)
        """
        try:
            if key:
                return {key: self.config_manager.config.get(key)}
            
            # Return full config with secrets masked
            config = self.config_manager.config.copy()
            
            # Mask sensitive fields
            if "api_key" in config:
                config["api_key"] = "***redacted***"
            if "totp_secret" in config:
                config["totp_secret"] = "***redacted***"
            
            return config
        
        except Exception as e:
            raise Exception(f"Failed to get config: {str(e)}")
    
    async def patch_config(self, updates: Dict) -> Dict:
        """Update configuration and save to disk.
        
        Args:
            updates: Dict of config keys to update
        
        Returns:
            Dict of applied changes
        """
        try:
            # Validate before applying
            is_valid, errors = await self.validate_config_partial(updates)
            if not is_valid:
                raise Exception(f"Validation failed: {errors}")
            
            # Apply changes
            applied = {}
            for key, value in updates.items():
                old_value = self.config_manager.config.get(key)
                self.config_manager.config[key] = value
                applied[key] = {
                    "old_value": old_value,
                    "new_value": value,
                }
            
            # Save to disk
            await self.config_manager.save()
            
            return applied
        
        except Exception as e:
            raise Exception(f"Failed to patch config: {str(e)}")
    
    async def reload_config(self, components: Optional[List[str]] = None) -> Dict:
        """Reload configuration without restart (hot-reload).
        
        Args:
            components: List of components to reload
                       (config, whitelist, firewall, plugins, notifications)
        
        Returns:
            Reload result dict
        """
        try:
            if not self.hot_reload_manager:
                return {
                    "status": "error",
                    "error": "Hot-reload manager not available",
                }
            
            result = await self.hot_reload_manager.reload(components=components)
            
            return result
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def validate_config(self, config_data: Dict) -> Tuple[bool, List[str]]:
        """Validate configuration against schema.
        
        Args:
            config_data: Config dict to validate
        
        Returns:
            Tuple[is_valid, list_of_errors]
        """
        try:
            errors = []
            
            # Validation rules
            if "port" in config_data:
                if not isinstance(config_data["port"], int) or not (1 <= config_data["port"] <= 65535):
                    errors.append("port must be integer between 1-65535")
            
            if "log_level" in config_data:
                if config_data["log_level"] not in ["DEBUG", "INFO", "WARNING", "ERROR"]:
                    errors.append("log_level must be DEBUG, INFO, WARNING, or ERROR")
            
            if "retention_days" in config_data:
                if not isinstance(config_data["retention_days"], int) or config_data["retention_days"] < 1:
                    errors.append("retention_days must be positive integer")
            
            if "max_bans" in config_data:
                if not isinstance(config_data["max_bans"], int) or config_data["max_bans"] < 1:
                    errors.append("max_bans must be positive integer")
            
            return len(errors) == 0, errors
        
        except Exception as e:
            return False, [str(e)]
    
    async def validate_config_partial(self, updates: Dict) -> Tuple[bool, List[str]]:
        """Validate partial config update.
        
        Args:
            updates: Partial config update dict
        
        Returns:
            Tuple[is_valid, list_of_errors]
        """
        # Merge with current config for full validation
        full_config = self.config_manager.config.copy()
        full_config.update(updates)
        
        return await self.validate_config(full_config)
