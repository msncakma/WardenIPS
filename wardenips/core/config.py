"""
WardenIPS - Async Configuration Manager (ConfigManager)
======================================================

Asynchronously reads and validates the config.yaml file,
providing a single configuration object globally (Singleton).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles
import yaml

from wardenips.core.exceptions import WardenConfigError
from wardenips.core.logger import get_logger

logger = get_logger(__name__)


# Required top-level configuration keys
_REQUIRED_SECTIONS = ("general", "whitelist")


class ConfigManager:
    """
    Async YAML configuration manager.

    Uses the Singleton pattern — only one instance exists application-wide.
    Reads the config.yaml file asynchronously and provides dot-notation
    access to configuration values.

    Usage:
        config = await ConfigManager.load("config.yaml")
        log_level = config.get("general.log_level", "INFO")
    """

    _instance: Optional[ConfigManager] = None
    _lock: asyncio.Lock = asyncio.Lock()

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}
        self._config_path: Optional[Path] = None

    # ── Singleton Factory ──

    @classmethod
    async def load(cls, config_path: str | Path) -> ConfigManager:
        """
        Loads the configuration file and returns the ConfigManager instance.

        Reads and validates the file on the first call. Subsequent calls
        return the existing instance (Singleton).

        Args:
            config_path: Path to the config.yaml file.

        Returns:
            Configured ConfigManager instance.

        Raises:
            WardenConfigError: If the file is not found or is invalid.
        """
        async with cls._lock:
            if cls._instance is not None:
                logger.debug("ConfigManager is already loaded, returning existing instance.")
                return cls._instance

            instance = cls()
            await instance._read_config(Path(config_path))
            instance._validate()
            cls._instance = instance
            logger.info("Configuration successfully loaded: %s", config_path)
            return cls._instance

    @classmethod
    async def reload(cls) -> ConfigManager:
        """
        Re-reads the configuration file (hot-reload).

        Returns:
            Updated ConfigManager instance.

        Raises:
            WardenConfigError: If the instance hasn't been created yet.
        """
        async with cls._lock:
            if cls._instance is None or cls._instance._config_path is None:
                raise WardenConfigError(
                    "ConfigManager has not been initialized. Call load() first."
                )
            await cls._instance._read_config(cls._instance._config_path)
            cls._instance._validate()
            logger.info("Configuration reloaded successfully.")
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Resets the Singleton instance (for testing purposes)."""
        cls._instance = None

    # ── Configuration Access ──

    def get(self, key: str, default: Any = None) -> Any:
        """
        Accesses a nested configuration value using a dot-separated key.

        Example:
            config.get("whitelist.ips")           -> ["127.0.0.1", "::1"]
            config.get("general.log_level", "INFO") -> "INFO"

        Args:
            key:     Dot-separated configuration key.
            default: Value to return if the key is not found.

        Returns:
            Configuration value or default.
        """
        keys = key.split(".")
        value: Any = self._data

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default

        return value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Returns an entire configuration section.

        Args:
            section: Top-level section name (e.g., "whitelist", "firewall").

        Returns:
            Section dictionary. Returns an empty dict if not found.
        """
        return self._data.get(section, {})

    @property
    def raw(self) -> Dict[str, Any]:
        """Dictionary of raw configuration data."""
        return self._data.copy()

    @property
    def config_path(self) -> Optional[Path]:
        """Path of the loaded configuration file."""
        return self._config_path

    async def save(self, data: Dict[str, Any]) -> None:
        """Validate and persist configuration data."""
        if not isinstance(data, dict):
            raise WardenConfigError("Configuration payload must be a dictionary.")
        if self._config_path is None:
            raise WardenConfigError("Configuration path is not initialized.")

        async with self._lock:
            previous = self._data
            self._data = data
            temp_path = None
            try:
                self._validate()
                serialized = yaml.safe_dump(
                    data,
                    sort_keys=False,
                    allow_unicode=True,
                )
                temp_path = self._config_path.with_suffix(self._config_path.suffix + ".tmp")
                async with aiofiles.open(
                    str(temp_path),
                    mode="w",
                    encoding="utf-8",
                ) as config_file:
                    await config_file.write(serialized)
                os.replace(temp_path, self._config_path)
            except OSError as exc:
                self._data = previous
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                raise WardenConfigError(
                    f"Configuration file could not be written: {self._config_path} — {exc}"
                ) from exc
            except Exception:
                self._data = previous
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                raise
            logger.info("Configuration saved successfully: %s", self._config_path)

    # ── Internal Methods ──

    async def _read_config(self, path: Path) -> None:
        """
        Asynchronously reads and parses the YAML file.

        Args:
            path: Path to config.yaml.

        Raises:
            WardenConfigError: If the file is not found or YAML is invalid.
        """
        if not path.exists():
            raise WardenConfigError(
                f"Configuration file not found: {path}"
            )

        try:
            async with aiofiles.open(str(path), mode="r", encoding="utf-8") as f:
                content = await f.read()
        except OSError as exc:
            raise WardenConfigError(
                f"Configuration file could not be read: {path} — {exc}"
            ) from exc

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise WardenConfigError(
                f"YAML parsing error: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise WardenConfigError(
                "Configuration file is not a valid YAML dictionary."
            )

        self._data = data
        self._config_path = path

    def _validate(self) -> None:
        """
        Validates required configuration fields.

        Raises:
            WardenConfigError: If a required field is missing.
        """
        for section in _REQUIRED_SECTIONS:
            if section not in self._data:
                raise WardenConfigError(
                    f"Required configuration section missing: '{section}'"
                )

        # Ensure either 'ips' or 'cidr_ranges' list exists in the whitelist section
        whitelist = self._data.get("whitelist", {})
        if whitelist.get("enabled", True):
            ips = whitelist.get("ips", [])
            cidr = whitelist.get("cidr_ranges", [])
            if not ips and not cidr:
                logger.warning(
                    "Whitelist is active but no IP or CIDR is defined! "
                    "Admin access might be at risk."
                )

        logger.debug("Configuration validation successful.")

    def __repr__(self) -> str:
        return (
            f"<ConfigManager path={self._config_path} "
            f"sections={list(self._data.keys())}>"
        )
