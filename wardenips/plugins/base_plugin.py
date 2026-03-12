"""
WardenIPS - BasePlugin Abstract Class
======================================

Tum WardenIPS pluginleri bu soyut siniftan turetilir.
SSH, Minecraft, Nginx vb. her servis icin ayri bir plugin yazilir.

Plugin sorumluluklari:
    1. Log satirini regex ile ayristirmak (parse)
    2. ConnectionEvent olusturmak
    3. Calculate risk scoremak
    4. Aksiyon onermek (ban, rapor, vb.)

Yeni plugin ekleme:
    1. BasePlugin'den turet
    2. parse_line() metodunu implement et
    3. config.yaml'a plugin bolumu ekle
    4. PluginManager'a kaydet
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, List, Optional

from wardenips.core.logger import get_logger
from wardenips.core.models import ConnectionEvent

if TYPE_CHECKING:
    from wardenips.core.config import ConfigManager

logger = get_logger(__name__)


class BasePlugin(abc.ABC):
    """
    WardenIPS plugin abstract base class.

    All plugins must inherit from this class and implement
    abstract methods.

    Example:
        class SSHPlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "SSH"

            @property
            def log_file_path(self) -> str:
                return self._config.get("plugins.ssh.log_path", "/var/log/auth.log")

            async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
                # parse the log line

            async def calculate_risk(self, event, context) -> int:
                # calculate the risk score
                ...
    """

    def __init__(self, config: ConfigManager) -> None:
        """
        Initialize the plugin.

        Args:
            config: ConfigManager instance.
        """
        self._config = config
        self._enabled: bool = True
        self._lines_processed: int = 0
        self._events_generated: int = 0
        self._logger = get_logger(f"plugin.{self.name.lower()}")

    # ══════════════════════════════════════════════════════════
    #  ABSTRACT METHODS (All plugins MUST implement these)
    # ══════════════════════════════════════════════════════════

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Plugin name (must be unique).

        Returns:
            Plugin name string (e.g., "SSH", "Minecraft", "Nginx").
        """
        ...

    @property
    @abc.abstractmethod
    def log_file_path(self) -> str:
        """
        Path to the log file to be monitored.

        Returns:
            Full path to the log file.
        """
        ...

    @abc.abstractmethod
    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        """
        Parse a log line and create a ConnectionEvent.

        This method is called for each new log line.
        If the line is not related to the plugin, return None.

        Args:
            line: Raw log line.

        Returns:
            ConnectionEvent object or None (irrelevant line).
        """
        ...

    @abc.abstractmethod
    async def calculate_risk(
        self,
        event: ConnectionEvent,
        context: dict,
    ) -> int:
        """
        Calculate the risk score for a connection event (0-100).

        Context, past events and ASN info etc.
        is a dictionary containing additional analysis data.

        Args:
            event:   Ayristirilmis ConnectionEvent.
            context: Ek analiz verileri:
                     - "recent_events": Recent events N minutes
                     - "event_count": Event count
                     - "asn_result": ASN lookup result
                     - "is_suspicious_asn": Is IP's ASN on suspicious list?

        Returns:
            0-100 arasi risk skoru.
        """
        ...

    # ══════════════════════════════════════════════════════════
    #  OPSIYONEL METODLAR (Override edilebilir)
    # ══════════════════════════════════════════════════════════

    async def on_start(self) -> None:
        """
        Plugin started.
        Override to perform custom startup actions.
        """
        self._logger.info("Plugin started: %s", self.name)
        self._logger.info("If you encounter any issues, please open an Issue on GitHub!")
        self._logger.info("Support the project: https://ko-fi.com/msncakma")

    async def on_stop(self) -> None:
        """
        Plugin stopped.
        Override to perform custom cleanup actions.
        """
        self._logger.info(
            "Plugin stopped: %s — Processed: %d events",
            self.name, self._events_generated,
        )
        self._logger.info("If you enjoyed WardenIPS, buy me a coffee! https://ko-fi.com/msncakma")

    async def on_event(self, event: ConnectionEvent) -> None:
        """
        Successful parse after events processing hook.
        Override to perform custom actions (e.g., metric aggregation).

        Args:
            event: Generated ConnectionEvent.
        """
        pass

    def get_action_recommendation(self, risk_score: int) -> str:
        """
        Returns action recommendation based on risk score.

        Args:
            risk_score: Calculated risk score (0-100).

        Returns:
            Action recommendation string.
        """
        ban_threshold = self._config.get("firewall.ban_threshold", 70)

        if risk_score >= ban_threshold:
            return "BAN"
        elif risk_score >= 40:
            return "WATCH"
        elif risk_score >= 10:
            return "LOG"
        else:
            return "IGNORE"

    # ══════════════════════════════════════════════════════════
    #  LOG TAILER CALLBACK (Otomatik olarak baglanir)
    # ══════════════════════════════════════════════════════════

    async def handle_line(self, line: str) -> Optional[ConnectionEvent]:
        """
        LogTailer calls this callback for each new line.

        This method:
        1. Parses the line using parse_line()
        2. Calls on_event() hook if parsing is successful
        3. Updates statistics

        Args:
            line: Raw log line.

        Returns:
            ConnectionEvent or None.
        """
        self._lines_processed += 1

        try:
            event = await self.parse_line(line)
            if event is not None:
                self._events_generated += 1
                await self.on_event(event)
                return event
        except Exception as exc:
            self._logger.error(
                "Line parsing error: %s — %s",
                exc, line[:100],
            )

        return None

    # ══════════════════════════════════════════════════════════
    #  INFO
    # ══════════════════════════════════════════════════════════

    @property
    def is_enabled(self) -> bool:
        """Plugin enabled?"""
        return self._enabled

    @is_enabled.setter
    def is_enabled(self, value: bool) -> None:
        self._enabled = value

    @property
    def stats(self) -> dict:
        """Plugin statistics."""
        return {
            "name": self.name,
            "enabled": self._enabled,
            "log_file": self.log_file_path,
            "lines_processed": self._lines_processed,
            "events_generated": self._events_generated,
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"name='{self.name}' "
            f"enabled={self._enabled} "
            f"lines={self._lines_processed} "
            f"events={self._events_generated}>"
        )


class PluginManager:
    """
    Plugin manager.

    Loads, starts, stops and lists plugins.
    Automatically links plugins with LogTailer.

    Usage:
        manager = PluginManager(config)
        manager.register(SSHPlugin(config))
        manager.register(MinecraftPlugin(config))
        await manager.start_all()
        # ...
        await manager.stop_all()
    """

    def __init__(self, config: ConfigManager) -> None:
        self._config = config
        self._plugins: dict[str, BasePlugin] = {}
        self._logger = get_logger("plugin_manager")

    def register(self, plugin: BasePlugin) -> None:
        """
        Register a plugin.

        Args:
            plugin: BasePlugin'den turetilmis plugin instance.

        Raises:
            ValueError: Plugin already registered.
        """
        if plugin.name in self._plugins:
            raise ValueError(
                f"Plugin already registered: '{plugin.name}'"
            )

        self._plugins[plugin.name] = plugin
        self._logger.info(
            "Plugin registered: %s (log: %s)",
            plugin.name, plugin.log_file_path,
        )

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get plugin by name."""
        return self._plugins.get(name)

    @property
    def plugins(self) -> List[BasePlugin]:
        """List of all registered plugins."""
        return list(self._plugins.values())

    @property
    def enabled_plugins(self) -> List[BasePlugin]:
        """List of enabled plugins."""
        return [p for p in self._plugins.values() if p.is_enabled]

    async def start_all(self) -> None:
        """Start all enabled plugins."""
        for plugin in self.enabled_plugins:
            try:
                await plugin.on_start()
            except Exception as exc:
                self._logger.error(
                    "Plugin start error (%s): %s",
                    plugin.name, exc,
                )

    async def stop_all(self) -> None:
        """Stop all plugins."""
        for plugin in self._plugins.values():
            try:
                await plugin.on_stop()
            except Exception as exc:
                self._logger.error(
                    "Plugin stop error (%s): %s",
                    plugin.name, exc,
                )

    @property
    def stats(self) -> dict:
        """Plugin statistics."""
        return {
            "total_plugins": len(self._plugins),
            "enabled_plugins": len(self.enabled_plugins),
            "plugins": {
                name: p.stats for name, p in self._plugins.items()
            },
        }

    def __repr__(self) -> str:
        return (
            f"<PluginManager "
            f"plugins={len(self._plugins)} "
            f"enabled={len(self.enabled_plugins)}>"
        )
