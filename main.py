"""
WardenIPS - Autonomous Intrusion Prevention System
==================================================

A high-performance IPS for Linux-based servers that detects botnet
and DDoS attacks entirely autonomously.

Usage:
    sudo python3 main.py
    sudo python3 main.py --config /etc/wardenips/config.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from pathlib import Path

from wardenips.core.config import ConfigManager
from wardenips.core.logger import setup_logging, get_logger
from wardenips.core.whitelist import WhitelistManager
from wardenips.core.asn_lookup import ASNLookupEngine
from wardenips.core.ip_hasher import IPHasher
from wardenips.core.database import DatabaseManager
from wardenips.core.firewall import FirewallManager
from wardenips.core.abuseipdb import AbuseIPDBReporter
from wardenips.core.log_tailer import LogTailer
from wardenips.core.models import ConnectionEvent, ThreatLevel
from wardenips.core.updater import UpdateChecker
from wardenips.plugins.base_plugin import PluginManager
from wardenips.plugins.ssh_plugin import SSHPlugin
from wardenips.plugins.minecraft_plugin import MinecraftPlugin

# Version
__version__ = "0.1.0"


class WardenIPS:
    """
    WardenIPS main application class.

    Initializes all components, loads plugins,
    runners log tailers and manages the analysis loop.
    """

    def __init__(self, config_path: str) -> None:
        self._config_path = Path(config_path)
        self._config: ConfigManager = None
        self._logger = None
        self._whitelist: WhitelistManager = None
        self._asn_engine: ASNLookupEngine = None
        self._hasher: IPHasher = None
        self._db: DatabaseManager = None
        self._firewall: FirewallManager = None
        self._abuse_reporter: AbuseIPDBReporter = None
        self._plugin_manager: PluginManager = None
        self._tailers: list[LogTailer] = []
        self._running = False

    async def start(self) -> None:
        """Starts WardenIPS and loads all components."""

        # ── 1. Configuration ──
        self._config = await ConfigManager.load(self._config_path)

        # ── 2. Logging ──
        log_level = self._config.get("general.log_level", "INFO")
        log_file = self._config.get("general.log_file")
        setup_logging(level=log_level, log_file=log_file)
        self._logger = get_logger("warden")

        self._logger.info("=" * 60)
        self._logger.info("  Starting WardenIPS v%s...", __version__)
        self._logger.info("=" * 60)

        # ── 2.5 System Dependency Checks ──
        await self._check_dependencies()

        # ── 3. Check for Updates ──
        updater = UpdateChecker(current_version=__version__)
        await updater.check_for_updates()

        # ── 4. Core Components ──
        self._whitelist = await WhitelistManager.create(self._config)
        self._logger.info("Whitelist: %s", self._whitelist.stats)

        self._asn_engine = ASNLookupEngine(self._config)
        self._logger.info("ASN Engine: %s", self._asn_engine)

        self._hasher = IPHasher.from_config(self._config)

        self._db = await DatabaseManager.create(self._config)
        self._logger.info("Database: %s", self._db)

        self._firewall = await FirewallManager.create(
            self._config, self._whitelist
        )
        self._logger.info("Firewall: %s", self._firewall)

        self._abuse_reporter = await AbuseIPDBReporter.create(self._config)
        self._logger.info("AbuseIPDB: %s", self._abuse_reporter)

        # ── 5. Load Plugins ──
        self._plugin_manager = PluginManager(self._config)
        self._register_plugins()
        await self._plugin_manager.start_all()

        # ── 6. Start Log Tailers ──
        self._start_tailers()

        self._running = True
        self._logger.info("")
        self._logger.info("=" * 60)
        self._logger.info(
            "  WardenIPS is ACTIVE — monitoring %d plugins",
            len(self._plugin_manager.enabled_plugins),
        )
        self._logger.info("=" * 60)

    def _register_plugins(self) -> None:
        """Registers plugins according to the configuration."""

        # SSH Plugin
        if self._config.get("plugins.ssh.enabled", True):
            ssh_plugin = SSHPlugin(self._config)
            self._plugin_manager.register(ssh_plugin)

        # Minecraft Plugin
        if self._config.get("plugins.minecraft.enabled", True):
            mc_plugin = MinecraftPlugin(self._config)
            self._plugin_manager.register(mc_plugin)

    def _start_tailers(self) -> None:
        """Creates and starts a LogTailer for each active plugin."""

        for plugin in self._plugin_manager.enabled_plugins:
            callback = self._create_event_handler(plugin)
            tailer = LogTailer(
                file_path=plugin.log_file_path,
                line_callback=callback,
                poll_interval=0.5,
                start_from_end=True,
                name=plugin.name,
            )
            tailer.create_task()
            self._tailers.append(tailer)
            self._logger.info(
                "Log tailer started: %s -> %s",
                plugin.name, plugin.log_file_path,
            )

    def _create_event_handler(self, plugin):
        """Creates an event processing callback for a plugin."""

        async def handler(line: str) -> None:
            # 1. Parse line
            event = await plugin.handle_line(line)
            if event is None:
                return

            # 2. Whitelist check
            if await self._whitelist.is_whitelisted(event.source_ip):
                return

            # 3. Hash IP
            ip_hash = self._hasher.hash_ip(event.source_ip)

            # 4. ASN lookup
            asn_result = self._asn_engine.lookup(event.source_ip)

            # 5. Query recent events count
            time_window = self._config.get("general.analysis_interval", 5)
            event_count = await self._db.get_event_count_by_ip(
                ip_hash, minutes=time_window
            )

            # 6. Calculate risk score
            context = {
                "event_count": event_count,
                "is_datacenter": asn_result.is_datacenter,
                "asn_result": asn_result,
            }
            risk_score = await plugin.calculate_risk(event, context)

            # 7. Determine threat level
            if risk_score >= 70:
                threat = ThreatLevel.HIGH
            elif risk_score >= 40:
                threat = ThreatLevel.MEDIUM
            elif risk_score >= 10:
                threat = ThreatLevel.LOW
            else:
                threat = ThreatLevel.NONE

            # 8. Log updated event to database
            updated_event = ConnectionEvent(
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                connection_type=event.connection_type,
                player_name=event.player_name,
                asn_number=asn_result.asn_number,
                asn_org=asn_result.asn_org,
                country_code=asn_result.country_code,
                is_datacenter=asn_result.is_datacenter,
                threat_level=threat,
                risk_score=risk_score,
                raw_log_line=event.raw_log_line,
                details=event.details,
            )
            await self._db.log_event(updated_event, ip_hash)

            # 9. Geofencing check
            if not await self._whitelist.is_country_allowed(
                asn_result.country_code
            ):
                risk_score = max(risk_score, 80)

            # 10. Execute action
            action = plugin.get_action_recommendation(risk_score)

            if action == "BAN":
                ban_threshold = self._config.get("firewall.ban_threshold", 70)
                ban_duration = self._config.get(
                    "firewall.ipset.default_ban_duration", 3600
                )
                reason = (
                    f"[{plugin.name}] Risk={risk_score} "
                    f"ASN={asn_result.asn_number} "
                    f"({event.details.get('event_type', 'unknown')})"
                )

                banned = await self._firewall.ban_ip(
                    event.source_ip,
                    duration=ban_duration,
                    reason=reason,
                )
                if banned:
                    await self._db.log_ban(
                        ip_hash, reason, risk_score, ban_duration
                    )
                    # Report to AbuseIPDB
                    categories = [18] if event.connection_type.value == "ssh" else [14]
                    await self._abuse_reporter.report_ip(
                        ip=event.source_ip,
                        categories=categories,
                        comment=reason,
                    )

                self._logger.warning(
                    "THREAT DETECTED: IP=%s Risk=%d Action=%s "
                    "Plugin=%s Type=%s",
                    event.source_ip, risk_score, action,
                    plugin.name, event.details.get("event_type", "?"),
                )
            elif action == "WATCH":
                self._logger.info(
                    "SUSPICIOUS: IP=%s Risk=%d Plugin=%s",
                    event.source_ip, risk_score, plugin.name,
                )

        return handler

    async def run_forever(self) -> None:
        """Run the main loop — wait until a signal is received."""

        stop_event = asyncio.Event()

        def signal_handler():
            self._logger.info("Shutdown signal received...")
            stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, signal_handler)
            except NotImplementedError:
                # Signal handling might not be supported on Windows
                pass

        try:
            await stop_event.wait()
        except KeyboardInterrupt:
            pass
        finally:
            await self.shutdown()

    async def _check_dependencies(self) -> None:
        """Verifies if required system programs are installed."""
        import shutil
        import sys

        # Basic tools check
        required_tools = []
        if sys.platform != "win32":
            required_tools.extend(["ipset", "iptables"])
            
            # Optional but recommended
            if not shutil.which("rsyslogd") and not shutil.which("journalctl"):
                self._logger.warning(
                    "System check: Neither 'rsyslog' nor 'journalctl' was found. "
                    "Log tailing might not work correctly if logs are not written."
                )

        missing = []
        for tool in required_tools:
            if not shutil.which(tool):
                missing.append(tool)
        
        if missing:
            self._logger.warning(
                "System check: Missing required tools: %s. "
                "WardenIPS might not function correctly or will run in simulation mode.",
                ", ".join(missing)
            )
        else:
            self._logger.debug("System check: All required dependencies are installed.")

    async def shutdown(self) -> None:
        """Safely shutdown all components."""

        self._logger.info("Shutting down WardenIPS...")
        self._running = False

        # Stop tailers
        for tailer in self._tailers:
            await tailer.stop()

        # Stop plugins
        if self._plugin_manager:
            await self._plugin_manager.stop_all()

        # Close services
        if self._abuse_reporter:
            await self._abuse_reporter.close()
        if self._firewall:
            await self._firewall.shutdown()
        if self._db:
            await self._db.close()
        if self._asn_engine:
            self._asn_engine.close()

        self._logger.info("=" * 60)
        self._logger.info("  WardenIPS shut down safely.")
        self._logger.info("=" * 60)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="WardenIPS - Autonomous Intrusion Prevention System",
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Configuration file path (default: config.yaml)",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"WardenIPS v{__version__}",
    )
    return parser.parse_args()


async def main() -> None:
    """Main entry point."""
    args = parse_args()

    warden = WardenIPS(config_path=args.config)
    await warden.start()
    await warden.run_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Suppress the KeyboardInterrupt traceback for a clean console output
        pass
