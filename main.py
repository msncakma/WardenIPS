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
import time
from collections import defaultdict
from pathlib import Path

from wardenips import __author__, __version__
from wardenips.core.config import ConfigManager
from wardenips.core.logger import setup_logging, get_logger
from wardenips.core.whitelist import WhitelistManager
from wardenips.core.asn_lookup import ASNLookupEngine
from wardenips.core.database import DatabaseManager
from wardenips.core.firewall import FirewallManager
from wardenips.core.abuseipdb import AbuseIPDBReporter
from wardenips.core.notifications import NotificationManager
from wardenips.core.blocklist import BlocklistManager
from wardenips.core.log_tailer import LogTailer
from wardenips.core.models import ConnectionEvent, ThreatLevel
from wardenips.core.updater import UpdateChecker
from wardenips.api.dashboard import DashboardAPI
from wardenips.plugins.base_plugin import PluginManager
from wardenips.plugins.ssh_plugin import SSHPlugin
from wardenips.plugins.minecraft_plugin import MinecraftPlugin
from wardenips.plugins.nginx_plugin import NginxPlugin


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
        self._asn_update_task: asyncio.Task = None
        self._db: DatabaseManager = None
        self._firewall: FirewallManager = None
        self._abuse_reporter: AbuseIPDBReporter = None
        self._notifier: NotificationManager = None
        self._dashboard: DashboardAPI = None
        self._blocklist: BlocklistManager = None
        self._plugin_manager: PluginManager = None
        self._tailers: list[LogTailer] = []
        self._running = False
        # In-memory burst tracker: ip -> list of timestamps (monotonic).
        # When an IP generates more events than _burst_threshold within
        # _burst_window seconds it is immediately banned without waiting
        # for the normal risk-score escalation.
        self._burst_tracker: dict[str, list[float]] = defaultdict(list)
        self._burst_window: int = 10    # seconds
        self._burst_threshold: int = 15  # events in window
        # Runtime counters for periodic summary
        self._stats_total_events: int = 0
        self._stats_total_bans: int = 0
        self._start_time: float = 0.0

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
        self._logger.info("  Maintainer: %s", __author__)
        self._logger.info("=" * 60)

        # ── 2.1 System Info Logging ──
        self._log_system_info()

        # ── 2.5 System Dependency Checks ──
        await self._check_dependencies()

        # ── 3. Check for Updates ──
        updater = UpdateChecker(current_version=__version__)
        await updater.check_for_updates()

        # ── 4. Core Components ──
        self._whitelist = await WhitelistManager.create(self._config)
        self._logger.info("Whitelist: %s", self._whitelist.stats)

        # ── 4.1 ASN Protection (GitHub'dan otomatik indirme) ──
        self._asn_engine = ASNLookupEngine(self._config)
        # GeoLite2-ASN.mmdb yoksa GitHub'dan indir
        asn_ready = await self._asn_engine.ensure_asn_database(self._config)
        if asn_ready and self._asn_engine._asn_reader is None:
            # Dosya indirildi, reload et
            self._asn_engine._load(self._config)
        self._logger.info("ASN Engine: %s", self._asn_engine)
        
        # ── 4.2 ASN Weekly Scheduler (GitHub'dan haftalık güncelleme) ──
        asn_auto_update = self._config.get("asn_protection.auto_update_enabled", True)
        if asn_auto_update:
            self._asn_update_task = self._asn_engine.start_weekly_scheduler(self._config)
            self._logger.info("ASN weekly updater scheduled (every Thursday 03:00 UTC)")

        # Select database backend (sqlite or redis)
        db_backend = self._config.get("database.backend", "sqlite")
        if db_backend == "redis":
            from wardenips.core.redis_backend import RedisDatabaseManager
            self._db = await RedisDatabaseManager.create(self._config)
        else:
            self._db = await DatabaseManager.create(self._config)
        self._logger.info("Database: %s", self._db)

        self._firewall = await FirewallManager.create(
            self._config, self._whitelist
        )
        self._logger.info("Firewall: %s", self._firewall)

        self._abuse_reporter = await AbuseIPDBReporter.create(self._config)
        self._logger.info("AbuseIPDB: %s", self._abuse_reporter)

        self._notifier = await NotificationManager.create(self._config)
        self._logger.info("Notifications: %s", self._notifier)

        # ── 5. Load Plugins ──
        self._plugin_manager = PluginManager(self._config)
        self._register_plugins()
        await self._plugin_manager.start_all()

        # ── 6. Start Log Tailers ──
        self._start_tailers()

        self._running = True
        self._start_time = time.monotonic()

        # ── 7. Blocklist Manager (optional) ──
        self._blocklist = await BlocklistManager.create(
            self._config, self._firewall,
        )
        if self._blocklist.enabled:
            await self._blocklist.start()
            self._logger.info("Blocklist: %s", self._blocklist)

        # ── 8. Dashboard API (optional) ──
        self._dashboard = DashboardAPI(
            self._config,
            self._db,
            self._firewall,
            self._start_time,
            notifier=self._notifier,
            blocklist=self._blocklist,
        )
        if self._dashboard.enabled:
            await self._dashboard.start()

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

        # Nginx Plugin
        if self._config.get("plugins.nginx.enabled", False):
            nginx_plugin = NginxPlugin(self._config)
            self._plugin_manager.register(nginx_plugin)

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

            self._stats_total_events += 1

            # 2. Whitelist check
            if await self._whitelist.is_whitelisted(event.source_ip):
                return

            # ── 2.5 Burst / flood detection ──
            # If the same IP fires more than _burst_threshold events in
            # _burst_window seconds, ban immediately without waiting for
            # the normal risk-score ramp-up.  This catches high-speed
            # brute-force / botnet floods that would slip through the
            # per-event scoring before enough events accumulate.
            now_mono = time.monotonic()
            ts_list = self._burst_tracker[event.source_ip]
            ts_list.append(now_mono)
            # Prune old timestamps outside the window
            cutoff = now_mono - self._burst_window
            self._burst_tracker[event.source_ip] = ts_list = [
                t for t in ts_list if t > cutoff
            ]
            if len(ts_list) >= self._burst_threshold:
                source_ip = event.source_ip
                ban_duration = self._config.get(
                    "firewall.ipset.default_ban_duration", 3600
                )
                reason = (
                    f"[{plugin.name}] BURST FLOOD — "
                    f"{len(ts_list)} events in {self._burst_window}s"
                )
                banned = await self._firewall.ban_ip(
                    event.source_ip, duration=ban_duration, reason=reason,
                )
                if banned:
                    self._stats_total_bans += 1
                    await self._db.log_ban(
                        source_ip, reason, 100, ban_duration
                    )
                    self._logger.warning(
                        "BURST DETECTED: IP=%s Events=%d/%ds — AUTO-BANNED "
                        "Plugin=%s",
                        event.source_ip, len(ts_list),
                        self._burst_window, plugin.name,
                    )
                    await self._notifier.notify_burst(
                        ip=event.source_ip,
                        event_count=len(ts_list),
                        window=self._burst_window,
                        plugin=plugin.name,
                    )
                    # Clear tracker for this IP so we don't keep re-banning
                    self._burst_tracker.pop(event.source_ip, None)
                return  # Skip normal scoring — already handled

            # 3. Use source IP directly (no anonymization layer)
            source_ip = event.source_ip

            success_logging_enabled = bool(
                self._config.get("successful_logins.enabled", True)
            )
            reset_risk_on_success = bool(
                self._config.get("successful_logins.reset_risk_score", True)
            )
            success_event_type_map = {
                "ssh": ["accepted_login"],
                "minecraft": ["login"],
            }
            success_event_types = success_event_type_map.get(
                event.connection_type.value,
                [],
            )
            is_success_event = event.details.get("event_type") in success_event_types

            if is_success_event and not success_logging_enabled:
                return

            # 4. ASN lookup
            asn_result = self._asn_engine.lookup(event.source_ip)

            # 5. Query recent events count
            time_window = self._config.get("general.analysis_interval", 5)
            event_count = await self._db.get_event_count_by_ip(
                source_ip,
                minutes=time_window,
                connection_type=event.connection_type.value,
                reset_on_success=reset_risk_on_success,
                success_event_types=success_event_types,
            )

            # 6. Calculate risk score
            context = {
                "event_count": event_count,
                "is_suspicious_asn": asn_result.is_suspicious,
                "asn_result": asn_result,
            }
            risk_score = await plugin.calculate_risk(event, context)

            if is_success_event and reset_risk_on_success:
                risk_score = 0

            # 7. Determine threat level
            if is_success_event and reset_risk_on_success:
                threat = ThreatLevel.NONE
            elif risk_score >= 70:
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
                is_suspicious_asn=asn_result.is_suspicious,
                threat_level=threat,
                risk_score=risk_score,
                raw_log_line=event.raw_log_line,
                details=event.details,
            )
            await self._db.log_event(updated_event, source_ip)

            if is_success_event:
                self._logger.info(
                    "Successful login recorded: Plugin=%s User=%s IP=%s",
                    plugin.name,
                    event.player_name or "unknown",
                    event.source_ip,
                )
                return

            # 9. Execute action
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
                    self._stats_total_bans += 1
                    await self._db.log_ban(
                        source_ip, reason, risk_score, ban_duration
                    )
                    # Report to AbuseIPDB
                    categories = [18] if event.connection_type.value == "ssh" else [14]
                    await self._abuse_reporter.report_ip(
                        ip=event.source_ip,
                        categories=categories,
                        comment=reason,
                    )
                    # Send notification
                    await self._notifier.notify_ban(
                        ip=event.source_ip,
                        reason=reason,
                        risk=risk_score,
                        duration=ban_duration,
                        plugin=plugin.name,
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

        # Periodic stats summary (every 5 minutes by default)
        async def _stats_loop():
            interval = self._config.get("general.stats_interval", 300)
            while self._running:
                await asyncio.sleep(interval)
                if not self._running:
                    break
                uptime = int(time.monotonic() - self._start_time)
                m, s = divmod(uptime, 60)
                h, m = divmod(m, 60)
                db_stats = await self._db.get_stats()
                self._logger.info(
                    "── STATS ── Uptime: %02d:%02d:%02d | "
                    "Session events: %d | Session bans: %d | "
                    "DB total events: %d | DB active bans: %d",
                    h, m, s,
                    self._stats_total_events,
                    self._stats_total_bans,
                    db_stats.get("total_events", 0),
                    db_stats.get("active_bans", 0),
                )

        stats_task = asyncio.create_task(_stats_loop())

        try:
            await stop_event.wait()
        except KeyboardInterrupt:
            pass
        finally:
            stats_task.cancel()
            await self.shutdown()

    def _log_system_info(self) -> None:
        """Logs basic system information for easier debugging."""
        import platform
        import sys
        import os

        os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
        arch_info = f"{platform.machine()} ({platform.architecture()[0]})"
        py_version = sys.version.split()[0]
        
        # Try to get RAM info using standard libs
        mem_info = "Unknown"
        try:
            if sys.platform == "linux":
                # Using sysconf on linux
                pages = os.sysconf("SC_PHYS_PAGES")
                page_size = os.sysconf("SC_PAGE_SIZE")
                total_ram_gb = (pages * page_size) / (1024 ** 3)
                mem_info = f"{total_ram_gb:.1f} GB"
            elif sys.platform == "win32":
                import ctypes
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                total_ram_gb = stat.ullTotalPhys / (1024 ** 3)
                mem_info = f"{total_ram_gb:.1f} GB"
        except Exception:
            pass

        self._logger.info("--- System Information ---")
        self._logger.info("OS      : %s", os_info)
        self._logger.info("Arch    : %s", arch_info)
        self._logger.info("Python  : %s", py_version)
        self._logger.info("RAM     : %s", mem_info)
        self._logger.info("--------------------------")

    async def _check_dependencies(self) -> None:
        """Verifies if required system programs are installed."""
        import shutil
        import sys
        import os

        # Debian/Ubuntu install ipset/iptables under /usr/sbin which may not be
        # in the PATH of a non-root user.  Search the common sbin directories
        # too so we don't emit a false-positive "missing tools" warning.
        def _which_sbin(tool: str):
            base = os.environ.get("PATH", "")
            extra = ["/sbin", "/usr/sbin", "/usr/local/sbin"]
            search_path = os.pathsep.join([base, *extra])
            return shutil.which(tool, path=search_path)

        # Basic tools check
        required_tools = []
        if sys.platform != "win32":
            required_tools.extend(["ipset", "iptables"])

            # Optional but recommended
            if not _which_sbin("rsyslogd") and not _which_sbin("journalctl"):
                self._logger.warning(
                    "System check: Neither 'rsyslog' nor 'journalctl' was found. "
                    "Log tailing might not work correctly if logs are not written."
                )

        missing = []
        for tool in required_tools:
            if not _which_sbin(tool):
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
        if self._notifier:
            await self._notifier.close()
        if self._dashboard:
            await self._dashboard.stop()
        if self._blocklist:
            await self._blocklist.stop()
        if self._firewall:
            await self._firewall.shutdown()
        if self._db:
            await self._db.close()
        
        # Cancel ASN update scheduler
        if self._asn_update_task and not self._asn_update_task.done():
            self._asn_update_task.cancel()
            try:
                await self._asn_update_task
            except asyncio.CancelledError:
                pass
        
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
        version=f"WardenIPS v{__version__} by {__author__}",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print a summary of WardenIPS database stats and exit.",
    )
    return parser.parse_args()


async def print_status(config_path: str) -> None:
    """Connect to the DB read-only, print stats, then exit."""
    config = await ConfigManager.load(Path(config_path))
    db = await DatabaseManager.create(config)
    stats = await db.get_stats()
    await db.close()

    print("="*50)
    print(f"  WardenIPS v{__version__} — Status Report")
    print(f"  Maintainer     : {__author__}")
    print("="*50)
    print(f"  Database       : {stats.get('db_path', 'N/A')}")
    print(f"  Total events   : {stats.get('total_events', 0)}")
    print(f"  Total bans     : {stats.get('total_bans', 0)}")
    print(f"  Active bans    : {stats.get('active_bans', 0)}")
    print(f"  Top attackers  : (run 'sqlite3 <db> \"SELECT source_ip, COUNT(*) c FROM ban_history GROUP BY source_ip ORDER BY c DESC LIMIT 5;\"')")
    print("="*50)


async def main() -> None:
    """Main entry point."""
    args = parse_args()

    if args.status:
        await print_status(args.config)
        return

    warden = WardenIPS(config_path=args.config)
    await warden.start()
    await warden.run_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Suppress the KeyboardInterrupt traceback for a clean console output
        pass
