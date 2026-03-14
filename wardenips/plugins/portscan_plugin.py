"""
WardenIPS - Portscan Plugin
===========================

Detects port scanners and botnets hitting closed or trap ports.
Integrates natively with UFW. If UFW is off, it installs a safety 
iptables LOG rule for common trap ports (Telnet, SMB, etc.) to 
ensure scanners are caught regardless of firewall state.

Detected events:
  - UFW Block logs
  - WardenIPS specific port trap logs
"""

from __future__ import annotations

import re
import asyncio
import time
from datetime import datetime
from typing import Optional, Dict

from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.plugins.base_plugin import BasePlugin
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# Matches both UFW blocks and WardenIPS custom trap blocks
# kernel: [1234.567] [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=... PROTO=TCP ... DPT=23
# kernel: [1234.567] Warden-PortScan: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=... PROTO=TCP ... DPT=23
_RE_PORTSCAN = re.compile(
    r"(?:\[UFW BLOCK\]|\[UFW AUDIT\]|Warden-PortScan(?:-All)?:|\bDROP\b|\bREJECT\b|\bDENY\b).*?SRC=([0-9a-fA-F:\.]+).*?DPT=(\d+)"
)

_RE_GENERIC_FIREWALL = re.compile(r"SRC=([0-9a-fA-F:\.]+).*?DPT=(\d+)")

# Syslog style prefix: Mar 13 14:30:22
_RE_SYSLOG_DATE = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)")

# Common scanner target ports. Connecting to these is instant BAN.
TRAP_PORTS = {23, 2323, 135, 139, 445, 1433, 3389, 5900}


class PortscanPlugin(BasePlugin):
    """
    Analyzes syslogs/kern.log to detect and block port scanners.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        raw_ports = self._config.get("plugins.portscan.trap_ports", TRAP_PORTS)
        raw_ignored_ports = self._config.get("plugins.portscan.ignored_ports", [])
        parsed_ports = set()
        parsed_ignored_ports = set()
        for port_value in raw_ports:
            try:
                parsed_ports.add(int(port_value))
            except (TypeError, ValueError):
                self._logger.warning("Ignoring invalid trap port value: %r", port_value)
        for port_value in raw_ignored_ports:
            try:
                parsed_ignored_ports.add(int(port_value))
            except (TypeError, ValueError):
                self._logger.warning("Ignoring invalid ignored port value: %r", port_value)
        self._ignored_ports = parsed_ignored_ports
        effective_trap_ports = (parsed_ports or set(TRAP_PORTS)) - self._ignored_ports
        self._trap_ports = effective_trap_ports
        self._scan_threshold = self._config.get("plugins.portscan.scan_threshold", 10)
        self._log_path = self._config.get("plugins.portscan.log_path", "/var/log/kern.log")
        self._monitor_all_ports = bool(self._config.get("plugins.portscan.monitor_all_ports", True))
        self._all_ports_limit_per_min = max(
            int(self._config.get("plugins.portscan.monitor_all_ports_limit_per_min", 120)),
            1,
        )
        self._all_ports_limit_burst = max(
            int(self._config.get("plugins.portscan.monitor_all_ports_burst", 120)),
            1,
        )
        raw_interfaces = self._config.get("plugins.portscan.monitor_all_ports_interfaces", [])
        parsed_interfaces: list[str] = []
        if isinstance(raw_interfaces, (list, tuple, set)):
            for value in raw_interfaces:
                interface = str(value).strip()
                if interface:
                    parsed_interfaces.append(interface)
        self._monitor_all_ports_interfaces = parsed_interfaces
        self._installed_iptables = False
        self._installed_iptables_port_groups: list[str] = []
        self._installed_all_ports_interfaces: list[str] = []
        # Dedup cache: prevents double-processing when both UFW and Warden-PortScan
        # iptables rules log the same packet (same ip+port within 2 seconds).
        self._recently_seen: dict[tuple, float] = {}

    def _build_all_ports_rule_args(self, interface: Optional[str] = None) -> list[str]:
        args = ["INPUT"]
        if interface:
            args.extend(["-i", interface])
        args.extend(
            [
                "-p", "tcp", "--syn",
                "-m", "conntrack", "--ctstate", "NEW",
                "-m", "limit", "--limit", f"{self._all_ports_limit_per_min}/minute",
                "--limit-burst", str(self._all_ports_limit_burst),
                "-j", "LOG", "--log-prefix", "Warden-PortScan-All: ",
            ]
        )
        return args

    def _iter_trap_port_groups(self) -> list[str]:
        """Return comma-separated trap-port groups (iptables multiport supports max 15)."""
        ports = sorted(self._trap_ports)
        if not ports:
            return []
        groups = []
        for i in range(0, len(ports), 15):
            groups.append(",".join(str(p) for p in ports[i:i + 15]))
        return groups

    @property
    def name(self) -> str:
        return "PortScan"

    @property
    def log_file_path(self) -> str:
        return self._log_path

    async def on_start(self) -> None:
        """
        Ensure iptables logs trap ports so we catch them even without UFW.
        """
        try:
            port_groups = self._iter_trap_port_groups()
            for ports_str in port_groups:
                check_cmd = [
                    "iptables", "-C", "INPUT", "-p", "tcp", "--syn",
                    "-m", "multiport", "--dports", ports_str,
                    "-j", "LOG", "--log-prefix", "Warden-PortScan: "
                ]

                proc = await asyncio.create_subprocess_exec(
                    *check_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()

                if proc.returncode != 0:
                    # Rule doesn't exist, insert it at the top of INPUT chain
                    insert_cmd = [
                        "iptables", "-I", "INPUT", "1", "-p", "tcp", "--syn",
                        "-m", "multiport", "--dports", ports_str,
                        "-j", "LOG", "--log-prefix", "Warden-PortScan: "
                    ]
                    proc_ins = await asyncio.create_subprocess_exec(
                        *insert_cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await proc_ins.wait()
                    if proc_ins.returncode == 0:
                        self._installed_iptables = True
                        self._installed_iptables_port_groups.append(ports_str)
                        self._logger.info("Installed custom iptables trap rule for ports: %s", ports_str)

            if self._monitor_all_ports:
                # Catch broad scan attempts (not only honeypot ports) so operator can
                # see non-trap probes in event history.
                targets = self._monitor_all_ports_interfaces or [""]
                for interface in targets:
                    rule_args = self._build_all_ports_rule_args(interface or None)
                    check_all_cmd = ["iptables", "-C", *rule_args]
                    proc_all = await asyncio.create_subprocess_exec(
                        *check_all_cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await proc_all.wait()
                    if proc_all.returncode != 0:
                        insert_all_cmd = ["iptables", "-I", *rule_args]
                        proc_ins_all = await asyncio.create_subprocess_exec(
                            *insert_all_cmd,
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        await proc_ins_all.wait()
                        if proc_ins_all.returncode == 0:
                            self._installed_all_ports_interfaces.append(interface)
                            if interface:
                                self._logger.info(
                                    "Installed all-port SYN log rule for interface '%s' (%s/min burst=%s).",
                                    interface,
                                    self._all_ports_limit_per_min,
                                    self._all_ports_limit_burst,
                                )
                            else:
                                self._logger.info(
                                    "Installed all-port SYN log rule (%s/min burst=%s).",
                                    self._all_ports_limit_per_min,
                                    self._all_ports_limit_burst,
                                )
        except Exception as e:
            self._logger.warning("Failed to setup PortScan trap rules (skip if not root or Windows): %s", e)
            
        await super().on_start()

    async def on_stop(self) -> None:
        """
        Cleanup iptables rules if we added them.
        """
        if self._installed_iptables:
            try:
                for ports_str in self._installed_iptables_port_groups:
                    del_cmd = [
                        "iptables", "-D", "INPUT", "-p", "tcp", "--syn",
                        "-m", "multiport", "--dports", ports_str,
                        "-j", "LOG", "--log-prefix", "Warden-PortScan: "
                    ]
                    proc_del = await asyncio.create_subprocess_exec(
                        *del_cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await proc_del.wait()
                    self._logger.info("Removed custom iptables trap rule for ports: %s", ports_str)
            except Exception as e:
                self._logger.warning("Failed to remove PortScan trap rules: %s", e)

        if self._installed_all_ports_interfaces:
            try:
                for interface in self._installed_all_ports_interfaces:
                    rule_args = self._build_all_ports_rule_args(interface or None)
                    del_all_cmd = ["iptables", "-D", *rule_args]
                    proc_del_all = await asyncio.create_subprocess_exec(
                        *del_all_cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await proc_del_all.wait()
                    if interface:
                        self._logger.info("Removed all-port SYN log rule for interface '%s'.", interface)
                    else:
                        self._logger.info("Removed all-port SYN log rule for PortScan telemetry.")
            except Exception as e:
                self._logger.warning("Failed to remove all-port PortScan rule: %s", e)
                
        await super().on_stop()

    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        match = _RE_PORTSCAN.search(line)
        if not match:
            # Fallback for distro-specific firewall log prefixes that still expose
            # SRC/DPT fields but don't include UFW/Warden marker strings.
            upper_line = line.upper()
            if not any(marker in upper_line for marker in ("DROP", "REJECT", "DENY", "BLOCK", "Warden-PortScan".upper())):
                return None
            match = _RE_GENERIC_FIREWALL.search(line)
            if not match:
                return None

        ip = match.group(1)
        port = match.group(2)
        try:
            if int(port) in self._ignored_ports:
                return None
        except ValueError:
            return None

        # Deduplicate: UFW and Warden-PortScan iptables rules both log the same
        # SYN packet, producing two kern.log lines within milliseconds of each
        # other.  Drop the second one to avoid double ban-logging.
        now_mono = time.monotonic()
        seen_key = (ip, port)
        if now_mono - self._recently_seen.get(seen_key, 0.0) < 2.0:
            return None
        self._recently_seen[seen_key] = now_mono
        # Prune stale entries to prevent unbounded growth
        if len(self._recently_seen) > 5000:
            cutoff = now_mono - 2.0
            self._recently_seen = {k: v for k, v in self._recently_seen.items() if v > cutoff}

        timestamp = self._parse_timestamp(line)

        return ConnectionEvent(
            timestamp=timestamp,
            source_ip=ip,
            connection_type=ConnectionType.PORTSCAN,
            player_name=f"port_{port}",  # Store the scanned port in player_name for telemetry
            asn_number="",
            asn_org="",
            raw_log_line=line,
            details={"event_type": "portscan"},
        )

    def _parse_timestamp(self, line: str) -> datetime:
        """Parse syslog timestamp. Fallback to current UTC time."""
        match = _RE_SYSLOG_DATE.match(line)
        if match:
            try:
                parsed = datetime.strptime(match.group(1), "%b %d %H:%M:%S")
                return parsed.replace(year=datetime.utcnow().year)
            except ValueError:
                pass
        return datetime.utcnow()

    async def calculate_risk(self, event: ConnectionEvent, context: dict) -> int:
        port_str = event.player_name.replace("port_", "")
        try:
            port = int(port_str)
        except ValueError:
            port = 0

        # If they hit a honeypot trap port (23, 445, etc), instant critical risk!
        if port in self._trap_ports:
            self._logger.warning("Instant trap triggered for IP %s on port %d!", event.source_ip, port)
            return ThreatLevel.CRITICAL.value

        # For normal UFW block logs, we count how many unique ports or drops accumulated
        recent_events = context.get("recent_events", [])
        
        # Only count events from THIS plugin
        portscan_events = [e for e in recent_events if e.connection_type == ConnectionType.PORTSCAN]
        drop_count = len(portscan_events)
        
        # If the IP has hit closed ports multiple times in a short window
        if drop_count >= self._scan_threshold:
            self._logger.warning("Port scanner detected: IP %s blocked %d times.", event.source_ip, drop_count)
            return ThreatLevel.CRITICAL.value
            
        # Add risk incrementally per dropped connection
        # Give +10 for every dropped connection, so 7 drops = 70 risk
        return min(ThreatLevel.CRITICAL.value, 10 * drop_count)
