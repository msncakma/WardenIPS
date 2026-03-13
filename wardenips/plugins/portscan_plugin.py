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
    r"(?:\[UFW BLOCK\]|Warden-PortScan:).*?SRC=([0-9a-fA-F:\.]+).*?DPT=(\d+)"
)

# Common scanner target ports. Connecting to these is instant BAN.
TRAP_PORTS = {23, 2323, 135, 139, 445, 1433, 3389, 5900}


class PortscanPlugin(BasePlugin):
    """
    Analyzes syslogs/kern.log to detect and block port scanners.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        self._trap_ports = set(self._config.get("plugins.portscan.trap_ports", TRAP_PORTS))
        self._scan_threshold = self._config.get("plugins.portscan.scan_threshold", 10)
        self._log_path = self._config.get("plugins.portscan.log_path", "/var/log/kern.log")
        self._installed_iptables = False

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
            # We add a rule that LOGs SYN packets to our trap ports.
            # Using -m multiport --dports works for up to 15 ports.
            ports_str = ",".join(map(str, list(self._trap_ports)[:15]))
            
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
                    self._logger.info("Installed custom iptables trap rule for ports: %s", ports_str)
        except Exception as e:
            self._logger.warning("Failed to setup PortScan trap rules (skip if not root or Windows): %s", e)
            
        await super().on_start()

    async def on_stop(self) -> None:
        """
        Cleanup iptables rules if we added them.
        """
        if self._installed_iptables:
            try:
                ports_str = ",".join(map(str, list(self._trap_ports)[:15]))
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
                self._logger.info("Removed custom iptables trap rule.")
            except Exception as e:
                self._logger.warning("Failed to remove PortScan trap rules: %s", e)
                
        await super().on_stop()

    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        match = _RE_PORTSCAN.search(line)
        if not match:
            return None

        ip = match.group(1)
        port = match.group(2)

        return ConnectionEvent(
            timestamp=datetime.now(),
            source_ip=ip,
            connection_type=ConnectionType.PORTSCAN,
            player_name=f"port_{port}",  # Store the scanned port in player_name for telemetry
            asn_number="",
            asn_org=""
        )

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
