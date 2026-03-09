"""
WardenIPS - Minecraft Plugin
===============================

To monitor Minecraft server log file (latest.log),
this plugin detects botnet and DDoS attacks.

Detected patterns:
  - Player connections (login)
  - Player disconnections (disconnect/lost connection)
  - Fast sequential connection attempts (botnet indicator)
  - Invalid packet/protocol errors
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.plugins.base_plugin import BasePlugin


# ══════════════════════════════════════════════════════════
#  Minecraft Log Regex Kaliplari (IPv4 + IPv6)
# ══════════════════════════════════════════════════════════

# Generic IP pattern: matches IPv4 dotted-quad or IPv6 (colon-hex)
_IP = r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]{3,39})'

# [14:30:22] [Server thread/INFO]: PlayerName[/203.0.113.50:12345] logged in
_RE_LOGIN = re.compile(
    r"\[.*?INFO\].*?:\s+(\S+)\[/" + _IP + r":\d+\]\s+logged in"
)

# [14:30:22] [Server thread/INFO]: PlayerName lost connection: Disconnected
_RE_DISCONNECT = re.compile(
    r"\[.*?INFO\].*?:\s+(\S+)\s+lost connection:\s+(.*)"
)

# [14:30:22] [Server thread/INFO]: /203.0.113.50:12345 lost connection: ...
_RE_IP_DISCONNECT = re.compile(
    r"\[.*?INFO\].*?:\s+/" + _IP + r":\d+\s+lost connection:\s+(.*)"
)

# [14:30:22] [Server thread/WARN]: Failed to handle packet for /203.0.113.50:12345
_RE_FAILED_PACKET = re.compile(
    r"\[.*?WARN\].*?Failed to handle packet for /" + _IP
)

# [14:30:22] [Server thread/INFO]: com.mojang.authlib.GameProfile ... (/203.0.113.50) ...
_RE_GAMEPROFILE_LOGIN = re.compile(
    r"GameProfile\{.*?name='?(\S+?)'?}\s*\(/" + _IP + r"\)"
)

# Minecraft log tarih formati: [14:30:22]
_RE_MC_TIMESTAMP = re.compile(
    r"\[(\d{2}:\d{2}:\d{2})\]"
)


class MinecraftPlugin(BasePlugin):
    """
    Minecraft botnet/DDoS dedect plugin.

    latest.log dosyasindaki baglanti eventslarini
    regex ile ayristirir ve risk skoru hesaplar.

    It evaluates fast sequential connection attempts as botnet indicator.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        plugin_conf = config.get_section("plugins").get("minecraft", {})
        self._enabled = plugin_conf.get("enabled", True)
        self._rapid_threshold = plugin_conf.get("rapid_connection_threshold", 10)
        self._time_window = plugin_conf.get("time_window", 60)

    @property
    def name(self) -> str:
        return "Minecraft"

    @property
    def log_file_path(self) -> str:
        return self._config.get(
            "plugins.minecraft.log_path",
            "/opt/minecraft/logs/latest.log",
        )

    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        """Parse latest.log line."""

        timestamp = self._parse_timestamp(line)

        # 1. Player login
        match = _RE_LOGIN.search(line)
        if match:
            player, ip = match.group(1), match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.MINECRAFT,
                player_name=player,
                threat_level=ThreatLevel.NONE,
                risk_score=0,
                raw_log_line=line,
                details={"event_type": "login"},
            )

        # 2. GameProfile connection (some server versions)
        match = _RE_GAMEPROFILE_LOGIN.search(line)
        if match:
            player, ip = match.group(1), match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.MINECRAFT,
                player_name=player,
                threat_level=ThreatLevel.NONE,
                risk_score=0,
                raw_log_line=line,
                details={"event_type": "login"},
            )

        # 3. IP connection loss (without nickname)
        match = _RE_IP_DISCONNECT.search(line)
        if match:
            ip, reason = match.group(1), match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.MINECRAFT,
                player_name=None,
                threat_level=ThreatLevel.LOW,
                risk_score=0,
                raw_log_line=line,
                details={
                    "event_type": "ip_disconnect",
                    "reason": reason.strip(),
                },
            )

        # 4. Packet error
        match = _RE_FAILED_PACKET.search(line)
        if match:
            ip = match.group(1)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.MINECRAFT,
                player_name=None,
                threat_level=ThreatLevel.MEDIUM,
                risk_score=0,
                raw_log_line=line,
                details={"event_type": "failed_packet"},
            )

        # This line is not related to Minecraft connection
        return None

    async def calculate_risk(self, event: ConnectionEvent, context: dict) -> int:
        """
        Calculate risk score for Minecraft events.

        Factors:
          - Event type (failed_packet > ip_disconnect > login)
          - Number of connections in the last N seconds (fast = botnet)
          - Datacenter IP?
          - Player name missing? (bot indicator)
        """
        score = 0
        event_type = event.details.get("event_type", "")
        event_count = context.get("event_count", 0)
        is_datacenter = context.get("is_datacenter", False)

        # Event type based base score
        if event_type == "failed_packet":
            score += 30  # Invalid packet = attack indicator
        elif event_type == "ip_disconnect":
            score += 15  # Fast connect/disconnect = bot
        elif event_type == "login":
            score += 5   # Normal login = low risk

        # Fast connection attempts (botnet pattern)
        # Each connection adds 10 points, so a large number of connections in a short time raises the score
        if event_count > 0:
            score += min(event_count * 10, 60)

        # Datacenter IP
        if is_datacenter:
            score += 20

        # Player name missing? (bot indicator)
        if not event.player_name:
            score += 10

        return min(score, 100)

    def _parse_timestamp(self, line: str) -> datetime:
        """Parse Minecraft log timestamp."""
        match = _RE_MC_TIMESTAMP.search(line)
        if match:
            try:
                time_str = match.group(1)
                now = datetime.utcnow()
                parsed = datetime.strptime(time_str, "%H:%M:%S")
                return parsed.replace(
                    year=now.year, month=now.month, day=now.day
                )
            except ValueError:
                pass
        return datetime.utcnow()
