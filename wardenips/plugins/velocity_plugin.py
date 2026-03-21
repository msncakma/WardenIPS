"""
WardenIPS - Velocity Proxy Plugin
=================================

Parses Velocity proxy logs for player connect/disconnect activity.

Supported patterns:
  - [connected player] name (/ip:port) has connected
  - [connected player] name (/ip:port) has disconnected
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.plugins.base_plugin import BasePlugin


_IP = r"(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]{3,39})"
_RE_CONNECTED = re.compile(
    r"\[connected player\]\s+(\S+)\s+\(/" + _IP + r":(\d+)\)\s+has\s+connected",
    re.IGNORECASE,
)
_RE_DISCONNECTED = re.compile(
    r"\[connected player\]\s+(\S+)\s+\(/" + _IP + r":(\d+)\)\s+has\s+disconnected",
    re.IGNORECASE,
)
_RE_TIME = re.compile(r"\[(\d{2}:\d{2}:\d{2})\]")


class VelocityPlugin(BasePlugin):
    def __init__(self, config) -> None:
        super().__init__(config)
        velocity_conf = config.get_section("plugins").get("minecraft", {}).get("velocity", {})
        self._enabled = bool(velocity_conf.get("enabled", False))

    @property
    def name(self) -> str:
        return "Velocity"

    @property
    def log_file_path(self) -> str:
        return self._config.get(
            "plugins.minecraft.velocity.log_path",
            "/opt/velocity/logs/latest.log",
        )

    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        timestamp = self._parse_timestamp(line)

        match = _RE_CONNECTED.search(line)
        if match:
            player_name, source_ip, source_port = match.group(1), match.group(2), match.group(3)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                connection_type=ConnectionType.MINECRAFT,
                player_name=player_name,
                threat_level=ThreatLevel.NONE,
                risk_score=0,
                raw_log_line=line,
                details={
                    "event_type": "velocity_connected",
                    "parser_source": "velocity_log",
                    "source_port": int(source_port),
                },
            )

        match = _RE_DISCONNECTED.search(line)
        if match:
            player_name, source_ip, source_port = match.group(1), match.group(2), match.group(3)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                connection_type=ConnectionType.MINECRAFT,
                player_name=player_name,
                threat_level=ThreatLevel.LOW,
                risk_score=0,
                raw_log_line=line,
                details={
                    "event_type": "velocity_disconnect",
                    "parser_source": "velocity_log",
                    "source_port": int(source_port),
                },
            )

        return None

    async def calculate_risk(self, event: ConnectionEvent, context: dict) -> int:
        score = 0
        event_type = str(event.details.get("event_type", ""))
        event_count = int(context.get("event_count", 0) or 0)
        is_suspicious_asn = bool(context.get("is_suspicious_asn", False))

        if event_type == "velocity_disconnect":
            score += 8
        elif event_type == "velocity_connected":
            score += 0

        if event_count > 0:
            score += min(event_count * 8, 55)

        if is_suspicious_asn:
            score += 20

        return min(score, 100)

    def _parse_timestamp(self, line: str) -> datetime:
        match = _RE_TIME.search(line)
        if match:
            try:
                now = datetime.utcnow()
                parsed = datetime.strptime(match.group(1), "%H:%M:%S")
                return parsed.replace(year=now.year, month=now.month, day=now.day)
            except Exception:
                pass
        return datetime.utcnow()
