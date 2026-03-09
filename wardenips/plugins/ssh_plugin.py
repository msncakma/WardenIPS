"""
WardenIPS - SSH Plugin
========================

Monitors /var/log/auth.log for SSH brute-force attacks.

Detected events:
  - Failed password try (Failed password)
  - Invalid user try (Invalid user)
  - Key authentication failure
  - Connection closed (connection closed/reset)
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.plugins.base_plugin import BasePlugin


# ══════════════════════════════════════════════════════════
#  auth.log Regex Kaliplari
# ══════════════════════════════════════════════════════════

# Failed password for root from 203.0.113.50 port 22 ssh2
_RE_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Invalid user admin from 203.0.113.50 port 22
_RE_INVALID_USER = re.compile(
    r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Accepted password for root from 192.168.1.1 port 54321 ssh2
_RE_ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Connection closed by authenticating user root 203.0.113.50 port 22
_RE_CONNECTION_CLOSED = re.compile(
    r"Connection (?:closed|reset) by (?:authenticating user )?(\S+)?\s*(\d+\.\d+\.\d+\.\d+)"
)

# pam_unix(sshd:auth): authentication failure; ... rhost=203.0.113.50 user=root
_RE_PAM_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)(?:\s+user=(\S+))?"
)

# sshd auth.log tarih formati: Mar  8 14:30:22
_RE_SYSLOG_DATE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)"
)


class SSHPlugin(BasePlugin):
    """
    SSH brute-force detection plugin.

    Parses failed login attempts from auth.log
    using regex and calculates risk scores.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        plugin_conf = config.get_section("plugins").get("ssh", {})
        self._enabled = plugin_conf.get("enabled", True)
        self._max_failed = plugin_conf.get("max_failed_attempts", 5)
        self._time_window = plugin_conf.get("time_window", 300)

    @property
    def name(self) -> str:
        return "SSH"

    @property
    def log_file_path(self) -> str:
        return self._config.get("plugins.ssh.log_path", "/var/log/auth.log")

    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        """Parse an auth.log line."""

        # Extract timestamp
        timestamp = self._parse_timestamp(line)

        # 1. Failed password
        match = _RE_FAILED_PASSWORD.search(line)
        if match:
            username, ip = match.group(1), match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.SSH,
                player_name=username,
                threat_level=ThreatLevel.MEDIUM,
                risk_score=0,  # calculate_risk'te hesaplanacak
                raw_log_line=line,
                details={"event_type": "failed_password"},
            )

        # 2. Invalid user
        match = _RE_INVALID_USER.search(line)
        if match:
            username, ip = match.group(1), match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.SSH,
                player_name=username,
                threat_level=ThreatLevel.MEDIUM,
                risk_score=0,
                raw_log_line=line,
                details={"event_type": "invalid_user"},
            )

        # 3. PAM dogrulama hatasi
        match = _RE_PAM_FAILURE.search(line)
        if match:
            ip = match.group(1)
            username = match.group(2) or "unknown"
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.SSH,
                player_name=username,
                threat_level=ThreatLevel.LOW,
                risk_score=0,
                raw_log_line=line,
                details={"event_type": "pam_failure"},
            )

        # 4. Connection closed (dogrulama sirasinda)
        match = _RE_CONNECTION_CLOSED.search(line)
        if match:
            username = match.group(1) or "unknown"
            ip = match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.SSH,
                player_name=username,
                threat_level=ThreatLevel.LOW,
                risk_score=0,
                raw_log_line=line,
                details={"event_type": "connection_closed"},
            )

        # Bu satir SSH ile ilgili degil
        return None

    async def calculate_risk(self, event: ConnectionEvent, context: dict) -> int:
        """
        Calculate risk score for SSH events.

        Factors:
          - Event type (invalid_user > failed_password > connection_closed)
          - Number of attempts in the last N minutes (repeated attempts increase risk)
          - Datacenter IP? (datacenter = high risk)
          - root user? (root = additional risk)
        """
        score = 0
        event_type = event.details.get("event_type", "")
        event_count = context.get("event_count", 0)
        is_datacenter = context.get("is_datacenter", False)

        # Olay tipi bazli taban skor
        if event_type == "invalid_user":
            score += 25  # Var olmayan kullanici = saldiri isareti
        elif event_type == "failed_password":
            score += 15
        elif event_type == "pam_failure":
            score += 15
        elif event_type == "connection_closed":
            score += 5

        # Tekrar eden denemeler (esik ustu)
        # Her deneme 10 puan ekler, ancak sirf deneme sayisindan max 60 puan alinabilir.
        if event_count > 0:
            score += min(event_count * 10, 60)

        # Datacenter IP
        if is_datacenter:
            score += 20

        # root hedefi
        if event.player_name and event.player_name.lower() == "root":
            score += 10

        return min(score, 100)

    def _parse_timestamp(self, line: str) -> datetime:
        """Parse syslog timestamp."""
        match = _RE_SYSLOG_DATE.match(line)
        if match:
            try:
                date_str = match.group(1)
                now = datetime.utcnow()
                parsed = datetime.strptime(date_str, "%b %d %H:%M:%S")
                return parsed.replace(year=now.year)
            except ValueError:
                pass
        return datetime.utcnow()
