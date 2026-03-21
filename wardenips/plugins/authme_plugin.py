"""
WardenIPS - AuthMe Plugin
===================================

Monitor AuthMe plugin log file (plugins/authme/authme.log),
detecting successful logins and registrations.

Detected patterns:
  - Successful player logins
  - Player registrations
  - Failed login attempts (via correlation with disconnects)
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.plugins.base_plugin import BasePlugin


# ══════════════════════════════════════════════════════════
#  AuthMe Log Regex Patterns
# ══════════════════════════════════════════════════════════

# Generic IP pattern: matches IPv4 dotted-quad or IPv6 (colon-hex)
_IP = r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]{3,39})'

# [06-25 19:02:40]: [FINE] gendi logged in 31.223.96.201
_RE_LOGIN = re.compile(
    r"\[.*?\]\s*:\s*\[FINE\]\s+(\S+)\s+logged in\s+" + _IP
)

# [06-25 21:35:26]: [FINE] Vincent001 registered 31.223.103.64
_RE_REGISTRATION = re.compile(
    r"\[.*?\]\s*:\s*\[FINE\]\s+(\S+)\s+registered\s+" + _IP
)

# AuthMe timestamp format: [MM-DD HH:MM:SS]
_RE_AUTHME_TIMESTAMP = re.compile(
    r"\[(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]"
)


class AuthMePlugin(BasePlugin):
    """
    AuthMe successful login/registration detection plugin.

    Parses plugins/authme/authme.log file and creates events
    for successful logins and registrations.

    Uses correlation with Minecraft disconnect events to track
    if a login actually connected successfully or disconnected shortly after.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        plugin_conf = config.get_section("plugins").get("authme", {})
        self._enabled = plugin_conf.get("enabled", True)
        # Correlation window in seconds: if disconnect happens within this
        # time after login, mark login_successful=false
        self._correlation_window_seconds = plugin_conf.get(
            "correlation_window_seconds", 30
        )

    @property
    def name(self) -> str:
        return "AuthMe"

    @property
    def log_file_path(self) -> str:
        return self._config.get(
            "plugins.authme.log_file_path",
            "plugins/authme/authme.log",
        )

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        """Parse authme.log line and extract login/registration events."""

        timestamp = self._parse_timestamp(line)

        # 1. Successful login event
        match = _RE_LOGIN.search(line)
        if match:
            player_name = match.group(1)
            source_ip = match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                connection_type=ConnectionType.AUTHME,
                player_name=player_name,
                threat_level=ThreatLevel.NONE,
                risk_score=0,
                raw_log_line=line,
                details={
                    "event_type": "login",
                    "login_successful": True,  # Default to True; may be updated by correlation
                },
            )

        # 2. Registration event
        match = _RE_REGISTRATION.search(line)
        if match:
            player_name = match.group(1)
            source_ip = match.group(2)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                connection_type=ConnectionType.AUTHME,
                player_name=player_name,
                threat_level=ThreatLevel.LOW,
                risk_score=10,
                raw_log_line=line,
                details={
                    "event_type": "registration",
                    "login_successful": True,
                },
            )

        return None

    def _parse_timestamp(self, line: str) -> datetime:
        """
        Parse AuthMe timestamp format: [MM-DD HH:MM:SS]
        Falls back to current UTC time if parsing fails.
        """
        try:
            match = _RE_AUTHME_TIMESTAMP.search(line)
            if match:
                ts_str = match.group(1)
                # Format: MM-DD HH:MM:SS
                # Note: AuthMe logs don't include year, so use current year
                current_year = datetime.utcnow().year
                dt_str = f"{current_year}-{ts_str}"
                return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError):
            pass
        return datetime.utcnow()

    async def calculate_risk(
        self,
        event: ConnectionEvent,
        context: dict,
    ) -> int:
        """
        Calculate risk score for AuthMe events.

        - Login: NONE (0) - successful authentication is low risk
        - Registration: LOW (10) - new account creation slightly elevated
        """
        event_type = event.details.get("event_type", "unknown")

        if event_type == "registration":
            return 10  # Low risk for new registrations

        return 0  # Successful logins are no risk

    async def on_event(self, event: ConnectionEvent) -> None:
        """
        Hook called after event is logged to database.
        Can be used for additional processing, notifications, etc.
        """
        pass

    async def on_start(self) -> None:
        """Initialize plugin when started."""
        pass

    async def on_stop(self) -> None:
        """Cleanup when plugin is stopped."""
        pass
