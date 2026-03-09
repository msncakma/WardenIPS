"""
WardenIPS - Nginx Plugin (Layer 7 Web Threat Detection)
=========================================================

Monitors Nginx/Apache access and error logs for malicious HTTP
requests: path traversal, SQL injection probes, scanner fingerprints,
excessive 4xx errors, and other common web attack patterns.

Detected patterns:
  - Directory traversal (../ sequences)
  - SQL injection probes (UNION SELECT, OR 1=1, etc.)
  - Scanner/exploit tool fingerprints (nikto, sqlmap, etc.)
  - Shell injection attempts (/bin/sh, cmd.exe, etc.)
  - Excessive 403/404 responses (brute-force scanning)
  - Suspicious HTTP methods (CONNECT, TRACE, DELETE on websites)
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.plugins.base_plugin import BasePlugin


# ══════════════════════════════════════════════════════════
#  Nginx/Apache Access Log Regex (Combined Log Format)
# ══════════════════════════════════════════════════════════

# Generic IP pattern: matches IPv4 dotted-quad or IPv6 (colon-hex)
_IP = r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]{3,39})'

# 203.0.113.50 - - [08/Mar/2025:14:30:22 +0000] "GET /path HTTP/1.1" 200 1234 "ref" "ua"
_RE_ACCESS_LOG = re.compile(
    _IP + r'\s+-\s+\S+\s+'
    r'\[([^\]]+)\]\s+'
    r'"(\S+)\s+(\S+)\s+\S+"\s+'
    r'(\d{3})\s+'
    r'(\d+|-)'
)

# Nginx error log: 2025/03/08 14:30:22 [error] ... client: 203.0.113.50, ...
_RE_ERROR_LOG = re.compile(
    r'\[error\].*?client:\s+' + _IP
)

# Nginx access log timestamp
_RE_NGINX_DATE = re.compile(
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'
)

# ══════════════════════════════════════════════════════════
#  Threat Detection Patterns
# ══════════════════════════════════════════════════════════

# Directory traversal
_RE_DIR_TRAVERSAL = re.compile(r'\.\./|\.\.\\', re.IGNORECASE)

# SQL injection probes
_RE_SQLI = re.compile(
    r"(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|"
    r";\s*drop\s+table|;\s*select\s+|"
    r"information_schema|concat\(|benchmark\(|sleep\()",
    re.IGNORECASE,
)

# Shell injection / command execution
_RE_SHELL = re.compile(
    r'/(?:bin/(?:sh|bash|zsh)|etc/passwd|etc/shadow|proc/self|'
    r'cmd\.exe|powershell|eval\(|system\(|exec\()',
    re.IGNORECASE,
)

# Scanner / exploit tool user-agents
_RE_SCANNER_UA = re.compile(
    r'(?:nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|'
    r'wpscan|acunetix|nessus|openvas|nuclei|httpx|curl/|wget/|'
    r'python-requests/|Go-http-client)',
    re.IGNORECASE,
)

# Suspicious paths (admin panels, config files, etc.)
_RE_SUSPICIOUS_PATH = re.compile(
    r'(?:/wp-admin|/wp-login|/phpmyadmin|/\.env|/\.git|'
    r'/\.htaccess|/\.htpasswd|/config\.\w+|/backup|'
    r'/admin|/manager/html|/actuator|/debug|/console)',
    re.IGNORECASE,
)

# Suspicious HTTP methods
_SUSPICIOUS_METHODS = {"CONNECT", "TRACE", "DELETE", "PATCH", "OPTIONS"}


class NginxPlugin(BasePlugin):
    """
    Nginx/Apache Layer 7 web threat detection plugin.

    Parses access logs (Combined Log Format) and error logs to detect
    web-based attacks such as SQL injection, path traversal, scanner
    activity, and brute-force directory enumeration.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        plugin_conf = config.get_section("plugins").get("nginx", {})
        self._enabled = plugin_conf.get("enabled", False)

    @property
    def name(self) -> str:
        return "Nginx"

    @property
    def log_file_path(self) -> str:
        return self._config.get(
            "plugins.nginx.log_path", "/var/log/nginx/access.log"
        )

    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        """Parse an Nginx/Apache access or error log line."""

        # Try access log format first
        match = _RE_ACCESS_LOG.search(line)
        if match:
            ip = match.group(1)
            method = match.group(3)
            path = match.group(4)
            status = int(match.group(5))
            timestamp = self._parse_timestamp(line)

            # Classify the event type
            event_type, details = self._classify_request(method, path, status, line)

            if event_type is None:
                # Normal request, skip
                return None

            details["method"] = method
            details["path"] = path[:200]  # truncate long paths
            details["status"] = status

            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.NGINX,
                player_name=None,
                threat_level=ThreatLevel.MEDIUM,
                risk_score=0,
                raw_log_line=line,
                details=details,
            )

        # Try error log format
        match = _RE_ERROR_LOG.search(line)
        if match:
            ip = match.group(1)
            timestamp = self._parse_timestamp(line)
            return ConnectionEvent(
                timestamp=timestamp,
                source_ip=ip,
                connection_type=ConnectionType.NGINX,
                player_name=None,
                threat_level=ThreatLevel.LOW,
                risk_score=0,
                raw_log_line=line,
                details={"event_type": "error_log"},
            )

        return None

    def _classify_request(
        self, method: str, path: str, status: int, full_line: str
    ) -> tuple:
        """
        Classify a request as normal or malicious.

        Returns (event_type, details) or (None, {}) for benign requests.
        """
        # Directory traversal
        if _RE_DIR_TRAVERSAL.search(path):
            return "dir_traversal", {"event_type": "dir_traversal"}

        # SQL injection
        if _RE_SQLI.search(path) or _RE_SQLI.search(full_line):
            return "sqli_probe", {"event_type": "sqli_probe"}

        # Shell injection / LFI
        if _RE_SHELL.search(path):
            return "shell_injection", {"event_type": "shell_injection"}

        # Scanner detection (user-agent)
        if _RE_SCANNER_UA.search(full_line):
            return "scanner", {"event_type": "scanner"}

        # Suspicious paths (CMS probes, config files)
        if _RE_SUSPICIOUS_PATH.search(path):
            return "suspicious_path", {"event_type": "suspicious_path"}

        # Suspicious HTTP method
        if method.upper() in _SUSPICIOUS_METHODS:
            return "suspicious_method", {"event_type": "suspicious_method"}

        # 403/404 responses — potential scanning/enumeration
        if status in (403, 404):
            return "client_error", {"event_type": "client_error"}

        # Normal request — ignore
        return None, {}

    async def calculate_risk(self, event: ConnectionEvent, context: dict) -> int:
        """
        Calculate risk score for Nginx events.

        Factors:
          - Event type severity
          - Number of events in time window (scanning behaviour)
          - Datacenter IP
        """
        score = 0
        event_type = event.details.get("event_type", "")
        event_count = context.get("event_count", 0)
        is_datacenter = context.get("is_datacenter", False)

        # Event type base scores
        type_scores = {
            "sqli_probe": 50,
            "shell_injection": 50,
            "dir_traversal": 40,
            "scanner": 35,
            "suspicious_path": 25,
            "suspicious_method": 15,
            "client_error": 10,
            "error_log": 5,
        }
        score += type_scores.get(event_type, 5)

        # Repeated events (scanning pattern)
        if event_count > 0:
            score += min(event_count * 8, 50)

        # Datacenter IP
        if is_datacenter:
            score += 15

        return min(score, 100)

    def _parse_timestamp(self, line: str) -> datetime:
        """Parse Nginx access log timestamp."""
        match = _RE_NGINX_DATE.search(line)
        if match:
            try:
                return datetime.strptime(
                    match.group(1), "%d/%b/%Y:%H:%M:%S"
                )
            except ValueError:
                pass
        return datetime.utcnow()
