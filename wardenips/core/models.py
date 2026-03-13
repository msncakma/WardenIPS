"""
WardenIPS - Data Models
===========================

System-wide dataclass and enum definitions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class ThreatLevel(enum.IntEnum):
    """
    Threat level classification.

    Numeric values are used as multipliers in risk score calculations.
    """

    NONE = 0        # Clean connection
    LOW = 10        # Low risk (e.g. single failed login)
    MEDIUM = 40     # Medium risk (e.g. repeated attempts)
    HIGH = 70       # High risk (e.g. brute-force pattern)
    CRITICAL = 100  # Critical (e.g. known botnet ASN, datacenter IP)


class ConnectionType(enum.Enum):
    """Connection source types."""

    SSH = "ssh"
    MINECRAFT = "minecraft"
    NGINX = "nginx"
    PORTSCAN = "portscan"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ConnectionEvent:
    """
    Immutable data model representing a single connection event.

    Attributes:
        timestamp:         Timestamp of when the event occurred.
        source_ip:         Source IP address (plaintext, used only in analysis).
        connection_type:   Connection type (e.g. SSH, Minecraft)
        player_name:       Player nick (Minecraft) or username (SSH).
        asn_number:        ASN number the IP belongs to.
        asn_org:           ASN organization name.
        is_suspicious_asn: Is the IP's ASN on the user's suspicious list?
        threat_level:      Calculated threat level.
        risk_score:        Risk score from 0 to 100.
        raw_log_line:      Raw log line (for debugging).
        details:           Additional analysis details.
    """

    timestamp: datetime
    source_ip: str
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    player_name: Optional[str] = None
    asn_number: Optional[int] = None
    asn_org: Optional[str] = None
    is_suspicious_asn: bool = False
    threat_level: ThreatLevel = ThreatLevel.NONE
    risk_score: int = 0
    raw_log_line: Optional[str] = None
    details: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return (
            f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] "
            f"{self.connection_type.value.upper():10s} | "
            f"IP={self.source_ip:>15s} | "
            f"Risk={self.risk_score:3d} | "
            f"Threat={self.threat_level.name}"
        )
