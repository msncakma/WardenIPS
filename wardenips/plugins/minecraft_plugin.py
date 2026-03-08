"""
WardenIPS - Minecraft Plugin
===============================

Minecraft sunucu log dosyasini (latest.log) izleyerek
botnet ve DDoS saldirilarini tespit eder.

Tespit edilen kaliplar:
  - Oyuncu baglantilari (login)
  - Oyuncu baglantilarinin kesilmesi (disconnect/lost connection)
  - Hizli art arda baglanti denemeleri (botnet isareti)
  - Gecersiz paket/protokol hatalari
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from wardenips.core.modeels import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.plugins.base_plugin import BasePlugin


# ══════════════════════════════════════════════════════════
#  Minecraft Log Regex Kaliplari
# ══════════════════════════════════════════════════════════

# [14:30:22] [Server thread/INFO]: PlayerName[/203.0.113.50:12345] logged in
_RE_LOGIN = re.compile(
    r"\[.*?INFO\].*?:\s+(\S+)\[/(\d+\.\d+\.\d+\.\d+):\d+\]\s+logged in"
)

# [14:30:22] [Server thread/INFO]: PlayerName lost connection: Disconnected
_RE_DISCONNECT = re.compile(
    r"\[.*?INFO\].*?:\s+(\S+)\s+lost connection:\s+(.*)"
)

# [14:30:22] [Server thread/INFO]: /203.0.113.50:12345 lost connection: ...
_RE_IP_DISCONNECT = re.compile(
    r"\[.*?INFO\].*?:\s+/(\d+\.\d+\.\d+\.\d+):\d+\s+lost connection:\s+(.*)"
)

# [14:30:22] [Server thread/WARN]: Failed to handle packet for /203.0.113.50:12345
_RE_FAILED_PACKET = re.compile(
    r"\[.*?WARN\].*?Failed to handle packet for /(\d+\.\d+\.\d+\.\d+)"
)

# [14:30:22] [Server thread/INFO]: com.mojang.authlib.GameProfile ... (/203.0.113.50) ...
_RE_GAMEPROFILE_LOGIN = re.compile(
    r"GameProfile\{.*?name='?(\S+?)'?}\s*\(/(\d+\.\d+\.\d+\.\d+)\)"
)

# Minecraft log tarih formati: [14:30:22]
_RE_MC_TIMESTAMP = re.compile(
    r"\[(\d{2}:\d{2}:\d{2})\]"
)


class MinecraftPlugin(BasePlugin):
    """
    Minecraft botnet/DDoS tespit plugini.

    latest.log dosyasindaki baglanti eventslarini
    regex ile ayristirir ve risk skoru hesaplar.

    Hizli art arda baglanti denemeleri botnet isareti olarak
    degerlendirilir.
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
        """latest.log satirini ayristirir."""

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

        # 2. GameProfile baglantisi (bazi server versiyonlari)
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

        # 3. IP ile baglanti kopma (nick olmadan)
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

        # Bu satir Minecraft baglantisi ile ilgili degil
        return None

    async def calculate_risk(self, event: ConnectionEvent, context: dict) -> int:
        """
        Minecraft eventslari icin risk skoru hesaplar.

        Faktorler:
          - Olay tipi (failed_packet > ip_disconnect > login)
          - Son N saniyedeki baglanti sayisi (hizli = botnet)
          - Datacenter IP mi?
          - Oyuncu ismi yok mu? (bot isareti)
        """
        score = 0
        event_type = event.details.get("event_type", "")
        event_count = context.get("event_count", 0)
        is_datacenter = context.get("is_datacenter", False)

        # Olay tipi bazli taban skor
        if event_type == "failed_packet":
            score += 30  # Gecersiz paket = saldiri isareti
        elif event_type == "ip_disconnect":
            score += 15  # Hizli baglan/kopar = bot
        elif event_type == "login":
            score += 5   # Normal giris = dusuk risk

        # Hizli baglanti denemeleri (botnet kalıbı)
        # Her baglanti 10 puan ekler, boylece kisa surede cok sayida baglanti yapilinca skor artar
        if event_count > 0:
            score += min(event_count * 10, 60)

        # Datacenter IP
        if is_datacenter:
            score += 20

        # Oyuncu ismi yoksa (bot)
        if not event.player_name:
            score += 10

        return min(score, 100)

    def _parse_timestamp(self, line: str) -> datetime:
        """Minecraft log tarih formatini ayristirir."""
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
