"""
WardenIPS - Async Database Manager
============================================

Record fields:
  - Timestamp
  - Hash'ed IP
  - Player name / username
  - Connection type (connection_type: ssh, minecraft, etc.)
  - ASN number (asn_number)
  - ASN organization name (asn_org)
  - Country code (country_code)
  - Datacenter status (is_datacenter)
  - Risk score (risk_score)
  - Threat level (threat_level)
  - Details (details — JSON)

All operations are fully asynchronous (aiosqlite).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite

from wardenips.core.exceptions import WardenDatabaseError
from wardenips.core.ip_hasher import IPHasher
from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# Database schema version — used for migrations in the future
_SCHEMA_VERSION = 1

# Table creation SQL queries
_CREATE_TABLES_SQL = """
-- Connection events table (main table)
CREATE TABLE IF NOT EXISTS connection_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    ip_hash         TEXT    NOT NULL,
    player_name     TEXT,
    connection_type TEXT    NOT NULL DEFAULT 'unknown',
    asn_number      INTEGER,
    asn_org         TEXT,
    country_code    TEXT,
    is_datacenter   INTEGER NOT NULL DEFAULT 0,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    threat_level    TEXT    NOT NULL DEFAULT 'NONE',
    details         TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_events_ip_hash
    ON connection_events(ip_hash);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON connection_events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_risk_score
    ON connection_events(risk_score);

CREATE INDEX IF NOT EXISTS idx_events_connection_type
    ON connection_events(connection_type);

-- Ban history table
CREATE TABLE IF NOT EXISTS ban_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_hash         TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    ban_duration    INTEGER NOT NULL DEFAULT 0,
    banned_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_bans_ip_hash
    ON ban_history(ip_hash);

CREATE INDEX IF NOT EXISTS idx_bans_active
    ON ban_history(is_active);

-- Schema version table (for migrations)
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"""


class DatabaseManager:
    """
    Asenkron GDPR uyumlu SQLite veritabani yoneticisi.

    All I/O operations are asynchronous (aiosqlite).
    IP addresses are hashed using IPHasher and stored.
    Correlation analysis is possible but IP addresses cannot be retrieved.

    Usage:
        db = await DatabaseManager.create(config)
        await db.log_event(event, ip_hash="a3f2b8c1...")
        recent = await db.get_recent_events_by_ip("a3f2b8c1...", minutes=5)
        await db.close()
    """

    def __init__(self) -> None:
        self._db: Optional[aiosqlite.Connection] = None
        self._db_path: Optional[Path] = None
        self._lock: asyncio.Lock = asyncio.Lock()

    # ── Factory ──

    @classmethod
    async def create(cls, config) -> DatabaseManager:
        """
        Veritabani baglantisini acar, semalari olusturur ve
        DatabaseManager dondurur.

        Args:
            config: ConfigManager instance.

        Returns:
            Hazir DatabaseManager.

        Raises:
            WardenDatabaseError: Veritabani olusturulamazsa.
        """
        instance = cls()
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        """
        Veritabanini acip semalari olusturur.
        """
        db_section = config.get_section("database")
        sqlite_section = db_section.get("sqlite", {})
        db_path_str = sqlite_section.get("path", "/var/lib/wardenips/warden.db")
        self._db_path = Path(db_path_str)

        # Ust dizinleri olustur
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Sudo olmadan calistirilmissa lokal bir klasore fallback yapalim
            fallback_dir = Path.cwd() / "data"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            self._db_path = fallback_dir / "warden.db"
            
            logger.warning(
                "Permission denied for '%s'. Falling back to local directory: '%s'. "
                "Did you forget to use 'sudo'?",
                db_path_str, self._db_path
            )
        except Exception as exc:
            raise WardenDatabaseError(
                f"Failed to create database directory: "
                f"{self._db_path.parent} - {exc}"
            )

        try:
            self._db = await aiosqlite.connect(str(self._db_path))
            # WAL modeu — okuma ve yazma islemleri birbirini engellemez
            await self._db.execute("PRAGMA journal_mode=WAL")
            # Foreign key destegi
            await self._db.execute("PRAGMA foreign_keys=ON")
            # Semalari olustur
            await self._db.executescript(_CREATE_TABLES_SQL)
            # Sema versiyonunu kaydet
            await self._ensure_schema_version()
            await self._db.commit()
            logger.info(
                "Database successfully initialized: %s", self._db_path
            )
        except Exception as exc:
            raise WardenDatabaseError(
                f"Database could not be started: {exc}"
            ) from exc

    async def _ensure_schema_version(self) -> None:
        """Checks or creates the schema version."""
        async with self._db.execute(
            "SELECT COUNT(*) FROM schema_version"
        ) as cursor:
            row = await cursor.fetchone()
            if row[0] == 0:
                await self._db.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (_SCHEMA_VERSION,),
                )
            else:
                async with self._db.execute(
                    "SELECT version FROM schema_version LIMIT 1"
                ) as vcursor:
                    vrow = await vcursor.fetchone()
                    current = vrow[0]
                    if current != _SCHEMA_VERSION:
                        logger.warning(
                            "Sema versiyonu uyumsuz! "
                            "Mevcut: %d, Beklenen: %d. "
                            "Migration gerekebilir.",
                            current, _SCHEMA_VERSION,
                        )

    # ── Olay Kaydi ──

    async def log_event(self, event: ConnectionEvent, ip_hash: str) -> int:
        """
        Logs a connection event to the database.

        IP addresses are replaced with hashed IP addresses (GDPR-compliant).

        Args:
            event:   ConnectionEvent object.
            ip_hash: Hash generated by IPHasher.hash_ip().

        Returns:
            ID of the added record.

        Raises:
            WardenDatabaseError: Write error.
        """
        async with self._lock:
            try:
                details_json = json.dumps(
                    event.details, ensure_ascii=False
                ) if event.details else None

                async with self._db.execute(
                    """
                    INSERT INTO connection_events
                        (timestamp, ip_hash, player_name, connection_type,
                         asn_number, asn_org, country_code, is_datacenter,
                         risk_score, threat_level, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.timestamp.isoformat(),
                        ip_hash,
                        event.player_name,
                        event.connection_type.value,
                        event.asn_number,
                        event.asn_org,
                        event.country_code,
                        1 if event.is_datacenter else 0,
                        event.risk_score,
                        event.threat_level.name,
                        details_json,
                    ),
                ) as cursor:
                    await self._db.commit()
                    row_id = cursor.lastrowid
                    logger.debug(
                        "Event logged ID=%d, IP_HASH=%s..., Risk=%d",
                        row_id, ip_hash[:12], event.risk_score,
                    )
                    return row_id

            except Exception as exc:
                raise WardenDatabaseError(
                    f"Event logging failed: {exc}"
                ) from exc

    # ── Ban Gecmisi ──

    async def log_ban(
        self,
        ip_hash: str,
        reason: str,
        risk_score: int,
        ban_duration: int = 0,
    ) -> int:
        """
        Logs a ban operation to the database.

        Args:
            ip_hash:      Hashed IP.
            reason:       Ban reason.
            risk_score:   Risk score that triggered the ban.
            ban_duration: Ban duration (seconds). 0 = permanent.

        Returns:
            Ban record ID.
        """
        async with self._lock:
            try:
                now = datetime.utcnow()
                expires_at = None
                if ban_duration > 0:
                    expires_at = (
                        now + timedelta(seconds=ban_duration)
                    ).isoformat()

                async with self._db.execute(
                    """
                    INSERT INTO ban_history
                        (ip_hash, reason, risk_score, ban_duration,
                         banned_at, expires_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        ip_hash,
                        reason,
                        risk_score,
                        ban_duration,
                        now.isoformat(),
                        expires_at,
                    ),
                ) as cursor:
                    await self._db.commit()
                    row_id = cursor.lastrowid
                    logger.info(
                        "Ban logged ID=%d, IP_HASH=%s..., "
                        "Reason='%s', Duration=%ds",
                        row_id, ip_hash[:12], reason, ban_duration,
                    )
                    return row_id

            except Exception as exc:
                raise WardenDatabaseError(
                    f"Ban logging failed: {exc}"
                ) from exc

    # ── Sorgu Metodlari ──

    async def get_recent_events_by_ip(
        self,
        ip_hash: str,
        minutes: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Returns the last N minutes of events for a given hashed IP.

        This method is used to detect repeated attacks.

        Args:
            ip_hash: Hashed IP address.
            minutes: Time window in minutes.

        Returns:
            List of event records.
        """
        cutoff = (
            datetime.utcnow() - timedelta(minutes=minutes)
        ).isoformat()

        try:
            async with self._db.execute(
                """
                SELECT id, timestamp, ip_hash, player_name,
                       connection_type, asn_number, asn_org,
                       country_code, is_datacenter, risk_score,
                       threat_level, details
                FROM connection_events
                WHERE ip_hash = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                """,
                (ip_hash, cutoff),
            ) as cursor:
                rows = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in rows]

        except Exception as exc:
            logger.error("Event query failed: %s", exc)
            return []

    async def get_event_count_by_ip(
        self,
        ip_hash: str,
        minutes: int = 5,
    ) -> int:
        """
        Returns the count of events for a given hashed IP in the last N minutes.

        Args:
            ip_hash: Hashed IP address.
            minutes: Time window in minutes.

        Returns:
            Olay sayisi.
        """
        cutoff = (
            datetime.utcnow() - timedelta(minutes=minutes)
        ).isoformat()

        try:
            async with self._db.execute(
                """
                SELECT COUNT(*) FROM connection_events
                WHERE ip_hash = ? AND timestamp >= ?
                """,
                (ip_hash, cutoff),
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0
        except Exception as exc:
            logger.error("Event count query failed: %s", exc)
            return 0

    async def is_ip_banned(self, ip_hash: str) -> bool:
        """
        Checks if a hashed IP has an active ban.

        Expired bans are automatically disabled.

        Args:
            ip_hash: Hashed IP.

        Returns:
            True ise IP banlı.
        """
        now = datetime.utcnow().isoformat()

        try:
            # Durationsi dolmus banlari pasifle
            await self._db.execute(
                """
                UPDATE ban_history
                SET is_active = 0
                WHERE is_active = 1
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                """,
                (now,),
            )
            await self._db.commit()

            # Aktif ban kontrolu
            async with self._db.execute(
                """
                SELECT COUNT(*) FROM ban_history
                WHERE ip_hash = ? AND is_active = 1
                """,
                (ip_hash,),
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] > 0 if row else False

        except Exception as exc:
            logger.error("Ban kontrol sorgusu basarisiz: %s", exc)
            return False

    # ── Istatistikler ──

    async def get_stats(self) -> Dict[str, Any]:
        """
        Returns database statistics.

        Returns:
            Total events count, total bans count, active bans count, etc.
        """
        stats: Dict[str, Any] = {}

        try:
            async with self._db.execute(
                "SELECT COUNT(*) FROM connection_events"
            ) as cursor:
                row = await cursor.fetchone()
                stats["total_events"] = row[0]

            async with self._db.execute(
                "SELECT COUNT(*) FROM ban_history"
            ) as cursor:
                row = await cursor.fetchone()
                stats["total_bans"] = row[0]

            async with self._db.execute(
                "SELECT COUNT(*) FROM ban_history WHERE is_active = 1"
            ) as cursor:
                row = await cursor.fetchone()
                stats["active_bans"] = row[0]

            stats["db_path"] = str(self._db_path)

        except Exception as exc:
            logger.error("Statistics query failed: %s", exc)

        return stats

    # ── Resource Management ──

    async def close(self) -> None:
        """Closes the database connection safely."""
        if self._db:
            await self._db.close()
            self._db = None
            logger.info("Database connection closed.")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __repr__(self) -> str:
        return f"<DatabaseManager path={self._db_path}>"
