"""
WardenIPS - Async Database Manager
============================================

Record fields:
  - Timestamp
    - Source IP
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
from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# Database schema version — used for migrations in the future
_SCHEMA_VERSION = 4

# Table creation SQL queries
_CREATE_TABLES_SQL = """
-- Connection events table (main table)
CREATE TABLE IF NOT EXISTS connection_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    source_ip       TEXT    NOT NULL,
    player_name     TEXT,
    connection_type TEXT    NOT NULL DEFAULT 'unknown',
    asn_number      INTEGER,
    asn_org         TEXT,
    is_suspicious_asn INTEGER NOT NULL DEFAULT 0,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    threat_level    TEXT    NOT NULL DEFAULT 'NONE',
    details         TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_events_source_ip
    ON connection_events(source_ip);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON connection_events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_risk_score
    ON connection_events(risk_score);

CREATE INDEX IF NOT EXISTS idx_events_connection_type
    ON connection_events(connection_type);

-- Ban history table
CREATE TABLE IF NOT EXISTS ban_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip       TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    ban_duration    INTEGER NOT NULL DEFAULT 0,
    banned_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_bans_source_ip
    ON ban_history(source_ip);

CREATE INDEX IF NOT EXISTS idx_bans_active
    ON ban_history(is_active);

-- Admin users table
CREATE TABLE IF NOT EXISTS admin_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at   TEXT,
    last_login_ip   TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_users_active
    ON admin_users(is_active);

-- Audit log for operator actions
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_username  TEXT,
    action          TEXT NOT NULL,
    target          TEXT,
    ip_address      TEXT,
    details_json    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at
    ON audit_log(created_at);

-- Schema version table (for migrations)
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"""


class DatabaseManager:
    """
    Asenkron SQLite veritabani yoneticisi.

    All I/O operations are asynchronous (aiosqlite).
    IP addresses are stored as source IP values.

    Usage:
        db = await DatabaseManager.create(config)
        await db.log_event(event, source_ip="203.0.113.7")
        recent = await db.get_recent_events_by_ip("203.0.113.7", minutes=5)
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
                        if current < 3:
                            await self._migrate_v2_to_v3_source_ip()
                        await self._db.execute(
                            "UPDATE schema_version SET version = ?",
                            (_SCHEMA_VERSION,),
                        )

    async def _migrate_v2_to_v3_source_ip(self) -> None:
        """Renames legacy ip_hash columns to source_ip and refreshes indexes."""

        async def _has_column(table: str, column: str) -> bool:
            async with self._db.execute(f"PRAGMA table_info({table})") as cursor:
                rows = await cursor.fetchall()
                return any(str(row[1]) == column for row in rows)

        # Migrate connection_events.ip_hash -> source_ip
        has_source_ip = await _has_column("connection_events", "source_ip")
        has_ip_hash = await _has_column("connection_events", "ip_hash")
        if (not has_source_ip) and has_ip_hash:
            await self._db.execute(
                "ALTER TABLE connection_events RENAME COLUMN ip_hash TO source_ip"
            )

        # Migrate ban_history.ip_hash -> source_ip
        has_source_ip = await _has_column("ban_history", "source_ip")
        has_ip_hash = await _has_column("ban_history", "ip_hash")
        if (not has_source_ip) and has_ip_hash:
            await self._db.execute(
                "ALTER TABLE ban_history RENAME COLUMN ip_hash TO source_ip"
            )

        # Refresh legacy index names
        await self._db.execute("DROP INDEX IF EXISTS idx_events_ip_hash")
        await self._db.execute("DROP INDEX IF EXISTS idx_bans_ip_hash")
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON connection_events(source_ip)"
        )
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_bans_source_ip ON ban_history(source_ip)"
        )

    # ── Olay Kaydi ──

    async def log_event(self, event: ConnectionEvent, source_ip: str) -> int:
        """
        Logs a connection event to the database.

        Args:
            event:   ConnectionEvent object.
            source_ip: Source IP address.

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
                        (timestamp, source_ip, player_name, connection_type,
                         asn_number, asn_org, is_suspicious_asn,
                         risk_score, threat_level, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.timestamp.isoformat(),
                        source_ip,
                        event.player_name,
                        event.connection_type.value,
                        event.asn_number,
                        event.asn_org,
                        1 if event.is_suspicious_asn else 0,
                        event.risk_score,
                        event.threat_level.name,
                        details_json,
                    ),
                ) as cursor:
                    await self._db.commit()
                    row_id = cursor.lastrowid
                    logger.debug(
                        "Event logged ID=%d, IP=%s, Risk=%d",
                        row_id, source_ip, event.risk_score,
                    )
                    return row_id

            except Exception as exc:
                raise WardenDatabaseError(
                    f"Event logging failed: {exc}"
                ) from exc

    # ── Ban Gecmisi ──

    async def log_ban(
        self,
        source_ip: str,
        reason: str,
        risk_score: int,
        ban_duration: int = 0,
    ) -> int:
        """
        Logs a ban operation to the database.

        Args:
            source_ip:    Source IP.
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
                        (source_ip, reason, risk_score, ban_duration,
                         banned_at, expires_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        source_ip,
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
                        "Ban logged ID=%d, IP=%s, "
                        "Reason='%s', Duration=%ds",
                        row_id, source_ip, reason, ban_duration,
                    )
                    return row_id

            except Exception as exc:
                raise WardenDatabaseError(
                    f"Ban logging failed: {exc}"
                ) from exc

    # ── Sorgu Metodlari ──

    async def get_recent_events_by_ip(
        self,
        source_ip: str,
        minutes: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Returns the last N minutes of events for a given source IP.

        This method is used to detect repeated attacks.

        Args:
            source_ip: Source IP address.
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
                  SELECT id, timestamp, source_ip, player_name,
                       connection_type, asn_number, asn_org,
                       is_suspicious_asn, risk_score,
                       threat_level, details
                FROM connection_events
                  WHERE source_ip = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                """,
                (source_ip, cutoff),
            ) as cursor:
                rows = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in rows]

        except Exception as exc:
            logger.error("Event query failed: %s", exc)
            return []

    async def get_event_count_by_ip(
        self,
        source_ip: str,
        minutes: int = 5,
        connection_type: Optional[str] = None,
        reset_on_success: bool = False,
        success_event_types: Optional[List[str]] = None,
    ) -> int:
        """
        Returns the count of events for a given source IP in the last N minutes.

        Args:
            source_ip: Source IP address.
            minutes: Time window in minutes.

        Returns:
            Olay sayisi.
        """
        cutoff = (
            datetime.utcnow() - timedelta(minutes=minutes)
        ).isoformat()

        try:
            effective_cutoff = cutoff
            success_patterns = [
                f'%"event_type": "{event_type}"%'
                for event_type in (success_event_types or [])
            ]

            if reset_on_success and success_patterns:
                latest_query = """
                    SELECT MAX(timestamp) FROM connection_events
                    WHERE source_ip = ? AND timestamp >= ?
                """
                latest_params: list[Any] = [source_ip, cutoff]
                if connection_type:
                    latest_query += " AND connection_type = ?"
                    latest_params.append(connection_type)
                latest_query += " AND (" + " OR ".join(["details LIKE ?"] * len(success_patterns)) + ")"
                latest_params.extend(success_patterns)
                async with self._db.execute(latest_query, latest_params) as latest_cursor:
                    latest_row = await latest_cursor.fetchone()
                    if latest_row and latest_row[0]:
                        effective_cutoff = latest_row[0]

            count_query = """
                SELECT COUNT(*) FROM connection_events
                WHERE source_ip = ? AND timestamp >= ?
            """
            count_params: list[Any] = [source_ip, effective_cutoff]
            if connection_type:
                count_query += " AND connection_type = ?"
                count_params.append(connection_type)
            if success_patterns:
                count_query += " AND NOT (" + " OR ".join(["details LIKE ?"] * len(success_patterns)) + ")"
                count_params.extend(success_patterns)

            async with self._db.execute(count_query, count_params) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0
        except Exception as exc:
            logger.error("Event count query failed: %s", exc)
            return 0

    async def get_recent_connection_types_by_ip(
        self,
        source_ip: str,
        minutes: int = 15,
    ) -> List[str]:
        """Returns distinct recent connection types observed for a source IP."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        try:
            async with self._db.execute(
                """
                SELECT DISTINCT connection_type
                FROM connection_events
                WHERE source_ip = ? AND timestamp >= ?
                """,
                (source_ip, cutoff),
            ) as cursor:
                rows = await cursor.fetchall()
                return [str(row[0]) for row in rows if row and row[0]]
        except Exception as exc:
            logger.error("Connection type query failed: %s", exc)
            return []

    async def get_total_ban_count_by_ip(self, source_ip: str) -> int:
        """Returns historical ban count for a source IP."""
        try:
            async with self._db.execute(
                """
                SELECT COUNT(*)
                FROM ban_history
                WHERE source_ip = ?
                """,
                (source_ip,),
            ) as cursor:
                row = await cursor.fetchone()
                return int(row[0]) if row else 0
        except Exception as exc:
            logger.error("Ban count query failed: %s", exc)
            return 0

    async def is_ip_banned(self, source_ip: str) -> bool:
        """
        Checks if a source IP has an active ban.

        Expired bans are automatically disabled.

        Args:
            source_ip: Source IP.

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
                WHERE source_ip = ? AND is_active = 1
                """,
                (source_ip,),
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

    # ── Admin Maintenance ──

    async def clear_events(self) -> int:
        """Deletes all connection event records and returns the number removed."""
        async with self._lock:
            try:
                async with self._db.execute(
                    "DELETE FROM connection_events"
                ) as cursor:
                    await self._db.commit()
                    return cursor.rowcount if cursor.rowcount is not None else 0
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Failed to clear event history: {exc}"
                ) from exc

    async def clear_ban_history(self) -> int:
        """Deletes all ban history records and returns the number removed."""
        async with self._lock:
            try:
                async with self._db.execute(
                    "DELETE FROM ban_history"
                ) as cursor:
                    await self._db.commit()
                    return cursor.rowcount if cursor.rowcount is not None else 0
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Failed to clear ban history: {exc}"
                ) from exc

    async def deactivate_all_bans(self) -> int:
        """Marks every active ban as inactive and returns the number updated."""
        async with self._lock:
            try:
                async with self._db.execute(
                    """
                    UPDATE ban_history
                    SET is_active = 0
                    WHERE is_active = 1
                    """
                ) as cursor:
                    await self._db.commit()
                    return cursor.rowcount if cursor.rowcount is not None else 0
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Failed to deactivate active bans: {exc}"
                ) from exc

    async def deactivate_ban_by_ip(self, source_ip: str) -> int:
        """Marks active bans for a specific source IP as inactive."""
        async with self._lock:
            try:
                async with self._db.execute(
                    """
                    UPDATE ban_history
                    SET is_active = 0
                    WHERE source_ip = ? AND is_active = 1
                    """,
                    (source_ip,),
                ) as cursor:
                    await self._db.commit()
                    return cursor.rowcount if cursor.rowcount is not None else 0
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Failed to deactivate ban record: {exc}"
                ) from exc


    # ── Admin Auth and Audit ──

    async def has_admin_users(self) -> bool:
        async with self._db.execute(
            "SELECT COUNT(*) FROM admin_users WHERE is_active = 1"
        ) as cursor:
            row = await cursor.fetchone()
            return bool(row and row[0] > 0)

    async def get_admin_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        async with self._db.execute(
            """
            SELECT id, username, password_hash, totp_secret, totp_enabled,
                   is_active, created_at, updated_at, last_login_at, last_login_ip
            FROM admin_users
            WHERE username = ? AND is_active = 1
            LIMIT 1
            """,
            (username,),
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    async def create_admin_user(
        self,
        username: str,
        password_hash: str,
        totp_secret: str,
        totp_enabled: bool = True,
    ) -> int:
        async with self._lock:
            async with self._db.execute(
                """
                INSERT INTO admin_users
                    (username, password_hash, totp_secret, totp_enabled, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, datetime('now'), datetime('now'))
                """,
                (username, password_hash, totp_secret, 1 if totp_enabled else 0),
            ) as cursor:
                await self._db.commit()
                return cursor.lastrowid

    async def record_admin_login(self, username: str, client_ip: str) -> None:
        async with self._lock:
            await self._db.execute(
                """
                UPDATE admin_users
                SET last_login_at = datetime('now'),
                    last_login_ip = ?,
                    updated_at = datetime('now')
                WHERE username = ?
                """,
                (client_ip, username),
            )
            await self._db.commit()

    async def log_audit_event(
        self,
        action: str,
        actor_username: Optional[str] = None,
        target: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> int:
        async with self._lock:
            details_json = json.dumps(details, ensure_ascii=False) if details else None
            async with self._db.execute(
                """
                INSERT INTO audit_log
                    (actor_username, action, target, ip_address, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (actor_username, action, target, ip_address, details_json),
            ) as cursor:
                await self._db.commit()
                return cursor.lastrowid

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
