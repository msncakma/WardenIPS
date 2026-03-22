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
from typing import Any, Dict, List, Optional, Set

import aiosqlite

from wardenips.core.exceptions import WardenDatabaseError
from wardenips.core.models import ConnectionEvent, ConnectionType, ThreatLevel
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# Database schema version — used for migrations in the future
_SCHEMA_VERSION = 10

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

CREATE INDEX IF NOT EXISTS idx_events_connection_type_ts
    ON connection_events(connection_type, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_player_ts
    ON connection_events(player_name, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_source_ip_ts
    ON connection_events(source_ip, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_authme_ip_ts
    ON connection_events(source_ip, timestamp)
    WHERE connection_type = 'authme';

CREATE INDEX IF NOT EXISTS idx_events_authme_player_ts
    ON connection_events(player_name, timestamp)
    WHERE connection_type = 'authme';

CREATE INDEX IF NOT EXISTS idx_events_missing_asn_scan
    ON connection_events(id)
    WHERE asn_number IS NULL AND asn_org IS NULL;

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
    is_owner        INTEGER NOT NULL DEFAULT 0,
    display_name    TEXT,
    created_by      TEXT,
    disabled_reason TEXT,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at TEXT,
    locked_until    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at   TEXT,
    last_login_ip   TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_users_active
    ON admin_users(is_active);

CREATE INDEX IF NOT EXISTS idx_admin_users_owner
    ON admin_users(is_owner);

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

-- RBAC roles
CREATE TABLE IF NOT EXISTS auth_roles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    role_code       TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    is_system       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_permissions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node            TEXT NOT NULL UNIQUE,
    description     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_role_permissions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id         INTEGER NOT NULL,
    permission_id   INTEGER NOT NULL,
    effect          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(role_id, permission_id),
    FOREIGN KEY(role_id) REFERENCES auth_roles(id) ON DELETE CASCADE,
    FOREIGN KEY(permission_id) REFERENCES auth_permissions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_role_permissions_role
    ON auth_role_permissions(role_id);

CREATE TABLE IF NOT EXISTS auth_user_roles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    role_id         INTEGER NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, role_id),
    FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES auth_roles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_user_roles_user
    ON auth_user_roles(user_id);

CREATE TABLE IF NOT EXISTS auth_user_permissions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    permission_id   INTEGER NOT NULL,
    effect          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, permission_id),
    FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    FOREIGN KEY(permission_id) REFERENCES auth_permissions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_user_permissions_user
    ON auth_user_permissions(user_id);

CREATE TABLE IF NOT EXISTS auth_invite_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT NOT NULL UNIQUE,
    created_by      TEXT,
    note            TEXT,
    max_uses        INTEGER NOT NULL DEFAULT 1,
    used_count      INTEGER NOT NULL DEFAULT 0,
    expires_at      TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1,
    role_codes_json TEXT,
    permission_nodes_json TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_auth_invite_active
    ON auth_invite_tokens(is_active, expires_at);

CREATE TABLE IF NOT EXISTS auth_query_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_username  TEXT,
    endpoint        TEXT NOT NULL,
    query_json      TEXT,
    result_count    INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    ip_address      TEXT,
    user_agent      TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_auth_query_logs_created
    ON auth_query_logs(created_at);

-- Minecraft observe-only burst anomalies
CREATE TABLE IF NOT EXISTS minecraft_burst_alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    source_ip       TEXT    NOT NULL,
    event_count     INTEGER NOT NULL,
    window_seconds  INTEGER NOT NULL,
    unique_ip_count INTEGER NOT NULL DEFAULT 1,
    plugin_name     TEXT    NOT NULL DEFAULT 'minecraft',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mc_burst_timestamp
    ON minecraft_burst_alerts(timestamp);

CREATE INDEX IF NOT EXISTS idx_mc_burst_source_ip
    ON minecraft_burst_alerts(source_ip);

-- Minecraft watchlist entries
CREATE TABLE IF NOT EXISTS minecraft_watchlist (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    player_name     TEXT    NOT NULL,
    reason          TEXT,
    actor_username  TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mc_watchlist_player_active
    ON minecraft_watchlist(player_name, is_active);

CREATE INDEX IF NOT EXISTS idx_mc_watchlist_created
    ON minecraft_watchlist(created_at);

-- Persistent Minecraft player intel cache (local-first)
CREATE TABLE IF NOT EXISTS minecraft_player_cache (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    player_name           TEXT    NOT NULL UNIQUE,
    email                 TEXT,
    uuid                  TEXT,
    ip                    TEXT,
    creation_ip           TEXT,
    creation_date         TEXT,
    last_login            TEXT,
    reg_ip                TEXT,
    is_verified           INTEGER,
    duplicate_email_count INTEGER NOT NULL DEFAULT 0,
    source                TEXT    NOT NULL DEFAULT 'mysql',
    updated_at            TEXT    NOT NULL DEFAULT (datetime('now')),
    created_at            TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mc_player_cache_email
    ON minecraft_player_cache(email);

CREATE INDEX IF NOT EXISTS idx_mc_player_cache_ip
    ON minecraft_player_cache(ip);

CREATE INDEX IF NOT EXISTS idx_mc_player_cache_updated
    ON minecraft_player_cache(updated_at);

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
                        if current < 5:
                            await self._migrate_v4_to_v5_minecraft_alerts()
                        if current < 6:
                            await self._migrate_v5_to_v6_minecraft_watchlist()
                        if current < 7:
                            await self._migrate_v6_to_v7_minecraft_player_cache()
                        if current < 8:
                            await self._migrate_v7_to_v8_authme_indexes()
                        if current < 9:
                            await self._migrate_v8_to_v9_missing_asn_index()
                        if current < 10:
                            await self._migrate_v9_to_v10_rbac_auth()
                        await self._db.execute(
                            "UPDATE schema_version SET version = ?",
                            (_SCHEMA_VERSION,),
                        )

    async def _migrate_v9_to_v10_rbac_auth(self) -> None:
        """Adds RBAC tables, invite/query logs, and admin account ownership columns."""

        async def _has_column(table: str, column: str) -> bool:
            async with self._db.execute(f"PRAGMA table_info({table})") as cursor:
                rows = await cursor.fetchall()
                return any(str(row[1]) == column for row in rows)

        admin_columns = {
            "is_owner": "INTEGER NOT NULL DEFAULT 0",
            "display_name": "TEXT",
            "created_by": "TEXT",
            "disabled_reason": "TEXT",
            "failed_login_count": "INTEGER NOT NULL DEFAULT 0",
            "last_failed_login_at": "TEXT",
            "locked_until": "TEXT",
        }
        for column_name, column_type in admin_columns.items():
            if not await _has_column("admin_users", column_name):
                await self._db.execute(
                    f"ALTER TABLE admin_users ADD COLUMN {column_name} {column_type}"
                )

        await self._db.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_admin_users_owner
                ON admin_users(is_owner);

            CREATE TABLE IF NOT EXISTS auth_roles (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                role_code       TEXT NOT NULL UNIQUE,
                display_name    TEXT NOT NULL,
                is_system       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS auth_permissions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                node            TEXT NOT NULL UNIQUE,
                description     TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS auth_role_permissions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                role_id         INTEGER NOT NULL,
                permission_id   INTEGER NOT NULL,
                effect          INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(role_id, permission_id),
                FOREIGN KEY(role_id) REFERENCES auth_roles(id) ON DELETE CASCADE,
                FOREIGN KEY(permission_id) REFERENCES auth_permissions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_auth_role_permissions_role
                ON auth_role_permissions(role_id);

            CREATE TABLE IF NOT EXISTS auth_user_roles (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL,
                role_id         INTEGER NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_id, role_id),
                FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
                FOREIGN KEY(role_id) REFERENCES auth_roles(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_auth_user_roles_user
                ON auth_user_roles(user_id);

            CREATE TABLE IF NOT EXISTS auth_user_permissions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL,
                permission_id   INTEGER NOT NULL,
                effect          INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_id, permission_id),
                FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
                FOREIGN KEY(permission_id) REFERENCES auth_permissions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_auth_user_permissions_user
                ON auth_user_permissions(user_id);

            CREATE TABLE IF NOT EXISTS auth_invite_tokens (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash      TEXT NOT NULL UNIQUE,
                created_by      TEXT,
                note            TEXT,
                max_uses        INTEGER NOT NULL DEFAULT 1,
                used_count      INTEGER NOT NULL DEFAULT 0,
                expires_at      TEXT,
                is_active       INTEGER NOT NULL DEFAULT 1,
                role_codes_json TEXT,
                permission_nodes_json TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_auth_invite_active
                ON auth_invite_tokens(is_active, expires_at);

            CREATE TABLE IF NOT EXISTS auth_query_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_username  TEXT,
                endpoint        TEXT NOT NULL,
                query_json      TEXT,
                result_count    INTEGER NOT NULL DEFAULT 0,
                duration_ms     INTEGER NOT NULL DEFAULT 0,
                ip_address      TEXT,
                user_agent      TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_auth_query_logs_created
                ON auth_query_logs(created_at);
            """
        )

        await self._seed_rbac_defaults()

        # Ensure there is at least one owner account for bootstrap compatibility.
        async with self._db.execute(
            "SELECT COUNT(*) FROM admin_users WHERE is_active = 1 AND is_owner = 1"
        ) as cursor:
            owner_row = await cursor.fetchone()
            owner_count = int(owner_row[0] or 0) if owner_row else 0

        if owner_count == 0:
            async with self._db.execute(
                "SELECT id, username FROM admin_users WHERE is_active = 1 ORDER BY id ASC LIMIT 1"
            ) as cursor:
                first_user = await cursor.fetchone()
            if first_user:
                first_user_id = int(first_user[0])
                await self._db.execute(
                    "UPDATE admin_users SET is_owner = 1 WHERE id = ?",
                    (first_user_id,),
                )
                await self._assign_role_to_user_id(first_user_id, "owner")

        # Assign admin role to remaining active users without roles.
        async with self._db.execute(
            """
            SELECT u.id
            FROM admin_users u
            WHERE u.is_active = 1
              AND NOT EXISTS (
                SELECT 1 FROM auth_user_roles ur WHERE ur.user_id = u.id
              )
            """
        ) as cursor:
            rows = await cursor.fetchall()
        for row in rows:
            await self._assign_role_to_user_id(int(row[0]), "admin")

    async def _migrate_v8_to_v9_missing_asn_index(self) -> None:
        """Adds index for efficient missing-ASN backfill scans."""
        await self._db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_missing_asn_scan
                ON connection_events(id)
                WHERE asn_number IS NULL AND asn_org IS NULL
            """
        )

    async def _migrate_v7_to_v8_authme_indexes(self) -> None:
        """Adds partial indexes to accelerate AuthMe correlation queries."""
        await self._db.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_events_authme_ip_ts
                ON connection_events(source_ip, timestamp)
                WHERE connection_type = 'authme';

            CREATE INDEX IF NOT EXISTS idx_events_authme_player_ts
                ON connection_events(player_name, timestamp)
                WHERE connection_type = 'authme';
            """
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

    async def _migrate_v4_to_v5_minecraft_alerts(self) -> None:
        """Adds minecraft burst alert table and analytics indexes."""
        await self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS minecraft_burst_alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                source_ip       TEXT    NOT NULL,
                event_count     INTEGER NOT NULL,
                window_seconds  INTEGER NOT NULL,
                unique_ip_count INTEGER NOT NULL DEFAULT 1,
                plugin_name     TEXT    NOT NULL DEFAULT 'minecraft',
                created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_mc_burst_timestamp
                ON minecraft_burst_alerts(timestamp);

            CREATE INDEX IF NOT EXISTS idx_mc_burst_source_ip
                ON minecraft_burst_alerts(source_ip);

            CREATE INDEX IF NOT EXISTS idx_events_connection_type_ts
                ON connection_events(connection_type, timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_player_ts
                ON connection_events(player_name, timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_source_ip_ts
                ON connection_events(source_ip, timestamp);
            """
        )

    async def _migrate_v5_to_v6_minecraft_watchlist(self) -> None:
        """Adds minecraft watchlist table and indexes."""
        await self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS minecraft_watchlist (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                player_name     TEXT    NOT NULL,
                reason          TEXT,
                actor_username  TEXT,
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_mc_watchlist_player_active
                ON minecraft_watchlist(player_name, is_active);

            CREATE INDEX IF NOT EXISTS idx_mc_watchlist_created
                ON minecraft_watchlist(created_at);
            """
        )

    async def _migrate_v6_to_v7_minecraft_player_cache(self) -> None:
        """Adds persistent Minecraft player intel cache table and indexes."""
        await self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS minecraft_player_cache (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                player_name           TEXT    NOT NULL UNIQUE,
                email                 TEXT,
                uuid                  TEXT,
                ip                    TEXT,
                creation_ip           TEXT,
                creation_date         TEXT,
                last_login            TEXT,
                reg_ip                TEXT,
                is_verified           INTEGER,
                duplicate_email_count INTEGER NOT NULL DEFAULT 0,
                source                TEXT    NOT NULL DEFAULT 'mysql',
                updated_at            TEXT    NOT NULL DEFAULT (datetime('now')),
                created_at            TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_mc_player_cache_email
                ON minecraft_player_cache(email);

            CREATE INDEX IF NOT EXISTS idx_mc_player_cache_ip
                ON minecraft_player_cache(ip);

            CREATE INDEX IF NOT EXISTS idx_mc_player_cache_updated
                ON minecraft_player_cache(updated_at);
            """
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

    async def cleanup_old_connection_events(
        self,
        days: int = 30,
        connection_types: Optional[List[str]] = None,
    ) -> int:
        """Deletes old connection_events rows and returns deleted row count."""
        cutoff = (datetime.utcnow() - timedelta(days=max(int(days), 1))).isoformat()
        normalized_types = [
            str(item).strip().lower()
            for item in (connection_types or [])
            if str(item).strip()
        ]

        async with self._lock:
            try:
                if normalized_types:
                    placeholders = ",".join(["?"] * len(normalized_types))
                    query = (
                        "DELETE FROM connection_events "
                        "WHERE timestamp < ? AND LOWER(COALESCE(connection_type, '')) IN ("
                        + placeholders
                        + ")"
                    )
                    params: List[Any] = [cutoff, *normalized_types]
                else:
                    query = "DELETE FROM connection_events WHERE timestamp < ?"
                    params = [cutoff]

                cursor = await self._db.execute(query, tuple(params))
                await self._db.commit()
                deleted = int(cursor.rowcount or 0)
                if deleted > 0:
                    logger.info(
                        "Retention cleanup deleted %d old event(s) older than %d day(s).",
                        deleted,
                        max(int(days), 1),
                    )
                return deleted
            except Exception as exc:
                logger.error("Retention cleanup failed: %s", exc)
                return 0

    async def get_events_missing_asn(
        self,
        limit: int = 200,
        connection_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Returns rows that have not yet received ASN enrichment."""
        safe_limit = min(max(int(limit), 1), 5000)
        normalized_types = [
            str(item).strip().lower()
            for item in (connection_types or [])
            if str(item).strip()
        ]

        try:
            query = """
                SELECT id, source_ip, connection_type
                FROM connection_events
                WHERE asn_number IS NULL
                  AND asn_org IS NULL
                  AND COALESCE(source_ip, '') <> ''
            """
            params: List[Any] = []
            if normalized_types:
                placeholders = ",".join(["?"] * len(normalized_types))
                query += f" AND LOWER(COALESCE(connection_type, '')) IN ({placeholders})"
                params.extend(normalized_types)
            query += " ORDER BY id ASC LIMIT ?"
            params.append(safe_limit)

            async with self._db.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in rows]
        except Exception as exc:
            logger.error("Missing-ASN query failed: %s", exc)
            return []

    async def apply_event_asn_backfill(self, updates: List[Dict[str, Any]]) -> int:
        """Applies ASN enrichment updates in a single transaction."""
        if not updates:
            return 0

        payload: List[tuple[Any, Any, Any, int]] = []
        for item in updates:
            try:
                event_id = int(item.get("id"))
            except Exception:
                continue
            asn_number = item.get("asn_number")
            asn_org = item.get("asn_org")
            is_suspicious = bool(item.get("is_suspicious_asn", False))
            payload.append(
                (
                    asn_number if asn_number is not None else None,
                    str(asn_org if asn_org is not None else ""),
                    1 if is_suspicious else 0,
                    event_id,
                )
            )

        if not payload:
            return 0

        async with self._lock:
            try:
                await self._db.executemany(
                    """
                    UPDATE connection_events
                    SET asn_number = ?,
                        asn_org = ?,
                        is_suspicious_asn = ?
                    WHERE id = ?
                    """,
                    payload,
                )
                await self._db.commit()
                return len(payload)
            except Exception as exc:
                logger.error("ASN backfill apply failed: %s", exc)
                return 0

    async def mark_authme_login_failed_by_disconnect(
        self,
        source_ip: str,
        disconnect_timestamp: datetime,
        window_seconds: int = 30,
        player_name: Optional[str] = None,
        disconnect_event_type: str = "ip_disconnect",
    ) -> int:
        """Mark the latest matching AuthMe login as failed after a disconnect event.

        Returns number of updated rows (0 or 1).
        """
        if not source_ip:
            return 0

        safe_window = max(int(window_seconds), 1)
        end_ts = disconnect_timestamp
        start_ts = disconnect_timestamp - timedelta(seconds=safe_window)

        try:
            async with self._lock:
                select_sql = """
                    SELECT id, details
                    FROM connection_events
                    WHERE connection_type = 'authme'
                      AND source_ip = ?
                      AND timestamp >= ?
                      AND timestamp <= ?
                      AND COALESCE(details, '') LIKE '%"event_type": "login"%'
                      AND (
                        COALESCE(details, '') NOT LIKE '%"login_successful": false%'
                        AND COALESCE(details, '') NOT LIKE '%"login_successful":false%'
                      )
                """
                params: list[Any] = [
                    source_ip,
                    start_ts.isoformat(),
                    end_ts.isoformat(),
                ]

                normalized_player = str(player_name or "").strip().lower()
                if normalized_player:
                    select_sql += " AND LOWER(COALESCE(player_name, '')) = LOWER(?)"
                    params.append(normalized_player)

                select_sql += " ORDER BY timestamp DESC LIMIT 1"

                async with self._db.execute(select_sql, tuple(params)) as cursor:
                    row = await cursor.fetchone()
                if not row:
                    return 0

                event_id = int(row[0])
                details_raw = row[1]
                details_obj: Dict[str, Any] = {}
                if isinstance(details_raw, str) and details_raw:
                    try:
                        parsed = json.loads(details_raw)
                        if isinstance(parsed, dict):
                            details_obj = parsed
                    except Exception:
                        details_obj = {}

                details_obj["login_successful"] = False
                details_obj["failure_reason"] = "disconnect_correlation"
                details_obj["failed_at"] = end_ts.isoformat()
                details_obj["correlated_disconnect_event_type"] = str(disconnect_event_type or "ip_disconnect")

                await self._db.execute(
                    "UPDATE connection_events SET details = ? WHERE id = ?",
                    (json.dumps(details_obj, ensure_ascii=False), event_id),
                )
                await self._db.commit()
                return 1
        except Exception as exc:
            logger.debug("AuthMe correlation update failed for %s: %s", source_ip, exc)
            return 0

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

    async def log_minecraft_burst_alert(
        self,
        source_ip: str,
        event_count: int,
        window_seconds: int,
        unique_ip_count: int = 1,
        plugin_name: str = "minecraft",
    ) -> int:
        """Logs a Minecraft burst anomaly for observe-only analytics."""
        async with self._lock:
            try:
                now = datetime.utcnow().isoformat()
                async with self._db.execute(
                    """
                    INSERT INTO minecraft_burst_alerts
                        (timestamp, source_ip, event_count, window_seconds, unique_ip_count, plugin_name)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        source_ip,
                        int(event_count),
                        int(window_seconds),
                        max(int(unique_ip_count), 1),
                        str(plugin_name or "minecraft").strip().lower(),
                    ),
                ) as cursor:
                    await self._db.commit()
                    return int(cursor.lastrowid)
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Minecraft burst alert logging failed: {exc}"
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

    async def _seed_rbac_defaults(self) -> None:
        roles = [
            ("owner", "Owner"),
            ("admin", "Admin"),
            ("moderator", "Moderator"),
            ("viewer", "Viewer"),
        ]
        permissions = [
            ("*", "Owner wildcard"),
            ("panel.view", "View panel routes"),
            ("minecraft.view", "View minecraft panel"),
            ("minecraft.intel.view", "Use minecraft entity intel"),
            ("minecraft.email.view.masked", "View masked emails"),
            ("minecraft.email.view.full", "View full emails"),
            ("minecraft.ip.view.masked", "View masked IPs"),
            ("minecraft.ip.view.full", "View full IPs"),
            ("minecraft.uuid.view.masked", "View masked UUIDs"),
            ("minecraft.uuid.view.full", "View full UUIDs"),
            ("minecraft.profile.last_login.view", "View login timestamps"),
            ("admin.query.run", "Run advanced query endpoint"),
            ("admin.audit.view", "View audit and query logs"),
            ("admin.users.manage", "Manage users and roles"),
            ("admin.invites.manage", "Manage invite tokens"),
            ("admin.config.edit", "Edit configuration"),
            ("portal.view", "View portal homepage"),
            ("portal.manage", "Manage portal links"),
        ]

        for role_code, display_name in roles:
            await self._db.execute(
                """
                INSERT INTO auth_roles (role_code, display_name, is_system)
                VALUES (?, ?, 1)
                ON CONFLICT(role_code) DO UPDATE SET display_name = excluded.display_name
                """,
                (role_code, display_name),
            )

        for node, description in permissions:
            await self._db.execute(
                """
                INSERT INTO auth_permissions (node, description)
                VALUES (?, ?)
                ON CONFLICT(node) DO UPDATE SET description = excluded.description
                """,
                (node, description),
            )

        role_permissions: dict[str, list[str]] = {
            "owner": ["*"],
            "admin": [
                "panel.view",
                "minecraft.view",
                "minecraft.intel.view",
                "minecraft.email.view.masked",
                "minecraft.email.view.full",
                "minecraft.ip.view.masked",
                "minecraft.ip.view.full",
                "minecraft.uuid.view.masked",
                "minecraft.uuid.view.full",
                "minecraft.profile.last_login.view",
                "admin.query.run",
                "admin.audit.view",
                "admin.config.edit",
                "portal.view",
            ],
            "moderator": [
                "panel.view",
                "minecraft.view",
                "minecraft.intel.view",
                "minecraft.email.view.masked",
                "minecraft.ip.view.masked",
                "minecraft.uuid.view.masked",
                "admin.query.run",
                "portal.view",
            ],
            "viewer": [
                "panel.view",
                "minecraft.view",
                "minecraft.email.view.masked",
                "minecraft.ip.view.masked",
                "minecraft.uuid.view.masked",
                "portal.view",
            ],
        }

        for role_code, nodes in role_permissions.items():
            for node in nodes:
                await self._db.execute(
                    """
                    INSERT OR IGNORE INTO auth_role_permissions (role_id, permission_id, effect)
                    SELECT r.id, p.id, 1
                    FROM auth_roles r, auth_permissions p
                    WHERE r.role_code = ? AND p.node = ?
                    """,
                    (role_code, node),
                )

    async def _assign_role_to_user_id(self, user_id: int, role_code: str) -> None:
        await self._db.execute(
            """
            INSERT OR IGNORE INTO auth_user_roles (user_id, role_id)
            SELECT ?, id FROM auth_roles WHERE role_code = ?
            """,
            (user_id, role_code),
        )

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
                   is_active, is_owner, display_name, created_by, disabled_reason,
                   failed_login_count, last_failed_login_at, locked_until,
                   created_at, updated_at, last_login_at, last_login_ip
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
        is_owner: bool = False,
        display_name: str = "",
        created_by: str = "",
    ) -> int:
        async with self._lock:
            await self._seed_rbac_defaults()
            async with self._db.execute(
                """
                INSERT INTO admin_users
                    (username, password_hash, totp_secret, totp_enabled, is_active, is_owner,
                     display_name, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?, datetime('now'), datetime('now'))
                """,
                (
                    username,
                    password_hash,
                    totp_secret,
                    1 if totp_enabled else 0,
                    1 if is_owner else 0,
                    display_name or username,
                    created_by or None,
                ),
            ) as cursor:
                user_id = int(cursor.lastrowid)
                await self._assign_role_to_user_id(
                    user_id,
                    "owner" if is_owner else "admin",
                )
                await self._db.commit()
                return user_id

    async def list_admin_users(self, limit: int = 250) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        async with self._db.execute(
            """
            SELECT id, username, is_active, is_owner, display_name, created_by,
                   failed_login_count, last_failed_login_at, locked_until,
                   created_at, updated_at, last_login_at, last_login_ip
            FROM admin_users
            ORDER BY id ASC
            LIMIT ?
            """,
            (safe_limit,),
        ) as cursor:
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    async def upsert_user_permission(self, username: str, permission_node: str, effect: int = 1) -> bool:
        node = str(permission_node or "").strip()
        if not node:
            return False
        async with self._lock:
            await self._seed_rbac_defaults()
            await self._db.execute(
                "INSERT INTO auth_permissions (node, description) VALUES (?, ?) ON CONFLICT(node) DO NOTHING",
                (node, "Custom permission node"),
            )
            async with self._db.execute(
                "SELECT id FROM admin_users WHERE username = ? AND is_active = 1 LIMIT 1",
                (username,),
            ) as cursor:
                user_row = await cursor.fetchone()
            if not user_row:
                await self._db.rollback()
                return False

            await self._db.execute(
                """
                INSERT INTO auth_user_permissions (user_id, permission_id, effect)
                SELECT ?, p.id, ?
                FROM auth_permissions p
                WHERE p.node = ?
                ON CONFLICT(user_id, permission_id) DO UPDATE SET effect = excluded.effect
                """,
                (int(user_row[0]), 1 if int(effect) >= 0 else -1, node),
            )
            await self._db.commit()
            return True

    async def get_user_effective_permissions(self, username: str) -> Dict[str, Set[str]]:
        async with self._db.execute(
            "SELECT id, is_owner FROM admin_users WHERE username = ? AND is_active = 1 LIMIT 1",
            (username,),
        ) as cursor:
            user_row = await cursor.fetchone()

        if not user_row:
            return {"allow": set(), "deny": set()}

        user_id = int(user_row[0])
        is_owner = bool(int(user_row[1] or 0))
        if is_owner:
            return {"allow": {"*"}, "deny": set()}

        allow: Set[str] = set()
        deny: Set[str] = set()

        async with self._db.execute(
            """
            SELECT p.node, rp.effect
            FROM auth_user_roles ur
            JOIN auth_role_permissions rp ON rp.role_id = ur.role_id
            JOIN auth_permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = ?
            """,
            (user_id,),
        ) as cursor:
            for node, effect in await cursor.fetchall():
                node_text = str(node or "").strip()
                if not node_text:
                    continue
                if int(effect or 1) >= 0:
                    allow.add(node_text)
                else:
                    deny.add(node_text)

        async with self._db.execute(
            """
            SELECT p.node, up.effect
            FROM auth_user_permissions up
            JOIN auth_permissions p ON p.id = up.permission_id
            WHERE up.user_id = ?
            """,
            (user_id,),
        ) as cursor:
            for node, effect in await cursor.fetchall():
                node_text = str(node or "").strip()
                if not node_text:
                    continue
                if int(effect or 1) >= 0:
                    allow.add(node_text)
                else:
                    deny.add(node_text)

        return {"allow": allow, "deny": deny}

    async def assign_role_to_user(self, username: str, role_code: str) -> bool:
        normalized_role = str(role_code or "").strip().lower()
        if not normalized_role:
            return False
        async with self._lock:
            await self._seed_rbac_defaults()
            async with self._db.execute(
                "SELECT id FROM admin_users WHERE username = ? AND is_active = 1 LIMIT 1",
                (username,),
            ) as cursor:
                row = await cursor.fetchone()
            if not row:
                return False
            await self._assign_role_to_user_id(int(row[0]), normalized_role)
            await self._db.commit()
            return True

    async def create_invite_token(
        self,
        token_hash: str,
        created_by: str,
        expires_at: Optional[str],
        max_uses: int = 1,
        role_codes: Optional[List[str]] = None,
        permission_nodes: Optional[List[str]] = None,
        note: str = "",
    ) -> int:
        async with self._lock:
            async with self._db.execute(
                """
                INSERT INTO auth_invite_tokens
                    (token_hash, created_by, note, max_uses, used_count, expires_at, is_active,
                     role_codes_json, permission_nodes_json)
                VALUES (?, ?, ?, ?, 0, ?, 1, ?, ?)
                """,
                (
                    token_hash,
                    created_by or None,
                    note or None,
                    max(1, int(max_uses or 1)),
                    expires_at,
                    json.dumps(role_codes or [], ensure_ascii=False),
                    json.dumps(permission_nodes or [], ensure_ascii=False),
                ),
            ) as cursor:
                await self._db.commit()
                return int(cursor.lastrowid)

    async def list_invite_tokens(self, limit: int = 100) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        async with self._db.execute(
            """
            SELECT id, token_hash, created_by, note, max_uses, used_count,
                   expires_at, is_active, role_codes_json, permission_nodes_json, created_at
            FROM auth_invite_tokens
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    async def get_active_invite_by_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        normalized = str(token_hash or "").strip()
        if not normalized:
            return None
        async with self._db.execute(
            """
            SELECT id, token_hash, created_by, note, max_uses, used_count,
                   expires_at, is_active, role_codes_json, permission_nodes_json, created_at
            FROM auth_invite_tokens
            WHERE token_hash = ? AND is_active = 1
            LIMIT 1
            """,
            (normalized,),
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cursor.description]
            invite = dict(zip(cols, row))

        expires_raw = str(invite.get("expires_at") or "").strip()
        if expires_raw:
            try:
                expires_at = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=datetime.now().astimezone().tzinfo)
                if expires_at <= datetime.now(expires_at.tzinfo):
                    return None
            except Exception:
                return None

        if int(invite.get("used_count") or 0) >= int(invite.get("max_uses") or 1):
            return None
        return invite

    async def consume_invite_token(self, invite_id: int) -> bool:
        safe_id = int(invite_id)
        async with self._lock:
            async with self._db.execute(
                """
                UPDATE auth_invite_tokens
                SET used_count = used_count + 1,
                    is_active = CASE WHEN used_count + 1 >= max_uses THEN 0 ELSE is_active END
                WHERE id = ? AND is_active = 1
                """,
                (safe_id,),
            ) as cursor:
                await self._db.commit()
                return bool(cursor.rowcount and cursor.rowcount > 0)

    async def log_query_event(
        self,
        actor_username: Optional[str],
        endpoint: str,
        query_payload: Optional[Dict[str, Any]],
        result_count: int,
        duration_ms: int,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> int:
        async with self._lock:
            async with self._db.execute(
                """
                INSERT INTO auth_query_logs
                    (actor_username, endpoint, query_json, result_count, duration_ms, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    actor_username,
                    str(endpoint or "")[:255],
                    json.dumps(query_payload or {}, ensure_ascii=False),
                    max(0, int(result_count or 0)),
                    max(0, int(duration_ms or 0)),
                    ip_address,
                    user_agent,
                ),
            ) as cursor:
                await self._db.commit()
                return int(cursor.lastrowid)

    async def get_query_logs(
        self,
        limit: int = 200,
        actor: str = "",
        endpoint: str = "",
    ) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        where_clauses: List[str] = []
        params: List[Any] = []
        if actor:
            where_clauses.append("LOWER(COALESCE(actor_username, '')) = LOWER(?)")
            params.append(actor)
        if endpoint:
            where_clauses.append("LOWER(COALESCE(endpoint, '')) LIKE ?")
            params.append(f"%{endpoint.lower()}%")
        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        async with self._db.execute(
            f"""
            SELECT id, actor_username, endpoint, query_json, result_count, duration_ms,
                   ip_address, user_agent, created_at
            FROM auth_query_logs
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """,
            (*params, safe_limit),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    async def get_audit_events(
        self,
        limit: int = 300,
        actor: str = "",
        action: str = "",
    ) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 2000))
        where_clauses: List[str] = []
        params: List[Any] = []
        if actor:
            where_clauses.append("LOWER(COALESCE(actor_username, '')) = LOWER(?)")
            params.append(actor)
        if action:
            where_clauses.append("LOWER(COALESCE(action, '')) LIKE ?")
            params.append(f"%{action.lower()}%")
        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        async with self._db.execute(
            f"""
            SELECT id, actor_username, action, target, ip_address, details_json, created_at
            FROM audit_log
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
            """,
            (*params, safe_limit),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    async def record_admin_failed_login(self, username: str, lock_seconds: int = 0) -> int:
        normalized = str(username or "").strip()
        if not normalized:
            return 0
        async with self._lock:
            lock_until = None
            if int(lock_seconds or 0) > 0:
                lock_until = (datetime.utcnow() + timedelta(seconds=int(lock_seconds))).isoformat()
            async with self._db.execute(
                """
                UPDATE admin_users
                SET failed_login_count = COALESCE(failed_login_count, 0) + 1,
                    last_failed_login_at = datetime('now'),
                    locked_until = COALESCE(?, locked_until),
                    updated_at = datetime('now')
                WHERE username = ?
                """,
                (lock_until, normalized),
            ) as cursor:
                await self._db.commit()
                return cursor.rowcount if cursor.rowcount is not None else 0

    async def record_admin_login(self, username: str, client_ip: str) -> None:
        async with self._lock:
            await self._db.execute(
                """
                UPDATE admin_users
                SET last_login_at = datetime('now'),
                    last_login_ip = ?,
                    failed_login_count = 0,
                    locked_until = NULL,
                    updated_at = datetime('now')
                WHERE username = ?
                """,
                (client_ip, username),
            )
            await self._db.commit()

    async def set_admin_totp_enabled(self, username: str, enabled: bool) -> int:
        """Enable or disable TOTP for a specific active admin account."""
        async with self._lock:
            async with self._db.execute(
                """
                UPDATE admin_users
                SET totp_enabled = ?,
                    updated_at = datetime('now')
                WHERE username = ? AND is_active = 1
                """,
                (1 if enabled else 0, username),
            ) as cursor:
                await self._db.commit()
                return cursor.rowcount if cursor.rowcount is not None else 0

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

    async def add_minecraft_watchlist(
        self,
        player_name: str,
        reason: str = "",
        actor_username: str = "",
    ) -> int:
        normalized = str(player_name or "").strip()
        if not normalized:
            raise WardenDatabaseError("Player name is required for watchlist.")
        async with self._lock:
            try:
                # Reactivate existing inactive entry when available.
                async with self._db.execute(
                    """
                    SELECT id
                    FROM minecraft_watchlist
                    WHERE LOWER(player_name) = LOWER(?)
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (normalized,),
                ) as cursor:
                    row = await cursor.fetchone()

                if row:
                    watch_id = int(row[0])
                    await self._db.execute(
                        """
                        UPDATE minecraft_watchlist
                        SET is_active = 1,
                            reason = ?,
                            actor_username = ?,
                            updated_at = datetime('now')
                        WHERE id = ?
                        """,
                        (reason, actor_username, watch_id),
                    )
                    await self._db.commit()
                    return watch_id

                async with self._db.execute(
                    """
                    INSERT INTO minecraft_watchlist
                        (player_name, reason, actor_username, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, 1, datetime('now'), datetime('now'))
                    """,
                    (normalized, reason, actor_username),
                ) as cursor:
                    await self._db.commit()
                    return int(cursor.lastrowid)
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Failed to add minecraft watchlist entry: {exc}"
                ) from exc

    async def remove_minecraft_watchlist(self, player_name: str) -> int:
        normalized = str(player_name or "").strip()
        if not normalized:
            return 0
        async with self._lock:
            try:
                async with self._db.execute(
                    """
                    UPDATE minecraft_watchlist
                    SET is_active = 0,
                        updated_at = datetime('now')
                    WHERE LOWER(player_name) = LOWER(?)
                      AND is_active = 1
                    """,
                    (normalized,),
                ) as cursor:
                    await self._db.commit()
                    return cursor.rowcount if cursor.rowcount is not None else 0
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Failed to remove minecraft watchlist entry: {exc}"
                ) from exc

    async def list_minecraft_watchlist(self, limit: int = 200) -> List[Dict[str, Any]]:
        max_limit = min(max(int(limit), 1), 1000)
        try:
            async with self._db.execute(
                """
                SELECT id, player_name, reason, actor_username, is_active, created_at, updated_at
                FROM minecraft_watchlist
                WHERE is_active = 1
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (max_limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in rows]
        except Exception as exc:
            logger.error("Minecraft watchlist query failed: %s", exc)
            return []

    async def get_minecraft_watchlist_names(self) -> set[str]:
        try:
            async with self._db.execute(
                """
                SELECT player_name
                FROM minecraft_watchlist
                WHERE is_active = 1
                """
            ) as cursor:
                rows = await cursor.fetchall()
                names: set[str] = set()
                for row in rows:
                    if not row:
                        continue
                    value = str(row[0] or "").strip().lower()
                    if value:
                        names.add(value)
                return names
        except Exception as exc:
            logger.error("Minecraft watchlist names query failed: %s", exc)
            return set()

    async def get_minecraft_player_cache(self, player_name: str) -> Optional[Dict[str, Any]]:
        normalized = str(player_name or "").strip()
        if not normalized:
            return None
        try:
            async with self._db.execute(
                """
                SELECT player_name, email, uuid, ip, creation_ip, creation_date,
                       last_login, reg_ip, is_verified, duplicate_email_count,
                       source, updated_at, created_at
                FROM minecraft_player_cache
                WHERE LOWER(player_name) = LOWER(?)
                LIMIT 1
                """,
                (normalized,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
        except Exception as exc:
            logger.error("Minecraft player cache query failed: %s", exc)
            return None

    async def upsert_minecraft_player_cache(
        self,
        player_name: str,
        payload: Dict[str, Any],
        source: str = "mysql",
    ) -> int:
        normalized = str(player_name or "").strip()
        if not normalized:
            raise WardenDatabaseError("player_name is required for minecraft cache upsert")

        async with self._lock:
            try:
                async with self._db.execute(
                    """
                    INSERT INTO minecraft_player_cache
                        (player_name, email, uuid, ip, creation_ip, creation_date,
                         last_login, reg_ip, is_verified, duplicate_email_count,
                         source, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(player_name) DO UPDATE SET
                        email = excluded.email,
                        uuid = excluded.uuid,
                        ip = excluded.ip,
                        creation_ip = excluded.creation_ip,
                        creation_date = excluded.creation_date,
                        last_login = excluded.last_login,
                        reg_ip = excluded.reg_ip,
                        is_verified = excluded.is_verified,
                        duplicate_email_count = excluded.duplicate_email_count,
                        source = excluded.source,
                        updated_at = datetime('now')
                    """,
                    (
                        normalized,
                        payload.get("email"),
                        payload.get("uuid"),
                        payload.get("ip"),
                        payload.get("creation_ip"),
                        payload.get("creation_date"),
                        payload.get("last_login"),
                        payload.get("reg_ip"),
                        payload.get("is_verified"),
                        int(payload.get("duplicate_email_count") or 0),
                        str(source or "mysql").strip().lower(),
                    ),
                ) as cursor:
                    await self._db.commit()
                    return int(cursor.lastrowid or 0)
            except Exception as exc:
                raise WardenDatabaseError(
                    f"Failed to upsert minecraft player cache: {exc}"
                ) from exc

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
