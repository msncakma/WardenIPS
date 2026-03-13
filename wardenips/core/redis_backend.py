"""
WardenIPS - Redis Backend (Alternative to SQLite)
===================================================

An optional Redis-backed storage backend for enterprise/cluster
deployments where multiple WardenIPS instances need to share state.

When enabled, Redis replaces SQLite for:
  - Event logging (recent events stored as sorted sets)
  - Ban history (hash per IP with TTL)
  - Statistics (atomic counters)

Requires: redis[hiredis] (pip install redis[hiredis])

Config:
  database:
    backend: "redis"       # or "sqlite" (default)
    redis:
      url: "redis://localhost:6379/0"
      prefix: "warden:"
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from wardenips.core.logger import get_logger

logger = get_logger(__name__)

try:
    import redis.asyncio as aioredis
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False


class RedisDatabaseManager:
    """
    Async Redis-backed database manager for WardenIPS.

    Drop-in replacement for DatabaseManager with the same public API.
    Uses sorted sets for time-windowed queries and hashes for ban records.

    Usage:
        db = await RedisDatabaseManager.create(config)
        await db.log_event(event, source_ip="203.0.113.7")
        count = await db.get_event_count_by_ip("203.0.113.7", minutes=5)
        await db.close()
    """

    def __init__(self) -> None:
        self._redis: Optional[aioredis.Redis] = None
        self._prefix: str = "warden:"
        self._event_ttl: int = 86400  # 24h event retention in Redis
        self._lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    async def create(cls, config) -> RedisDatabaseManager:
        instance = cls()
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        if not _REDIS_AVAILABLE:
            raise RuntimeError(
                "Redis backend requested but 'redis' package is not installed. "
                "Install with: pip install redis[hiredis]"
            )

        db_section = config.get_section("database")
        redis_section = db_section.get("redis", {})
        redis_url = redis_section.get("url", "redis://localhost:6379/0")
        self._prefix = redis_section.get("prefix", "warden:")
        self._event_ttl = redis_section.get("event_ttl", 86400)

        self._redis = aioredis.from_url(
            redis_url, decode_responses=True
        )

        # Verify connection
        try:
            await self._redis.ping()
            logger.info("Redis backend connected: %s", redis_url)
        except Exception as exc:
            raise RuntimeError(f"Redis connection failed: {exc}") from exc

    def _key(self, *parts: str) -> str:
        return self._prefix + ":".join(parts)

    # ── Event Logging ──

    async def log_event(self, event, source_ip: str) -> int:
        """Log a connection event to Redis."""
        async with self._lock:
            event_id = await self._redis.incr(self._key("event_id_seq"))
            now = datetime.utcnow()

            event_data = {
                "id": event_id,
                "timestamp": event.timestamp.isoformat(),
                "source_ip": source_ip,
                "player_name": event.player_name or "",
                "connection_type": event.connection_type.value,
                "asn_number": event.asn_number or 0,
                "asn_org": event.asn_org or "",
                "country_code": event.country_code or "",
                "is_datacenter": 1 if event.is_datacenter else 0,
                "risk_score": event.risk_score,
                "threat_level": event.threat_level.name,
                "details": json.dumps(event.details or {}, ensure_ascii=False),
            }

            pipe = self._redis.pipeline()
            # Store event data
            event_key = self._key("event", str(event_id))
            pipe.hset(event_key, mapping=event_data)
            pipe.expire(event_key, self._event_ttl)
            # Index by source IP (sorted set, score = timestamp)
            score = event.timestamp.timestamp()
            pipe.zadd(self._key("ip_events", source_ip), {str(event_id): score})
            pipe.expire(self._key("ip_events", source_ip), self._event_ttl)
            # Global counter
            pipe.incr(self._key("stats", "total_events"))
            await pipe.execute()

            return event_id

    # ── Ban History ──

    async def log_ban(
        self,
        source_ip: str,
        reason: str,
        risk_score: int,
        ban_duration: int = 0,
    ) -> int:
        """Log a ban operation to Redis."""
        async with self._lock:
            ban_id = await self._redis.incr(self._key("ban_id_seq"))
            now = datetime.utcnow()
            expires_at = ""
            if ban_duration > 0:
                expires_at = (now + timedelta(seconds=ban_duration)).isoformat()

            ban_data = {
                "id": ban_id,
                "source_ip": source_ip,
                "reason": reason,
                "risk_score": risk_score,
                "ban_duration": ban_duration,
                "banned_at": now.isoformat(),
                "expires_at": expires_at,
                "is_active": 1,
            }

            pipe = self._redis.pipeline()
            ban_key = self._key("ban", str(ban_id))
            pipe.hset(ban_key, mapping=ban_data)
            if ban_duration > 0:
                pipe.expire(ban_key, ban_duration + 60)
            # Track active bans
            pipe.sadd(self._key("active_bans"), str(ban_id))
            pipe.sadd(self._key("ip_bans", source_ip), str(ban_id))
            pipe.incr(self._key("stats", "total_bans"))
            await pipe.execute()

            logger.info(
                "Ban logged ID=%d, IP=%s, Reason='%s', Duration=%ds",
                ban_id, source_ip, reason, ban_duration,
            )
            return ban_id

    # ── Queries ──

    async def get_event_count_by_ip(
        self,
        source_ip: str,
        minutes: int = 5,
        connection_type: str | None = None,
        reset_on_success: bool = False,
        success_event_types: list[str] | None = None,
    ) -> int:
        """Returns count of events for a source IP in the last N minutes."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).timestamp()
        now = datetime.utcnow().timestamp()
        if not reset_on_success or not success_event_types:
            return await self._redis.zcount(
                self._key("ip_events", source_ip), cutoff, now
            )

        event_ids = await self._redis.zrangebyscore(
            self._key("ip_events", source_ip), cutoff, now
        )
        filtered_events = []
        for event_id in event_ids:
            data = await self._redis.hgetall(self._key("event", str(event_id)))
            if not data:
                continue
            if connection_type and data.get("connection_type") != connection_type:
                continue
            filtered_events.append(data)

        reset_index = -1
        for index, item in enumerate(filtered_events):
            try:
                details = json.loads(item.get("details") or "{}")
            except Exception:
                details = {}
            if details.get("event_type") in success_event_types:
                reset_index = index

        start_index = reset_index + 1 if reset_index >= 0 else 0
        count = 0
        for item in filtered_events[start_index:]:
            try:
                details = json.loads(item.get("details") or "{}")
            except Exception:
                details = {}
            if details.get("event_type") in success_event_types:
                continue
            count += 1
        return count

    async def get_recent_events_by_ip(
        self, source_ip: str, minutes: int = 5
    ) -> List[Dict[str, Any]]:
        """Returns recent events for a source IP."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).timestamp()
        now = datetime.utcnow().timestamp()
        event_ids = await self._redis.zrangebyscore(
            self._key("ip_events", source_ip), cutoff, now
        )
        events = []
        for eid in event_ids:
            data = await self._redis.hgetall(self._key("event", str(eid)))
            if data:
                events.append(data)
        return events

    async def get_recent_connection_types_by_ip(
        self,
        source_ip: str,
        minutes: int = 15,
    ) -> List[str]:
        """Returns distinct recent connection types observed for a source IP."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).timestamp()
        now = datetime.utcnow().timestamp()
        event_ids = await self._redis.zrangebyscore(
            self._key("ip_events", source_ip), cutoff, now
        )
        values = set()
        for eid in event_ids:
            data = await self._redis.hgetall(self._key("event", str(eid)))
            connection_type = (data or {}).get("connection_type")
            if connection_type:
                values.add(connection_type)
        return sorted(values)

    async def get_total_ban_count_by_ip(self, source_ip: str) -> int:
        """Returns historical ban count for a source IP."""
        return int(await self._redis.scard(self._key("ip_bans", source_ip)))

    async def is_ip_banned(self, source_ip: str) -> bool:
        """Check if a source IP has an active ban."""
        ban_ids = await self._redis.smembers(self._key("ip_bans", source_ip))
        for bid in ban_ids:
            ban_key = self._key("ban", str(bid))
            data = await self._redis.hgetall(ban_key)
            if data and data.get("is_active") == "1":
                return True
        return False

    async def get_stats(self) -> Dict[str, Any]:
        """Returns database statistics."""
        total_events = await self._redis.get(
            self._key("stats", "total_events")
        ) or 0
        total_bans = await self._redis.get(
            self._key("stats", "total_bans")
        ) or 0
        active_bans = await self._redis.scard(self._key("active_bans"))

        return {
            "total_events": int(total_events),
            "total_bans": int(total_bans),
            "active_bans": active_bans,
            "db_path": "redis",
        }

    async def has_admin_users(self) -> bool:
        return int(await self._redis.scard(self._key("admin_users"))) > 0

    async def get_admin_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        data = await self._redis.hgetall(self._key("admin_user", username))
        if not data or data.get("is_active") != "1":
            return None
        data["id"] = int(data.get("id", 0) or 0)
        data["totp_enabled"] = int(data.get("totp_enabled", 0) or 0)
        data["is_active"] = int(data.get("is_active", 0) or 0)
        return data

    async def create_admin_user(
        self,
        username: str,
        password_hash: str,
        totp_secret: str,
        totp_enabled: bool = True,
    ) -> int:
        user_id = await self._redis.incr(self._key("admin_user_id_seq"))
        now = datetime.utcnow().isoformat()
        payload = {
            "id": user_id,
            "username": username,
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "totp_enabled": 1 if totp_enabled else 0,
            "is_active": 1,
            "created_at": now,
            "updated_at": now,
            "last_login_at": "",
            "last_login_ip": "",
        }
        pipe = self._redis.pipeline()
        pipe.hset(self._key("admin_user", username), mapping=payload)
        pipe.sadd(self._key("admin_users"), username)
        await pipe.execute()
        return int(user_id)

    async def record_admin_login(self, username: str, client_ip: str) -> None:
        now = datetime.utcnow().isoformat()
        await self._redis.hset(
            self._key("admin_user", username),
            mapping={"last_login_at": now, "last_login_ip": client_ip, "updated_at": now},
        )

    async def log_audit_event(
        self,
        action: str,
        actor_username: Optional[str] = None,
        target: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> int:
        audit_id = await self._redis.incr(self._key("audit_id_seq"))
        payload = {
            "id": audit_id,
            "actor_username": actor_username or "",
            "action": action,
            "target": target or "",
            "ip_address": ip_address or "",
            "details_json": json.dumps(details or {}, ensure_ascii=False),
            "created_at": datetime.utcnow().isoformat(),
        }
        await self._redis.hset(self._key("audit", str(audit_id)), mapping=payload)
        await self._redis.zadd(self._key("audit_log"), {str(audit_id): time.time()})
        return int(audit_id)

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Redis connection closed.")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __repr__(self) -> str:
        return f"<RedisDatabaseManager prefix='{self._prefix}'>"
