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
        await db.log_event(event, ip_hash="a3f2b8c1...")
        count = await db.get_event_count_by_ip("a3f2b8c1...", minutes=5)
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

    async def log_event(self, event, ip_hash: str) -> int:
        """Log a connection event to Redis."""
        async with self._lock:
            event_id = await self._redis.incr(self._key("event_id_seq"))
            now = datetime.utcnow()

            event_data = {
                "id": event_id,
                "timestamp": event.timestamp.isoformat(),
                "ip_hash": ip_hash,
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
            # Index by IP hash (sorted set, score = timestamp)
            score = event.timestamp.timestamp()
            pipe.zadd(self._key("ip_events", ip_hash), {str(event_id): score})
            pipe.expire(self._key("ip_events", ip_hash), self._event_ttl)
            # Global counter
            pipe.incr(self._key("stats", "total_events"))
            await pipe.execute()

            return event_id

    # ── Ban History ──

    async def log_ban(
        self,
        ip_hash: str,
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
                "ip_hash": ip_hash,
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
            pipe.sadd(self._key("ip_bans", ip_hash), str(ban_id))
            pipe.incr(self._key("stats", "total_bans"))
            await pipe.execute()

            logger.info(
                "Ban logged ID=%d, IP_HASH=%s..., Reason='%s', Duration=%ds",
                ban_id, ip_hash[:12], reason, ban_duration,
            )
            return ban_id

    # ── Queries ──

    async def get_event_count_by_ip(
        self, ip_hash: str, minutes: int = 5
    ) -> int:
        """Returns count of events for a hashed IP in the last N minutes."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).timestamp()
        now = datetime.utcnow().timestamp()
        return await self._redis.zcount(
            self._key("ip_events", ip_hash), cutoff, now
        )

    async def get_recent_events_by_ip(
        self, ip_hash: str, minutes: int = 5
    ) -> List[Dict[str, Any]]:
        """Returns recent events for a hashed IP."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).timestamp()
        now = datetime.utcnow().timestamp()
        event_ids = await self._redis.zrangebyscore(
            self._key("ip_events", ip_hash), cutoff, now
        )
        events = []
        for eid in event_ids:
            data = await self._redis.hgetall(self._key("event", str(eid)))
            if data:
                events.append(data)
        return events

    async def is_ip_banned(self, ip_hash: str) -> bool:
        """Check if a hashed IP has an active ban."""
        ban_ids = await self._redis.smembers(self._key("ip_bans", ip_hash))
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
