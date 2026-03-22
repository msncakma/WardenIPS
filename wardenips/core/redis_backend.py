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
from typing import Any, Dict, List, Optional, Set

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
        data["is_owner"] = int(data.get("is_owner", 0) or 0)
        data["totp_enabled"] = int(data.get("totp_enabled", 0) or 0)
        data["is_active"] = int(data.get("is_active", 0) or 0)
        data["failed_login_count"] = int(data.get("failed_login_count", 0) or 0)
        return data

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
        user_id = await self._redis.incr(self._key("admin_user_id_seq"))
        now = datetime.utcnow().isoformat()
        payload = {
            "id": user_id,
            "username": username,
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "totp_enabled": 1 if totp_enabled else 0,
            "is_active": 1,
            "is_owner": 1 if is_owner else 0,
            "display_name": display_name or username,
            "created_by": created_by,
            "failed_login_count": 0,
            "last_failed_login_at": "",
            "locked_until": "",
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
            mapping={
                "last_login_at": now,
                "last_login_ip": client_ip,
                "updated_at": now,
                "failed_login_count": 0,
                "locked_until": "",
            },
        )

    async def record_admin_failed_login(self, username: str, lock_seconds: int = 0) -> int:
        key = self._key("admin_user", username)
        exists = await self._redis.exists(key)
        if not exists:
            return 0
        now = datetime.utcnow().isoformat()
        payload = {"last_failed_login_at": now, "updated_at": now}
        if int(lock_seconds or 0) > 0:
            payload["locked_until"] = (datetime.utcnow() + timedelta(seconds=int(lock_seconds))).isoformat()
        await self._redis.hincrby(key, "failed_login_count", 1)
        await self._redis.hset(key, mapping=payload)
        return 1

    async def get_user_effective_permissions(self, username: str) -> Dict[str, Set[str]]:
        user = await self.get_admin_user_by_username(username)
        if user and int(user.get("is_owner", 0) or 0) == 1:
            return {"allow": {"*"}, "deny": set()}
        return {"allow": {"panel.view", "minecraft.view", "admin.query.run"}, "deny": set()}

    async def upsert_user_permission(self, username: str, permission_node: str, effect: int = 1) -> bool:
        # Redis backend keeps a permissive fallback until full RBAC sync is implemented.
        return bool(username and permission_node)

    async def assign_role_to_user(self, username: str, role_code: str) -> bool:
        return bool(username and role_code)

    async def list_admin_users(self, limit: int = 250) -> List[Dict[str, Any]]:
        members = await self._redis.smembers(self._key("admin_users"))
        rows: List[Dict[str, Any]] = []
        for username in sorted(list(members))[: max(1, min(int(limit), 1000))]:
            user = await self.get_admin_user_by_username(str(username))
            if user:
                rows.append(user)
        return rows

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
        invite_id = await self._redis.incr(self._key("invite_id_seq"))
        payload = {
            "id": invite_id,
            "token_hash": token_hash,
            "created_by": created_by or "",
            "note": note or "",
            "max_uses": max(1, int(max_uses or 1)),
            "used_count": 0,
            "expires_at": expires_at or "",
            "is_active": 1,
            "role_codes_json": json.dumps(role_codes or [], ensure_ascii=False),
            "permission_nodes_json": json.dumps(permission_nodes or [], ensure_ascii=False),
            "created_at": datetime.utcnow().isoformat(),
        }
        await self._redis.hset(self._key("invite", str(invite_id)), mapping=payload)
        await self._redis.zadd(self._key("invites"), {str(invite_id): time.time()})
        return int(invite_id)

    async def list_invite_tokens(self, limit: int = 100) -> List[Dict[str, Any]]:
        invite_ids = await self._redis.zrevrange(self._key("invites"), 0, max(0, int(limit) - 1))
        rows: List[Dict[str, Any]] = []
        for invite_id in invite_ids:
            data = await self._redis.hgetall(self._key("invite", str(invite_id)))
            if data:
                rows.append(data)
        return rows

    async def get_active_invite_by_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        token_value = str(token_hash or "").strip()
        if not token_value:
            return None
        invite_ids = await self._redis.zrevrange(self._key("invites"), 0, 999)
        for invite_id in invite_ids:
            data = await self._redis.hgetall(self._key("invite", str(invite_id)))
            if not data:
                continue
            if str(data.get("token_hash", "")) != token_value:
                continue
            if str(data.get("is_active", "1")) != "1":
                continue
            try:
                used = int(data.get("used_count", 0) or 0)
                max_uses = int(data.get("max_uses", 1) or 1)
            except Exception:
                used = 0
                max_uses = 1
            if used >= max_uses:
                continue
            return data
        return None

    async def consume_invite_token(self, invite_id: int) -> bool:
        key = self._key("invite", str(invite_id))
        data = await self._redis.hgetall(key)
        if not data or str(data.get("is_active", "1")) != "1":
            return False
        try:
            used = int(data.get("used_count", 0) or 0) + 1
            max_uses = int(data.get("max_uses", 1) or 1)
        except Exception:
            used = 1
            max_uses = 1
        is_active = 0 if used >= max_uses else 1
        await self._redis.hset(key, mapping={"used_count": used, "is_active": is_active})
        return True

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
        query_id = await self._redis.incr(self._key("query_log_id_seq"))
        payload = {
            "id": query_id,
            "actor_username": actor_username or "",
            "endpoint": endpoint,
            "query_json": json.dumps(query_payload or {}, ensure_ascii=False),
            "result_count": int(result_count or 0),
            "duration_ms": int(duration_ms or 0),
            "ip_address": ip_address or "",
            "user_agent": user_agent or "",
            "created_at": datetime.utcnow().isoformat(),
        }
        await self._redis.hset(self._key("query_log", str(query_id)), mapping=payload)
        await self._redis.zadd(self._key("query_logs"), {str(query_id): time.time()})
        return int(query_id)

    async def get_query_logs(self, limit: int = 200, actor: str = "", endpoint: str = "") -> List[Dict[str, Any]]:
        query_ids = await self._redis.zrevrange(self._key("query_logs"), 0, max(0, int(limit) - 1))
        rows: List[Dict[str, Any]] = []
        actor_l = str(actor or "").lower()
        endpoint_l = str(endpoint or "").lower()
        for query_id in query_ids:
            data = await self._redis.hgetall(self._key("query_log", str(query_id)))
            if not data:
                continue
            if actor_l and str(data.get("actor_username", "")).lower() != actor_l:
                continue
            if endpoint_l and endpoint_l not in str(data.get("endpoint", "")).lower():
                continue
            rows.append(data)
        return rows

    async def get_audit_events(self, limit: int = 300, actor: str = "", action: str = "") -> List[Dict[str, Any]]:
        audit_ids = await self._redis.zrevrange(self._key("audit_log"), 0, max(0, int(limit) - 1))
        rows: List[Dict[str, Any]] = []
        actor_l = str(actor or "").lower()
        action_l = str(action or "").lower()
        for audit_id in audit_ids:
            data = await self._redis.hgetall(self._key("audit", str(audit_id)))
            if not data:
                continue
            if actor_l and str(data.get("actor_username", "")).lower() != actor_l:
                continue
            if action_l and action_l not in str(data.get("action", "")).lower():
                continue
            rows.append(data)
        return rows

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
