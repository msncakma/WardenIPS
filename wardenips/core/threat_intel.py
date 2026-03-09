"""
WardenIPS - Decentralized Threat Intelligence Sync
=====================================================

Allows multiple WardenIPS instances to share banned IP hashes
over HTTP, creating a decentralized threat intelligence network.

How it works:
  - Each instance runs a lightweight HTTP sync server
  - Periodically pulls new ban hashes from configured peer nodes
    - Received hashes are stored as shared threat indicators for correlation
  - Only HMAC-hashed IPs are shared — no plaintext IPs leave the node

Architecture:
  ┌─────────┐     push/pull      ┌─────────┐
  │ Node A  │ ◄──────────────► │ Node B  │
  └─────────┘                    └─────────┘
       ▲                              ▲
       │         push/pull            │
       └──────────► ┌─────────┐ ◄────┘
                    │ Node C  │
                    └─────────┘

Config:
  threat_intel:
    enabled: false
    sync_interval: 300          # Pull from peers every N seconds
    share_bans: true            # Share our bans with peers
    auto_ban_received: false    # Currently informational only with hashed feeds
    received_ban_duration: 1800 # Reserved for future plaintext-compatible feeds
    peers:                      # List of peer node URLs
      - "http://10.0.0.2:7681"
      - "http://10.0.0.3:7681"
    server:
      enabled: true
      host: "0.0.0.0"
      port: 7681
      api_key: ""               # Shared secret between nodes
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional, Set

from wardenips.core.logger import get_logger

logger = get_logger(__name__)

try:
    import aiohttp
    from aiohttp import web
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False


class ThreatIntelSync:
    """
    Decentralized threat intelligence synchronization.

    Runs a lightweight HTTP server to serve local ban hashes
    and periodically pulls ban hashes from peer nodes.
    """

    def __init__(self) -> None:
        self._enabled: bool = False
        self._share_bans: bool = True
        self._auto_ban: bool = False
        self._received_ban_duration: int = 1800
        self._sync_interval: int = 300
        self._peers: list[str] = []
        self._server_enabled: bool = False
        self._server_host: str = "0.0.0.0"
        self._server_port: int = 7681
        self._api_key: str = ""

        # Shared state
        self._db = None
        self._firewall = None
        self._local_ban_hashes: Set[str] = set()
        self._received_hashes: Set[str] = set()
        self._peer_status: dict[str, dict[str, Any]] = {}
        self._last_sync_started_at: Optional[str] = None
        self._last_sync_completed_at: Optional[str] = None

        # Server
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._sync_task: Optional[asyncio.Task] = None
        self._total_shared: int = 0
        self._total_received: int = 0

    @classmethod
    async def create(cls, config, db, firewall) -> ThreatIntelSync:
        instance = cls()
        instance._db = db
        instance._firewall = firewall
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        section = config.get_section("threat_intel") if config.get("threat_intel", None) else {}
        if not section:
            return

        self._enabled = section.get("enabled", False)
        if not self._enabled or not _AIOHTTP_AVAILABLE:
            return

        self._share_bans = section.get("share_bans", True)
        self._auto_ban = section.get("auto_ban_received", False)
        self._received_ban_duration = section.get("received_ban_duration", 1800)
        self._sync_interval = section.get("sync_interval", 300)
        self._peers = [peer.rstrip("/") for peer in section.get("peers", []) if peer]
        self._peer_status = {
            peer: {
                "peer": peer,
                "reachable": False,
                "last_attempt_at": None,
                "last_success_at": None,
                "last_error": None,
                "last_received_count": 0,
                "total_received": 0,
            }
            for peer in self._peers
        }

        server = section.get("server", {})
        self._server_enabled = server.get("enabled", True)
        self._server_host = server.get("host", "0.0.0.0")
        self._server_port = server.get("port", 7681)
        self._api_key = server.get("api_key", "")

    @property
    def enabled(self) -> bool:
        return self._enabled and _AIOHTTP_AVAILABLE

    async def start(self) -> None:
        """Start the sync server and periodic pull task."""
        if not self.enabled:
            return

        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        )

        # Start HTTP server for peers to pull from
        if self._server_enabled:
            self._app = web.Application()
            self._app.router.add_get("/api/threat-intel/bans", self._handle_get_bans)
            self._app.router.add_get("/api/threat-intel/health", self._handle_health)
            self._app.router.add_get("/api/threat-intel/status", self._handle_status)

            self._runner = web.AppRunner(self._app, access_log=None)
            await self._runner.setup()
            site = web.TCPSite(self._runner, self._server_host, self._server_port)
            await site.start()
            logger.info(
                "Threat Intel sync server started on %s:%d",
                self._server_host, self._server_port,
            )

        # Start periodic sync loop
        if self._peers:
            self._sync_task = asyncio.create_task(self._sync_loop())
            logger.info(
                "Threat Intel sync enabled — %d peer(s), interval %ds",
                len(self._peers), self._sync_interval,
            )

        if self._auto_ban:
            logger.warning(
                "Threat Intel auto_ban_received is enabled, but peers share only hashed IPs. "
                "This currently works as correlation intel, not direct firewall blocking."
            )

    async def stop(self) -> None:
        """Stop sync server and tasks."""
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        if self._runner:
            await self._runner.cleanup()
        if self._session:
            await self._session.close()
        logger.info(
            "Threat Intel sync stopped. Shared: %d, Received: %d",
            self._total_shared, self._total_received,
        )

    def _check_auth(self, request: web.Request) -> bool:
        if not self._api_key:
            return True
        auth = request.headers.get("Authorization", "")
        return auth == f"Bearer {self._api_key}"

    # ── Server Handlers ──

    async def _handle_health(self, request: web.Request) -> web.Response:
        status = await self.get_status(include_peers=False)
        return web.json_response({
            "status": "ok",
            "enabled": status["enabled"],
            "mode": status["mode"],
            "sharing_enabled": status["sharing_enabled"],
            "auto_ban_effective": status["auto_ban_effective"],
            "sync_interval": status["sync_interval"],
            "peer_count": len(self._peers),
            "shared": status["shared_total"],
            "received": status["received_total"],
            "local_bans": status["local_hash_count"],
            "last_sync_started_at": status["last_sync_started_at"],
            "last_sync_completed_at": status["last_sync_completed_at"],
        })

    async def _handle_status(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        return web.json_response(await self.get_status())

    async def get_status(self, include_peers: bool = True) -> dict[str, Any]:
        local_hashes = await self._get_local_ban_hashes() if self._share_bans else set()
        status = {
            "enabled": self.enabled,
            "mode": "correlation-only",
            "description": (
                "Peers exchange hashed active-ban indicators. This improves visibility "
                "and correlation across nodes, but does not directly firewall-block remote "
                "hashes because plaintext IPs are never shared."
            ),
            "sharing_enabled": self._share_bans,
            "auto_ban_requested": self._auto_ban,
            "auto_ban_effective": False,
            "sync_interval": self._sync_interval,
            "received_ban_duration": self._received_ban_duration,
            "local_hash_count": len(local_hashes),
            "received_hash_count": len(self._received_hashes),
            "shared_total": self._total_shared,
            "received_total": self._total_received,
            "last_sync_started_at": self._last_sync_started_at,
            "last_sync_completed_at": self._last_sync_completed_at,
        }
        if include_peers:
            status["peers"] = list(self._peer_status.values())
        return status

    async def _handle_get_bans(self, request: web.Request) -> web.Response:
        """Return locally banned IP hashes for peers to consume."""
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)

        if not self._share_bans:
            return web.json_response({"hashes": [], "count": 0})

        # Fetch recent ban hashes from DB
        hashes = await self._get_local_ban_hashes()
        self._total_shared += len(hashes)

        return web.json_response({
            "hashes": list(hashes),
            "count": len(hashes),
        })

    async def _get_local_ban_hashes(self) -> Set[str]:
        """Get hashed IPs from active bans in the database."""
        try:
            async with self._db._lock:
                async with self._db._db.execute(
                    """
                    SELECT DISTINCT ip_hash FROM ban_history
                    WHERE is_active = 1
                    """
                ) as cursor:
                    rows = await cursor.fetchall()
                    hashes = {row[0] for row in rows}
                    self._local_ban_hashes = hashes
                    return hashes
        except Exception as exc:
            logger.debug("Failed to get local ban hashes: %s", exc)
            return set()

    # ── Sync Loop ──

    async def _sync_loop(self) -> None:
        """Periodically pull ban hashes from peers."""
        while True:
            self._last_sync_started_at = self._now_iso()
            for peer_url in self._peers:
                await self._pull_from_peer(peer_url)
            self._last_sync_completed_at = self._now_iso()
            await asyncio.sleep(self._sync_interval)

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    async def _pull_from_peer(self, peer_url: str) -> None:
        """Pull ban hashes from a single peer."""
        url = f"{peer_url.rstrip('/')}/api/threat-intel/bans"
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        status = self._peer_status.setdefault(
            peer_url,
            {
                "peer": peer_url,
                "reachable": False,
                "last_attempt_at": None,
                "last_success_at": None,
                "last_error": None,
                "last_received_count": 0,
                "total_received": 0,
            },
        )
        status["last_attempt_at"] = self._now_iso()

        try:
            async with self._session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    status["reachable"] = False
                    status["last_error"] = f"HTTP {resp.status}"
                    logger.debug(
                        "Peer %s returned %d", peer_url, resp.status
                    )
                    return

                data = await resp.json()
                peer_hashes = set(data.get("hashes", []))
                new_hashes = peer_hashes - self._received_hashes
                status["reachable"] = True
                status["last_success_at"] = self._now_iso()
                status["last_error"] = None
                status["last_received_count"] = len(new_hashes)
                status["total_received"] += len(new_hashes)

                if new_hashes:
                    self._received_hashes.update(new_hashes)
                    self._total_received += len(new_hashes)
                    logger.info(
                        "Received %d new ban hash(es) from peer %s",
                        len(new_hashes), peer_url,
                    )

                    # Auto-ban is NOT supported for hashed IPs since we can't
                    # reconstruct the original IP from the hash.  This data is
                    # informational — it enriches the local threat database for
                    # correlation analysis.  If auto_ban_received is enabled
                    # AND the peer shares plaintext IPs (not recommended), it
                    # would work, but by default we only log the intelligence.
                    if self._auto_ban:
                        logger.debug(
                            "auto_ban_received is enabled but hashed IPs cannot "
                            "be banned directly. Hashes stored for correlation."
                        )

        except asyncio.TimeoutError:
            status["reachable"] = False
            status["last_error"] = "timeout"
            logger.debug("Timeout pulling from peer %s", peer_url)
        except Exception as exc:
            status["reachable"] = False
            status["last_error"] = str(exc)
            logger.debug("Error pulling from peer %s: %s", peer_url, exc)

    def __repr__(self) -> str:
        return (
            f"<ThreatIntelSync enabled={self._enabled} "
            f"peers={len(self._peers)} "
            f"shared={self._total_shared} received={self._total_received}>"
        )
