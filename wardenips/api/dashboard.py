"""
WardenIPS - Web Dashboard REST API
====================================

A lightweight async REST API built on aiohttp for real-time monitoring
of WardenIPS internals: stats, banned IPs, recent events,
and system health.

Endpoints:
  GET  /api/health              — Health check / uptime
  GET  /api/stats               — Database statistics
  GET  /api/bans                — Active ban list
  GET  /api/firewall-bans       — Active firewall IPs (plaintext operational view)
  GET  /api/events?limit=N      — Recent events
  GET  /api/firewall            — Firewall status
  GET  /api/top-attackers       — Top attacking source IPs
  GET  /api/top-portscanned-ports — Top scanned destination ports (portscan plugin)
  GET  /api/events-timeline     — Events grouped by hour
  GET  /api/asn-stats           — Events grouped by ASN organization
  GET  /api/threat-distribution — Events grouped by threat level
  GET  /api/plugin-stats        — Events grouped by plugin/connection type
  GET  /login                   — Dashboard login page
  GET  /                        — Configurable landing route
  GET  /dashboard               — Public read-only dashboard
  GET  /admin                   — Advanced admin dashboard
  GET  /v2                      — Legacy redirect to /admin

The API is completely optional and controlled by the 'dashboard' section
in config.yaml.  When disabled, no port is opened.
"""

from __future__ import annotations

import asyncio
import copy
import hmac
import ipaddress
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
from urllib.parse import quote, urlencode

from aiohttp import web
import yaml

from wardenips import __author__, __version__
from wardenips.core.auth import (
  build_totp_qr_data_url,
  build_totp_uri,
  check_password_policy,
  generate_totp_secret,
  hash_password,
  verify_bootstrap_token,
  verify_password,
  verify_totp_code,
)
from wardenips.core.logger import get_logger
from wardenips.core.geoip_country import CountryLookupEngine
from wardenips.core.updater import UpdateChecker

logger = get_logger(__name__)

_AIOHTTP_WEB_AVAILABLE = True


class DashboardAPI:
  """Async REST API server for WardenIPS monitoring."""

  def __init__(
    self,
    config,
    db,
    firewall,
    start_time: float,
    whitelist=None,
    notifier=None,
    blocklist=None,
  ) -> None:
    self._config = config
    self._db = db
    self._firewall = firewall
    self._whitelist = whitelist
    self._start_time = start_time
    self._notifier = notifier
    self._blocklist = blocklist
    self._enabled: bool = False
    self._host: str = "127.0.0.1"
    self._port: int = 7680
    self._app: Optional[web.Application] = None
    self._runner: Optional[web.AppRunner] = None
    self._api_key: str = ""
    self._session_ttl: int = 600
    self._login_rate_limit_per_minute: int = 10
    self._public_dashboard_enabled: bool = True
    self._homepage: str = "dashboard"
    self._session_cookie_name: str = "wardenips_dashboard_session"
    self._sessions: dict[str, float] = {}
    self._session_users: dict[str, str] = {}
    self._pending_logins: dict[str, dict[str, object]] = {}
    self._pending_setups: dict[str, dict[str, object]] = {}
    self._login_attempts: dict[str, list[float]] = {}
    self._activity_touches: dict[str, list[float]] = {}
    self._recent_client_ips: dict[str, float] = {}
    self._activity_touch_interval_seconds: int = 15
    self._bootstrap_setup_required: bool = False
    self._bootstrap_token_hash: str = ""
    self._bootstrap_token_expires_at: str = ""
    self._country_lookup = CountryLookupEngine(self._config)
    self._initialize_config()

  def _initialize_config(self) -> None:
    dash = self._config.get_section("dashboard") if self._config.get("dashboard", None) else {}
    if not dash:
      return
    self._enabled = dash.get("enabled", False)
    self._host = dash.get("host", "127.0.0.1")
    self._port = dash.get("port", 7680)
    self._api_key = dash.get("api_key", "")
    self._session_ttl = max(int(dash.get("session_ttl", 600)), 60)
    self._login_rate_limit_per_minute = max(
      int(dash.get("login_rate_limit_per_minute", 10)),
      1,
    )
    self._public_dashboard_enabled = bool(dash.get("public_dashboard", True))
    homepage = str(dash.get("homepage", "dashboard")).strip().lower()
    self._homepage = homepage if homepage in {"dashboard", "login", "admin"} else "dashboard"
    bootstrap = dash.get("bootstrap", {}) if isinstance(dash.get("bootstrap", {}), dict) else {}
    self._bootstrap_setup_required = bool(bootstrap.get("setup_required", False))
    self._bootstrap_token_hash = str(bootstrap.get("token_hash", "") or "").strip()
    self._bootstrap_token_expires_at = str(bootstrap.get("token_expires_at", "") or "").strip()

  def _sync_firewall_simulation_mode(self) -> tuple[bool, bool]:
    """Apply firewall.simulation_mode from config to runtime firewall state."""
    desired = bool(self._config.get("firewall.simulation_mode", False))
    effective = bool(self._firewall.apply_simulation_config(desired))
    return desired, effective

  @property
  def enabled(self) -> bool:
    return self._enabled and _AIOHTTP_WEB_AVAILABLE

  def _get_bearer_secrets(self) -> set[str]:
    # Keep API key support for scripted clients.
    return {self._api_key} if self._api_key else set()

  def _bootstrap_token_is_valid(self) -> bool:
    if not self._bootstrap_setup_required or not self._bootstrap_token_hash:
      return False
    if not self._bootstrap_token_expires_at:
      return True
    try:
      expires_at = datetime.fromisoformat(self._bootstrap_token_expires_at.replace("Z", "+00:00"))
      return expires_at > datetime.now(timezone.utc)
    except Exception:
      return False

  async def _admin_auth_available(self) -> bool:
    try:
      return await self._db.has_admin_users()
    except Exception:
      return False

  async def _use_database_auth(self) -> bool:
    try:
      return await self._db.has_admin_users()
    except Exception:
      return False

  def _get_session_token(self, request: web.Request) -> str:
    return request.cookies.get(self._session_cookie_name, "")

  def _cleanup_expired_sessions(self) -> None:
    now = time.time()
    expired = [token for token, expires_at in self._sessions.items() if expires_at <= now]
    for token in expired:
      self._sessions.pop(token, None)
      self._session_users.pop(token, None)

    expired_pending_login = [token for token, payload in self._pending_logins.items() if float(payload.get("expires_at", 0)) <= now]
    for token in expired_pending_login:
      self._pending_logins.pop(token, None)

    expired_pending_setup = [token for token, payload in self._pending_setups.items() if float(payload.get("expires_at", 0)) <= now]
    for token in expired_pending_setup:
      self._pending_setups.pop(token, None)

  def _client_ip(self, request: web.Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
    ip_value = forwarded_for or request.remote or "unknown"
    self._track_client_ip(ip_value)
    return ip_value

  def _track_client_ip(self, ip_value: str) -> None:
    if not self._is_valid_ip(ip_value):
      return
    now = time.time()
    self._recent_client_ips[ip_value] = now
    cutoff = now - 3600
    stale = [ip for ip, ts in self._recent_client_ips.items() if ts < cutoff]
    for ip in stale:
      self._recent_client_ips.pop(ip, None)

  @staticmethod
  def _is_valid_ip(value: str) -> bool:
    try:
      ipaddress.ip_address(str(value).strip())
      return True
    except Exception:
      return False

  def get_recent_client_ips(self, max_age_seconds: int = 1800) -> set[str]:
    """Returns recently seen dashboard client IPs for anti-lockout checks."""
    now = time.time()
    cutoff = now - max(int(max_age_seconds), 60)
    return {
      ip
      for ip, seen_at in self._recent_client_ips.items()
      if seen_at >= cutoff and self._is_valid_ip(ip)
    }

  def _consume_rate_limit(
    self,
    bucket: dict[str, list[float]],
    key: str,
    limit: int,
    window_seconds: int,
  ) -> bool:
    now = time.monotonic()
    entries = [value for value in bucket.get(key, []) if now - value < window_seconds]
    if len(entries) >= limit:
      bucket[key] = entries
      return True
    entries.append(now)
    bucket[key] = entries
    return False

  def _is_session_authenticated(self, request: web.Request) -> bool:
    self._cleanup_expired_sessions()
    token = self._get_session_token(request)
    if not token:
      return False
    expires_at = self._sessions.get(token)
    if not expires_at or expires_at <= time.time():
      self._sessions.pop(token, None)
      return False
    return True

  def _touch_session(self, request: web.Request) -> bool:
    token = self._get_session_token(request)
    if not token:
      return False
    expires_at = self._sessions.get(token)
    if not expires_at or expires_at <= time.time():
      self._sessions.pop(token, None)
      return False
    self._sessions[token] = time.time() + self._session_ttl
    return True

  def _get_session_actor(self, request: web.Request) -> Optional[str]:
    token = self._get_session_token(request)
    return self._session_users.get(token)

  def _check_auth(self, request: web.Request) -> bool:
    if self._is_session_authenticated(request):
      return True
    bearer_secrets = self._get_bearer_secrets()
    if not bearer_secrets:
      return False
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
      return False
    token = auth[7:]
    return token in bearer_secrets

  def _check_public_dashboard_access(self, request: web.Request) -> bool:
    self._client_ip(request)
    if self._public_dashboard_enabled:
      return True
    return self._check_auth(request)

  @staticmethod
  def _build_operator_advice(event: dict) -> str:
    details_raw = event.get("details")
    details_text = str(details_raw or "").lower()
    event_type = str(event.get("event_type") or "").lower()
    player_name = str(event.get("player_name") or "")
    risk_score = int(event.get("risk_score") or 0)

    if "wp-login.php" in details_text or "admin-ajax.php" in details_text or event_type in {"suspicious_path", "scanner"}:
      return "WordPress brute-force probe detected. Restrict wp-admin/wp-login access and enable MFA."
    if "union select" in details_text or "sql syntax" in details_text or event_type == "sqli_probe":
      return "SQL injection attempt observed. Enforce input sanitization and prepared statements."
    if "../" in details_text or event_type in {"dir_traversal", "shell_injection"}:
      return "Traversal or command-injection pattern detected. Tighten WAF rules and review exposed endpoints."
    if event_type == "portscan" or "port_" in details_text:
      if player_name.startswith("port_"):
        scanned_port = player_name.replace("port_", "", 1)
        return (
          f"Port-scan activity detected on port {scanned_port}. "
          "If this port is configured as a honeypot trap, treat this source as hostile reconnaissance."
        )
      return (
        "Port scanning activity detected. Keep non-required ports closed, "
        "and maintain trap-port monitoring for repeated probes."
      )
    if risk_score >= 80:
      return "High-intensity activity detected. Consider stricter ban thresholds and upstream rate limiting."
    return "No immediate action required; continue monitoring this source for repeated behavior."

  @staticmethod
  def _get_event_threat_label(event: dict) -> str:
    event_type = str(event.get("event_type") or "").strip().lower()
    connection_type = str(event.get("connection_type") or "").strip().lower()
    if connection_type == "ssh" and event_type == "accepted_login":
      return "SUCCESS"
    return str(event.get("threat_level") or "NONE").upper()

  def _normalize_next_path(self, candidate: str, default: str = "/dashboard") -> str:
    value = str(candidate or "").strip()
    if not value.startswith("/") or value.startswith("//"):
      return default
    return value

  def _render_ui_template(self, html: str) -> str:
    return (
      html
      .replace("__APP_VERSION__", __version__)
      .replace("__APP_AUTHOR__", __author__)
    )

  def _format_duration(self, total_seconds: Optional[int]) -> str:
    if total_seconds is None or total_seconds < 0:
      return "--"
    days, remainder = divmod(int(total_seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
      return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

  @staticmethod
  def _parse_timestamp_unix(timestamp_value: object) -> Optional[int]:
    raw = str(timestamp_value or "").strip()
    if not raw:
      return None
    normalized = raw.replace(" ", "T")
    try:
      dt = datetime.fromisoformat(normalized)
    except Exception:
      return None
    if dt.tzinfo is None:
      # Older rows may be naive local times. Treat as server-local tz.
      local_tz = datetime.now().astimezone().tzinfo
      dt = dt.replace(tzinfo=local_tz)
    return int(dt.timestamp())

  @staticmethod
  def _normalize_country_code(country_value: object) -> str:
    code = str(country_value or "").strip().upper()
    if len(code) == 2 and code.isalpha():
      return code
    return ""

  def _resolve_country_code(self, details_obj: object, source_ip: object) -> str:
    details = details_obj if isinstance(details_obj, dict) else {}
    code = self._normalize_country_code(details.get("country_code"))
    if code:
      return code
    source_value = str(source_ip or "").strip()
    if self._country_lookup and self._is_valid_ip(source_value):
      looked_up = self._normalize_country_code(
        self._country_lookup.lookup_country_code(source_value)
      )
      if looked_up:
        return looked_up
    return ""

  def _get_system_uptime_seconds(self) -> Optional[int]:
    try:
      if os.path.exists("/proc/uptime"):
        with open("/proc/uptime", encoding="utf-8") as uptime_file:
          return int(float(uptime_file.read().split()[0]))
      if sys.platform.startswith("win"):
        import ctypes

        return int(ctypes.windll.kernel32.GetTickCount64() / 1000)
    except Exception:
      return None
    return None

  def _json_auth_error(self) -> web.Response:
    if self._bootstrap_token_is_valid():
      return web.json_response(
        {
          "error": "setup_required",
          "message": "Initial admin setup is required before /admin can be used.",
          "redirect_to": "/setup",
        },
        status=403,
      )
    return web.json_response({"error": "unauthorized"}, status=401)

  def _require_dashboard_auth(self, request: web.Request) -> Optional[web.Response]:
    if self._bootstrap_token_is_valid():
      raise web.HTTPFound("/setup")
    if self._is_session_authenticated(request):
      return None
    next_path = quote(
      self._normalize_next_path(request.path_qs or "/admin", "/admin"),
      safe="/%?=&",
    )
    raise web.HTTPFound(f"/login?next={next_path}")

  def _issue_session(self, response: web.StreamResponse, request: web.Request, username: Optional[str] = None) -> None:
    token = secrets.token_urlsafe(32)
    self._sessions[token] = time.time() + self._session_ttl
    if username:
      self._session_users[token] = username
    response.set_cookie(
      self._session_cookie_name,
      token,
      max_age=self._session_ttl,
      httponly=True,
      secure=request.secure,
      samesite="Lax",
      path="/",
    )

  def _clear_session(self, request: web.Request, response: web.StreamResponse) -> None:
    token = self._get_session_token(request)
    if token:
      self._sessions.pop(token, None)
      self._session_users.pop(token, None)
    response.del_cookie(self._session_cookie_name, path="/")

  async def _clear_bootstrap_config(self) -> None:
    await self._config.patch_values(
      {
        "dashboard.bootstrap.setup_required": False,
        "dashboard.bootstrap.token_hash": "",
        "dashboard.bootstrap.token_expires_at": "",
      }
    )
    self._initialize_config()

  async def _log_audit(
    self,
    request: web.Request,
    action: str,
    actor_username: Optional[str] = None,
    target: Optional[str] = None,
    details: Optional[dict] = None,
  ) -> None:
    try:
      await self._db.log_audit_event(
        action=action,
        actor_username=actor_username or self._get_session_actor(request),
        target=target,
        ip_address=self._client_ip(request),
        details=details,
      )
    except Exception as exc:
      logger.debug("Audit logging failed for %s: %s", action, exc)

  async def start(self) -> None:
    if not self.enabled:
      return

    self._app = web.Application()
    self._app.router.add_get("/", self._handle_root)
    self._app.router.add_get("/dashboard", self._handle_dashboard)
    self._app.router.add_get("/admin", self._handle_dashboard_v2)
    self._app.router.add_get("/v2", self._handle_dashboard_v2)
    self._app.router.add_get("/login", self._handle_login_page)
    self._app.router.add_get("/setup", self._handle_setup_page)
    self._app.router.add_post("/api/login", self._handle_login)
    self._app.router.add_post("/api/login/totp", self._handle_login_totp)
    self._app.router.add_post("/api/setup/begin", self._handle_setup_begin)
    self._app.router.add_post("/api/setup/complete", self._handle_setup_complete)
    self._app.router.add_post("/api/logout", self._handle_logout)
    self._app.router.add_post("/api/session/activity", self._handle_session_activity)
    self._app.router.add_get("/logout", self._handle_logout)
    self._app.router.add_get("/api/health", self._handle_health)
    self._app.router.add_get("/api/stats", self._handle_stats)
    self._app.router.add_get("/api/bans", self._handle_bans)
    self._app.router.add_get("/api/firewall-bans", self._handle_firewall_bans)
    self._app.router.add_get("/api/events", self._handle_events)
    self._app.router.add_get("/api/firewall", self._handle_firewall)
    self._app.router.add_get("/api/top-attackers", self._handle_top_attackers)
    self._app.router.add_get("/api/top-portscanned-ports", self._handle_top_portscanned_ports)
    self._app.router.add_get("/api/events-timeline", self._handle_events_timeline)
    self._app.router.add_get("/api/asn-stats", self._handle_asn_stats)
    self._app.router.add_get("/api/geo-heatmap", self._handle_geo_heatmap)
    self._app.router.add_get("/api/threat-distribution", self._handle_threat_distribution)
    self._app.router.add_get("/api/plugin-stats", self._handle_plugin_stats)
    self._app.router.add_get("/api/blocklist", self._handle_blocklist)
    self._app.router.add_post("/api/admin/ban-ip", self._handle_admin_ban_ip)
    self._app.router.add_post("/api/admin/unban-ip", self._handle_admin_unban_ip)
    self._app.router.add_get("/api/admin/whitelist", self._handle_admin_get_whitelist)
    self._app.router.add_post("/api/admin/whitelist/add", self._handle_admin_add_whitelist)
    self._app.router.add_post("/api/admin/whitelist/remove", self._handle_admin_remove_whitelist)
    self._app.router.add_post("/api/admin/deactivate-ban", self._handle_admin_deactivate_ban)
    self._app.router.add_post("/api/admin/deactivate-all-bans", self._handle_admin_deactivate_all_bans)
    self._app.router.add_post("/api/admin/enforce-simulated-bans", self._handle_admin_enforce_simulated_bans)
    self._app.router.add_post("/api/admin/reconcile-bans", self._handle_admin_reconcile_bans)
    self._app.router.add_get("/api/admin/auth-settings", self._handle_admin_get_auth_settings)
    self._app.router.add_post("/api/admin/auth-settings", self._handle_admin_set_auth_settings)
    self._app.router.add_post("/api/admin/query-records", self._handle_admin_query_records)
    self._app.router.add_post("/api/admin/flush-firewall", self._handle_admin_flush_firewall)
    self._app.router.add_post("/api/admin/clear-events", self._handle_admin_clear_events)
    self._app.router.add_post("/api/admin/clear-ban-history", self._handle_admin_clear_ban_history)
    self._app.router.add_post("/api/admin/test-notification", self._handle_admin_test_notification)
    self._app.router.add_get("/api/admin/update-status", self._handle_admin_update_status)
    self._app.router.add_get("/api/admin/config", self._handle_admin_get_config)
    self._app.router.add_post("/api/admin/config", self._handle_admin_save_config)
    self._app.router.add_post("/api/admin/config/patch", self._handle_admin_patch_config)

    self._runner = web.AppRunner(self._app, access_log=None)
    await self._runner.setup()
    site = web.TCPSite(self._runner, self._host, self._port)
    await site.start()
    logger.info("Dashboard API started on http://%s:%d", self._host, self._port)

  async def stop(self) -> None:
    if self._runner:
      await self._runner.cleanup()
      logger.info("Dashboard API stopped.")
    if self._country_lookup:
      self._country_lookup.close()

  async def _handle_health(self, request: web.Request) -> web.Response:
    uptime = int(time.monotonic() - self._start_time)
    system_uptime_seconds = self._get_system_uptime_seconds()
    return web.json_response(
      {
        "status": "ok",
        "uptime": self._format_duration(uptime),
        "uptime_seconds": uptime,
        "system_uptime": self._format_duration(system_uptime_seconds),
        "system_uptime_seconds": system_uptime_seconds,
      }
    )

  async def _handle_stats(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    stats = await self._db.get_stats()
    stats["firewall_active_bans"] = await self._firewall.get_banned_count()
    stats["simulation_mode"] = self._firewall.simulation_mode
    return web.json_response(stats)

  async def _handle_bans(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT source_ip, reason, risk_score, ban_duration,
               banned_at, expires_at, is_active
          FROM ban_history
          WHERE is_active = 1
          ORDER BY banned_at DESC
          LIMIT 100
          """
        ) as cursor:
          rows = await cursor.fetchall()
          columns = [d[0] for d in cursor.description]
          bans = [dict(zip(columns, row)) for row in rows]
      for ban in bans:
        ban["banned_at_unix"] = self._parse_timestamp_unix(ban.get("banned_at"))
        ban["expires_at_unix"] = self._parse_timestamp_unix(ban.get("expires_at"))
      return web.json_response({"bans": bans, "count": len(bans)})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_events(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    limit = min(int(request.query.get("limit", "50")), 200)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT id, timestamp, source_ip, player_name,
               connection_type, asn_number, asn_org,
               is_suspicious_asn, risk_score,
               threat_level, details
          FROM connection_events
          ORDER BY id DESC
          LIMIT ?
          """,
          (limit,),
        ) as cursor:
          rows = await cursor.fetchall()
          columns = [d[0] for d in cursor.description]
          events = [dict(zip(columns, row)) for row in rows]
      for event in events:
        details_obj = {}
        details_value = event.get("details")
        if isinstance(details_value, str) and details_value:
          try:
            details_obj = json.loads(details_value)
          except Exception:
            details_obj = {}
        elif isinstance(details_value, dict):
          details_obj = details_value
        event["event_type"] = str(details_obj.get("event_type") or "")
        event["country_code"] = self._resolve_country_code(
          details_obj,
          event.get("source_ip"),
        )
        event["threat_label"] = self._get_event_threat_label(event)
        event["timestamp_unix"] = self._parse_timestamp_unix(event.get("timestamp"))
        event["operator_advice"] = self._build_operator_advice(event)
      return web.json_response({"events": events, "count": len(events)})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_firewall(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    count = await self._firewall.get_banned_count()
    return web.json_response(
      {
        "simulation_mode": self._firewall.simulation_mode,
        "active_bans": count,
        "firewall": repr(self._firewall),
      }
    )

  async def _handle_firewall_bans(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    limit = min(int(request.query.get("limit", "500")), 2000)
    try:
      items = await self._firewall.list_banned_ips(limit=limit)
      return web.json_response({"items": items, "count": len(items)})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_top_attackers(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    limit = min(int(request.query.get("limit", "10")), 50)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT source_ip,
               COUNT(*) as ban_count,
               MAX(risk_score) as max_risk,
               MAX(banned_at) as last_ban
          FROM ban_history
          GROUP BY source_ip
          ORDER BY ban_count DESC
          LIMIT ?
          """,
          (limit,),
        ) as cursor:
          rows = await cursor.fetchall()
          columns = [d[0] for d in cursor.description]
          attackers = [dict(zip(columns, row)) for row in rows]
      return web.json_response({"attackers": attackers})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_top_portscanned_ports(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    limit = min(int(request.query.get("limit", "10")), 100)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT
               CASE
                 WHEN player_name LIKE 'port_%' THEN substr(player_name, 6)
                 ELSE ''
               END AS scanned_port,
               COUNT(*) AS scan_count,
               MAX(timestamp) AS last_seen
          FROM connection_events
          WHERE connection_type = 'portscan'
          GROUP BY scanned_port
          HAVING scanned_port <> ''
          ORDER BY scan_count DESC, last_seen DESC
          LIMIT ?
          """,
          (limit,),
        ) as cursor:
          rows = await cursor.fetchall()
          ports = [
            {
              "port": str(row[0]),
              "scan_count": int(row[1]),
              "last_seen": row[2],
            }
            for row in rows
          ]
      return web.json_response({"ports": ports, "count": len(ports)})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_events_timeline(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    hours = min(int(request.query.get("hours", "24")), 168)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
               COUNT(*) as count
          FROM connection_events
          WHERE COALESCE(strftime('%s', timestamp), 0) >= strftime('%s', 'now', ? || ' hours')
          GROUP BY hour
          ORDER BY hour ASC
          """,
          (f"-{hours}",),
        ) as cursor:
          rows = await cursor.fetchall()
          timeline = [{"hour": r[0], "count": r[1]} for r in rows]
      return web.json_response({"timeline": timeline})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_asn_stats(self, request: web.Request) -> web.Response:
    """Top countries (if present in event details) and ASN organizations."""
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT COALESCE(asn_org, 'Unknown') as org,
               COUNT(*) as count,
               SUM(CASE WHEN is_suspicious_asn=1 THEN 1 ELSE 0 END) as suspicious_count
          FROM connection_events
          WHERE asn_org IS NOT NULL
          GROUP BY asn_org
          ORDER BY count DESC
          LIMIT 20
          """
        ) as cursor:
          rows = await cursor.fetchall()
          orgs = [{"org": r[0], "count": r[1], "suspicious": r[2]} for r in rows]

      # Country values are optional and inferred from event details JSON.
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT source_ip, details
          FROM connection_events
          ORDER BY id DESC
          LIMIT 5000
          """
        ) as cursor:
          rows = await cursor.fetchall()

          counts: dict[str, int] = {}
          for source_ip, details_value in rows:
            details_obj = {}
            if isinstance(details_value, str) and details_value:
              try:
                details_obj = json.loads(details_value)
              except Exception:
                details_obj = {}
            elif isinstance(details_value, dict):
              details_obj = details_value

            code = self._resolve_country_code(details_obj, source_ip) or "ZZ"
            counts[code] = counts.get(code, 0) + 1

          countries = [
            {"country": country, "count": count}
            for country, count in sorted(
              counts.items(),
              key=lambda item: item[1],
              reverse=True,
            )[:30]
          ]

      return web.json_response({"asn_orgs": orgs, "countries": countries})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_geo_heatmap(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    hours = min(int(request.query.get("hours", "24")), 168)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT source_ip, details
          FROM connection_events
          WHERE COALESCE(strftime('%s', timestamp), 0) >= strftime('%s', 'now', ? || ' hours')
          ORDER BY id DESC
          LIMIT 5000
          """,
          (f"-{hours}",),
        ) as cursor:
          rows = await cursor.fetchall()

          counts: dict[str, int] = {}
          for source_ip, details_value in rows:
            details_obj = {}
            if isinstance(details_value, str) and details_value:
              try:
                details_obj = json.loads(details_value)
              except Exception:
                details_obj = {}
            elif isinstance(details_value, dict):
              details_obj = details_value

            code = self._resolve_country_code(details_obj, source_ip)
            if not code or code == "ZZ":
              continue
            counts[code] = counts.get(code, 0) + 1

          points = [
            {"country": country, "count": count}
            for country, count in sorted(
              counts.items(),
              key=lambda item: item[1],
              reverse=True,
            )[:150]
          ]
      return web.json_response({"points": points, "hours": hours})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_threat_distribution(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT threat_level, COUNT(*) as count
          FROM connection_events
          GROUP BY threat_level
          ORDER BY count DESC
          """
        ) as cursor:
          rows = await cursor.fetchall()
          distribution = [{"level": r[0], "count": r[1]} for r in rows]
      return web.json_response({"distribution": distribution})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_plugin_stats(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT connection_type, COUNT(*) as count
          FROM connection_events
          GROUP BY connection_type
          ORDER BY count DESC
          """
        ) as cursor:
          rows = await cursor.fetchall()
          plugins = [{"plugin": r[0], "count": r[1]} for r in rows]
      return web.json_response({"plugins": plugins})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_blocklist(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    if not self._blocklist:
      return web.json_response(
        {
          "enabled": False,
          "mode": "disabled",
          "description": "Blocklist protection is not configured.",
        }
      )
    try:
      return web.json_response(await self._blocklist.get_status())
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_login_page(self, request: web.Request) -> web.Response:
    if self._bootstrap_token_is_valid():
      raise web.HTTPFound("/setup")
    next_path = self._normalize_next_path(
      request.query.get("next", "/dashboard"),
      "/dashboard",
    )
    if self._is_session_authenticated(request):
      raise web.HTTPFound(next_path)
    auth_ready = await self._admin_auth_available()
    html = LOGIN_HTML.replace("__NEXT_PATH__", json.dumps(next_path))
    html = html.replace("__AUTH_READY__", "true" if auth_ready else "false")
    html = html.replace(
      "__PUBLIC_DASHBOARD_ENABLED__",
      "true" if self._public_dashboard_enabled else "false",
    )
    html = html.replace(
      "__SETUP_MESSAGE__",
      json.dumps(
        "No admin user exists yet. Complete the first-boot setup flow and create an admin account."
      ),
    )
    html = self._render_ui_template(html)
    return web.Response(text=html, content_type="text/html")

  async def _handle_setup_page(self, request: web.Request) -> web.Response:
    if not self._bootstrap_token_is_valid():
      raise web.HTTPFound("/login")
    html = SETUP_HTML.replace("__SETUP_EXPIRY__", json.dumps(self._bootstrap_token_expires_at or "24 hours"))
    html = self._render_ui_template(html)
    return web.Response(text=html, content_type="text/html")

  async def _handle_login(self, request: web.Request) -> web.Response:
    if self._bootstrap_token_is_valid():
      return web.json_response(
        {"error": "setup_required", "message": "Initial setup must be completed before login.", "redirect_to": "/setup"},
        status=403,
      )
    client_ip = self._client_ip(request)
    if self._consume_rate_limit(
      self._login_attempts,
      client_ip,
      self._login_rate_limit_per_minute,
      60,
    ):
      return web.json_response(
        {"error": "too_many_attempts", "message": "Too many login attempts."},
        status=429,
      )
    try:
      payload = await request.json()
    except Exception:
      form_data = await request.post()
      payload = dict(form_data)

    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    next_path = self._normalize_next_path(
      str(payload.get("next", "/dashboard")).strip() or "/dashboard",
      "/dashboard",
    )
    if not await self._admin_auth_available():
      return self._json_auth_error()
    user = await self._db.get_admin_user_by_username(username)
    if not user or not verify_password(str(user.get("password_hash", "")), password):
      await self._log_audit(request, "auth.login_failed", actor_username=username or None, details={"reason": "invalid_credentials"})
      return web.json_response(
        {"error": "invalid_credentials", "message": "Invalid username or password."},
        status=401,
      )

    if int(user.get("totp_enabled", 0)):
      pending_token = secrets.token_urlsafe(24)
      self._pending_logins[pending_token] = {
        "username": user["username"],
        "next_path": next_path,
        "expires_at": time.time() + 300,
      }
      return web.json_response({"ok": True, "requires_totp": True, "pending_token": pending_token})

    response = web.json_response({"ok": True, "redirect_to": next_path})
    self._issue_session(response, request, username=user["username"])
    await self._db.record_admin_login(user["username"], client_ip)
    await self._log_audit(request, "auth.login_success", actor_username=user["username"], details={"method": "password_only"})
    return response

  async def _handle_login_totp(self, request: web.Request) -> web.Response:
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    pending_token = str(payload.get("pending_token", "")).strip()
    code = str(payload.get("totp_code", "")).strip()
    pending = self._pending_logins.get(pending_token)
    if not pending or float(pending.get("expires_at", 0)) <= time.time():
      self._pending_logins.pop(pending_token, None)
      return web.json_response({"error": "pending_auth_expired", "message": "The login challenge expired. Start again."}, status=401)
    username = str(pending.get("username", ""))
    user = await self._db.get_admin_user_by_username(username)
    if not user or not verify_totp_code(str(user.get("totp_secret", "")), code):
      await self._log_audit(request, "auth.totp_failed", actor_username=username, details={"reason": "invalid_totp"})
      return web.json_response({"error": "invalid_totp", "message": "Invalid TOTP code."}, status=401)

    self._pending_logins.pop(pending_token, None)
    response = web.json_response({"ok": True, "redirect_to": pending.get("next_path") or "/admin"})
    self._issue_session(response, request, username=username)
    await self._db.record_admin_login(username, self._client_ip(request))
    await self._log_audit(request, "auth.login_success", actor_username=username, details={"method": "password_totp"})
    return response

  async def _handle_admin_get_auth_settings(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    if not actor:
      return self._json_auth_error()

    user = await self._db.get_admin_user_by_username(actor)
    if not user:
      return web.json_response(
        {"error": "admin_user_not_found", "message": "Admin user profile was not found."},
        status=404,
      )

    return web.json_response(
      {
        "ok": True,
        "username": actor,
        "totp_enabled": bool(int(user.get("totp_enabled", 0))),
      }
    )

  async def _handle_admin_set_auth_settings(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    if not actor:
      return self._json_auth_error()

    try:
      payload = await request.json()
    except Exception:
      payload = {}

    if "totp_enabled" not in payload:
      return web.json_response(
        {"error": "missing_totp_enabled", "message": "totp_enabled is required."},
        status=400,
      )

    raw_enabled = payload.get("totp_enabled")
    if isinstance(raw_enabled, bool):
      enabled = raw_enabled
    elif isinstance(raw_enabled, (int, float)):
      enabled = bool(int(raw_enabled))
    elif isinstance(raw_enabled, str):
      enabled = raw_enabled.strip().lower() in {"1", "true", "yes", "on"}
    else:
      return web.json_response(
        {"error": "invalid_totp_enabled", "message": "totp_enabled must be a boolean-like value."},
        status=400,
      )

    user = await self._db.get_admin_user_by_username(actor)
    if not user:
      return web.json_response(
        {"error": "admin_user_not_found", "message": "Admin user profile was not found."},
        status=404,
      )

    if enabled and not str(user.get("totp_secret", "")).strip():
      return web.json_response(
        {
          "error": "totp_secret_missing",
          "message": "Cannot enable TOTP because this admin user has no TOTP secret.",
        },
        status=400,
      )

    updated = await self._db.set_admin_totp_enabled(actor, enabled)
    if not enabled:
      pending_for_actor = [
        token
        for token, item in self._pending_logins.items()
        if str(item.get("username", "")) == actor
      ]
      for token in pending_for_actor:
        self._pending_logins.pop(token, None)

    await self._log_audit(
      request,
      "admin.auth_settings_update",
      actor_username=actor,
      details={"totp_enabled": enabled, "updated": updated},
    )

    return web.json_response(
      {
        "ok": True,
        "username": actor,
        "totp_enabled": enabled,
        "updated": updated,
        "message": "TOTP requirement enabled." if enabled else "TOTP requirement disabled.",
      }
    )

  async def _handle_setup_begin(self, request: web.Request) -> web.Response:
    if not self._bootstrap_token_is_valid():
      return web.json_response({"error": "setup_unavailable", "message": "First-boot setup is not available anymore."}, status=403)
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    bootstrap_token = str(payload.get("bootstrap_token", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    password_confirm = str(payload.get("password_confirm", ""))
    if not verify_bootstrap_token(self._bootstrap_token_hash, bootstrap_token):
      await self._log_audit(request, "setup.begin_failed", actor_username=username or None, details={"reason": "invalid_bootstrap"})
      return web.json_response({"error": "invalid_bootstrap", "message": "Invalid bootstrap token."}, status=401)
    if not username or username.lower() == "admin":
      return web.json_response({"error": "invalid_username", "message": "Choose a non-default admin username."}, status=400)
    if password != password_confirm:
      return web.json_response({"error": "password_mismatch", "message": "Passwords do not match."}, status=400)
    is_valid, policy_message = check_password_policy(password)
    if not is_valid:
      return web.json_response({"error": "weak_password", "message": policy_message}, status=400)
    if await self._db.has_admin_users():
      return web.json_response({"error": "setup_completed", "message": "An admin user already exists."}, status=409)

    pending_token = secrets.token_urlsafe(24)
    totp_secret = generate_totp_secret()
    totp_uri = build_totp_uri(username, totp_secret)
    self._pending_setups[pending_token] = {
      "username": username,
      "password_hash": hash_password(password),
      "totp_secret": totp_secret,
      "expires_at": time.time() + 900,
    }
    await self._log_audit(request, "setup.begin_success", actor_username=username, details={"totp": True})
    return web.json_response({
      "ok": True,
      "pending_setup_token": pending_token,
      "totp_secret": totp_secret,
      "totp_uri": totp_uri,
      "totp_qr_data_url": build_totp_qr_data_url(totp_uri),
    })

  async def _handle_setup_complete(self, request: web.Request) -> web.Response:
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    pending_token = str(payload.get("pending_setup_token", "")).strip()
    totp_code = str(payload.get("totp_code", "")).strip()
    pending = self._pending_setups.get(pending_token)
    if not pending or float(pending.get("expires_at", 0)) <= time.time():
      self._pending_setups.pop(pending_token, None)
      return web.json_response({"error": "setup_expired", "message": "Setup session expired. Start again."}, status=401)
    if not verify_totp_code(str(pending.get("totp_secret", "")), totp_code):
      await self._log_audit(request, "setup.complete_failed", actor_username=str(pending.get("username", "")), details={"reason": "invalid_totp"})
      return web.json_response({"error": "invalid_totp", "message": "Invalid TOTP code."}, status=401)
    if await self._db.has_admin_users():
      self._pending_setups.pop(pending_token, None)
      return web.json_response({"error": "setup_completed", "message": "An admin user already exists."}, status=409)

    username = str(pending.get("username", ""))
    try:
      await self._db.create_admin_user(
        username=username,
        password_hash=str(pending.get("password_hash", "")),
        totp_secret=str(pending.get("totp_secret", "")),
        totp_enabled=True,
      )
    except Exception as exc:
      message = str(exc)
      if "readonly" in message.lower():
        return web.json_response(
          {
            "error": "database_readonly",
            "message": "Database is not writable by the service account. Repair ownership/permissions for /var/lib/wardenips and retry.",
          },
          status=500,
        )
      return web.json_response(
        {"error": "setup_failed", "message": message or "Admin setup failed."},
        status=500,
      )
    self._pending_setups.pop(pending_token, None)
    await self._clear_bootstrap_config()
    response = web.json_response({"ok": True, "redirect_to": "/admin", "message": "Initial admin setup completed."})
    self._issue_session(response, request, username=username)
    await self._db.record_admin_login(username, self._client_ip(request))
    await self._log_audit(request, "setup.complete_success", actor_username=username, details={"totp": True})
    return response

  async def _handle_root(self, request: web.Request) -> web.Response:
    if self._bootstrap_token_is_valid():
      raise web.HTTPFound("/setup")
    if self._homepage == "login":
      raise web.HTTPFound("/login")
    if self._homepage == "admin":
      raise web.HTTPFound("/admin")
    raise web.HTTPFound("/dashboard")

  async def _handle_logout(self, request: web.Request) -> web.Response:
    if request.method == "GET":
      response = web.HTTPFound("/login")
    else:
      response = web.json_response({"ok": True, "redirect_to": "/login"})
    self._clear_session(request, response)
    return response

  async def _handle_session_activity(self, request: web.Request) -> web.Response:
    if not self._is_session_authenticated(request):
      return self._json_auth_error()
    token = self._get_session_token(request)
    if self._consume_rate_limit(
      self._activity_touches,
      token,
      limit=1,
      window_seconds=self._activity_touch_interval_seconds,
    ):
      return web.json_response(
        {"ok": True, "ttl_seconds": max(int(self._sessions.get(token, 0) - time.time()), 0)}
      )
    self._touch_session(request)
    return web.json_response(
      {"ok": True, "ttl_seconds": max(int(self._sessions.get(token, 0) - time.time()), 0)}
    )

  def _normalize_whitelist_entry(self, value: str) -> tuple[str, str]:
    candidate = str(value or "").strip()
    if not candidate:
      raise ValueError("Whitelist entry is required.")
    if "/" in candidate:
      network = ipaddress.ip_network(candidate, strict=False)
      return str(network), "cidr"
    return str(ipaddress.ip_address(candidate)), "ip"

  async def _handle_admin_get_whitelist(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    return web.json_response(
      {
        "ok": True,
        "ips": list(self._config.get("whitelist.ips", []) or []),
        "cidr_ranges": list(self._config.get("whitelist.cidr_ranges", []) or []),
      }
    )

  async def _handle_admin_add_whitelist(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    raw_value = str(payload.get("value", "")).strip()
    try:
      normalized, entry_type = self._normalize_whitelist_entry(raw_value)
    except Exception:
      return web.json_response({"error": "invalid_entry", "message": "Provide a valid IPv4/IPv6 address or CIDR range."}, status=400)

    ip_values = list(self._config.get("whitelist.ips", []) or [])
    cidr_values = list(self._config.get("whitelist.cidr_ranges", []) or [])

    if entry_type == "ip":
      if normalized in ip_values:
        return web.json_response({"ok": True, "message": f"{normalized} is already in whitelist.", "entry": normalized, "entry_type": entry_type})
      ip_values.append(normalized)
    else:
      if normalized in cidr_values:
        return web.json_response({"ok": True, "message": f"{normalized} is already in whitelist.", "entry": normalized, "entry_type": entry_type})
      cidr_values.append(normalized)

    await self._config.patch_values(
      {
        "whitelist.ips": ip_values,
        "whitelist.cidr_ranges": cidr_values,
      }
    )
    if self._whitelist:
      await self._whitelist.reload(self._config)

    await self._log_audit(request, "admin.whitelist_add", actor_username=actor, details={"entry": normalized, "entry_type": entry_type})
    return web.json_response({"ok": True, "message": f"Added {normalized} to whitelist.", "entry": normalized, "entry_type": entry_type})

  async def _handle_admin_remove_whitelist(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    raw_value = str(payload.get("value", "")).strip()
    try:
      normalized, entry_type = self._normalize_whitelist_entry(raw_value)
    except Exception:
      return web.json_response({"error": "invalid_entry", "message": "Provide a valid IPv4/IPv6 address or CIDR range."}, status=400)

    ip_values = list(self._config.get("whitelist.ips", []) or [])
    cidr_values = list(self._config.get("whitelist.cidr_ranges", []) or [])
    changed = False

    if entry_type == "ip" and normalized in ip_values:
      ip_values = [item for item in ip_values if str(item).strip() != normalized]
      changed = True
    if entry_type == "cidr" and normalized in cidr_values:
      cidr_values = [item for item in cidr_values if str(item).strip() != normalized]
      changed = True

    if not changed:
      return web.json_response({"ok": True, "message": f"{normalized} was not present in whitelist.", "entry": normalized, "entry_type": entry_type})

    await self._config.patch_values(
      {
        "whitelist.ips": ip_values,
        "whitelist.cidr_ranges": cidr_values,
      }
    )
    if self._whitelist:
      await self._whitelist.reload(self._config)

    await self._log_audit(request, "admin.whitelist_remove", actor_username=actor, details={"entry": normalized, "entry_type": entry_type})
    return web.json_response({"ok": True, "message": f"Removed {normalized} from whitelist.", "entry": normalized, "entry_type": entry_type})

  async def _handle_admin_unban_ip(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    payload = await request.json()
    ip_value = str(payload.get("ip", "")).strip()
    if not ip_value:
      return web.json_response({"error": "invalid_ip", "message": "IP address is required."}, status=400)
    firewall_result = await self._firewall.unban_ip(ip_value)
    deactivated = await self._db.deactivate_ban_by_ip(ip_value)
    await self._log_audit(request, "admin.unban_ip", actor_username=actor, details={"ip": ip_value, "firewall_result": firewall_result, "deactivated_records": deactivated})
    return web.json_response(
      {
        "ok": firewall_result,
        "message": f"Removed {ip_value} from firewall bans.",
        "deactivated_records": deactivated,
      }
    )

  async def _handle_admin_ban_ip(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    ip_value = str(payload.get("ip", "")).strip()
    if not ip_value:
      return web.json_response({"error": "invalid_ip", "message": "IP address is required."}, status=400)
    try:
      ipaddress.ip_address(ip_value)
    except Exception:
      return web.json_response({"error": "invalid_ip", "message": "Provide a valid IPv4 or IPv6 address."}, status=400)

    duration_value = payload.get("duration", self._config.get("firewall.ipset.default_ban_duration", 0))
    try:
      duration = max(int(duration_value), 0)
    except Exception:
      duration = max(int(self._config.get("firewall.ipset.default_ban_duration", 0)), 0)

    reason = str(payload.get("reason", "")).strip() or "[ADMIN] Manual ban from dashboard"
    risk_score_value = payload.get("risk_score", 100)
    try:
      risk_score = min(max(int(risk_score_value), 0), 100)
    except Exception:
      risk_score = 100

    banned = await self._firewall.ban_ip(ip_value, duration=duration, reason=reason)
    if not banned:
      return web.json_response(
        {
          "ok": False,
          "message": f"Ban request for {ip_value} was skipped (already banned, whitelisted, or blocked by safety checks).",
        },
        status=409,
      )

    await self._db.log_ban(ip_value, reason, risk_score, duration)
    await self._notifier.notify_ban(
      ip=ip_value,
      reason=reason,
      risk=risk_score,
      duration=duration,
      plugin="admin",
    )
    await self._log_audit(
      request,
      "admin.ban_ip",
      actor_username=actor,
      details={"ip": ip_value, "duration": duration, "reason": reason, "risk_score": risk_score},
    )
    return web.json_response(
      {
        "ok": True,
        "message": f"{ip_value} was added to firewall ban list.",
        "duration": duration,
        "risk_score": risk_score,
      }
    )

  async def _handle_admin_deactivate_ban(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    payload = await request.json()
    source_ip = str(payload.get("source_ip", "")).strip()
    if not source_ip:
      return web.json_response(
        {"error": "invalid_ip", "message": "Source IP is required."},
        status=400,
      )
    updated = await self._db.deactivate_ban_by_ip(source_ip)
    await self._log_audit(request, "admin.deactivate_ban", actor_username=actor, details={"source_ip": source_ip, "updated": updated})
    return web.json_response({"ok": True, "updated": updated})

  async def _handle_admin_deactivate_all_bans(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    updated = await self._db.deactivate_all_bans()
    await self._log_audit(request, "admin.deactivate_all_bans", actor_username=actor, details={"updated": updated})
    return web.json_response({"ok": True, "updated": updated})

  async def _handle_admin_enforce_simulated_bans(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)

    if not self._firewall.simulation_mode:
      return web.json_response(
        {
          "error": "simulation_not_enabled",
          "message": "Simulation mode is not enabled. This action is only available while simulation mode is active.",
        },
        status=400,
      )

    now_unix = int(time.time())
    candidates: list[dict[str, object]] = []
    expired_ips: set[str] = set()

    async with self._db._lock:
      async with self._db._db.execute(
        """
        SELECT source_ip, reason, ban_duration, expires_at
        FROM ban_history
        WHERE is_active = 1
        ORDER BY banned_at DESC
        LIMIT 5000
        """
      ) as cursor:
        rows = await cursor.fetchall()

    seen_ips: set[str] = set()
    for source_ip, reason, ban_duration, expires_at in rows:
      ip_value = str(source_ip or "").strip()
      if not ip_value or ip_value in seen_ips:
        continue
      seen_ips.add(ip_value)

      duration = int(ban_duration or 0)
      expires_unix = self._parse_timestamp_unix(expires_at)
      if expires_unix is not None:
        remaining = expires_unix - now_unix
        if remaining <= 0:
          expired_ips.add(ip_value)
          continue
        duration = remaining

      candidates.append(
        {
          "ip": ip_value,
          "duration": duration,
          "reason": str(reason or "simulation replay"),
        }
      )

    deactivated_expired = 0
    for ip_value in expired_ips:
      deactivated_expired += await self._db.deactivate_ban_by_ip(ip_value)

    result = await self._firewall.enforce_db_bans(candidates)
    await self._log_audit(
      request,
      "admin.enforce_simulated_bans",
      actor_username=actor,
      details={
        "requested": result.get("requested", 0),
        "applied": result.get("applied", 0),
        "failed": result.get("failed", 0),
        "skipped": result.get("skipped", 0),
        "expired_deactivated": deactivated_expired,
      },
    )
    return web.json_response(
      {
        "ok": True,
        "requested": result.get("requested", 0),
        "applied": result.get("applied", 0),
        "failed": result.get("failed", 0),
        "skipped": result.get("skipped", 0),
        "expired_deactivated": deactivated_expired,
      }
    )

  async def _handle_admin_reconcile_bans(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)

    now_unix = int(time.time())
    desired: dict[str, dict[str, object]] = {}
    expired_ips: set[str] = set()
    skipped_invalid = 0
    db_total_bans = 0

    async with self._db._lock:
      async with self._db._db.execute("SELECT COUNT(*) FROM ban_history") as total_cursor:
        total_row = await total_cursor.fetchone()
        db_total_bans = int(total_row[0]) if total_row else 0
      async with self._db._db.execute(
        """
        SELECT source_ip, reason, ban_duration, expires_at
        FROM ban_history
        WHERE is_active = 1
        ORDER BY banned_at DESC
        LIMIT 20000
        """
      ) as cursor:
        rows = await cursor.fetchall()

    for source_ip, reason, ban_duration, expires_at in rows:
      ip_value = str(source_ip or "").strip()
      if not ip_value or ip_value in desired:
        continue
      try:
        ipaddress.ip_address(ip_value)
      except Exception:
        skipped_invalid += 1
        continue

      try:
        duration = max(int(ban_duration or 0), 0)
      except Exception:
        duration = 0

      expires_unix = self._parse_timestamp_unix(expires_at)
      if expires_unix is not None:
        remaining = expires_unix - now_unix
        if remaining <= 0:
          expired_ips.add(ip_value)
          continue
        duration = max(int(remaining), 1)

      desired[ip_value] = {
        "duration": duration,
        "reason": str(reason or "db reconcile"),
      }

    deactivated_expired = 0
    for ip_value in expired_ips:
      deactivated_expired += await self._db.deactivate_ban_by_ip(ip_value)

    candidates = [
      {
        "ip": ip_value,
        "duration": int(meta.get("duration", 0)),
        "reason": str(meta.get("reason", "db reconcile")),
      }
      for ip_value, meta in desired.items()
    ]

    firewall_items = await self._firewall.list_banned_ips(limit=20000)
    firewall_ips = {
      str(item.get("ip") or "").strip()
      for item in firewall_items
      if str(item.get("ip") or "").strip()
    }
    desired_ips = set(desired.keys())

    enforce_result = await self._firewall.enforce_db_bans(candidates)
    re_applied = int(enforce_result.get("applied", 0))
    apply_failed = int(enforce_result.get("failed", 0))
    apply_skipped = int(enforce_result.get("skipped", 0))
    requested = int(enforce_result.get("requested", 0))

    # Reconcile is intentionally one-way (DB -> Firewall).
    # Keep firewall-only entries untouched so manual operator bans are preserved.
    removed_extra = 0
    remove_failed = 0
    firewall_extra_untouched = len(firewall_ips - desired_ips)

    await self._log_audit(
      request,
      "admin.reconcile_bans",
      actor_username=actor,
      details={
        "db_total_bans": db_total_bans,
        "db_active_considered": len(desired_ips),
        "expired_deactivated": deactivated_expired,
        "invalid_rows_skipped": skipped_invalid,
        "firewall_before": len(firewall_ips),
        "requested": requested,
        "reapplied": re_applied,
        "apply_failed": apply_failed,
        "apply_skipped": apply_skipped,
        "removed_extra": removed_extra,
        "remove_failed": remove_failed,
        "firewall_extra_untouched": firewall_extra_untouched,
      },
    )

    return web.json_response(
      {
        "ok": True,
        "db_total_bans": db_total_bans,
        "db_active_considered": len(desired_ips),
        "expired_deactivated": deactivated_expired,
        "invalid_rows_skipped": skipped_invalid,
        "firewall_before": len(firewall_ips),
        "requested": requested,
        "reapplied": re_applied,
        "apply_failed": apply_failed,
        "apply_skipped": apply_skipped,
        "removed_extra": removed_extra,
        "remove_failed": remove_failed,
        "firewall_extra_untouched": firewall_extra_untouched,
      }
    )

  async def _handle_admin_query_records(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)

    try:
      payload = await request.json()
    except Exception:
      payload = {}

    field = str(payload.get("field", "auto") or "auto").strip().lower()
    value = str(payload.get("value", "") or "").strip()
    limit = min(max(int(payload.get("limit", 200) or 200), 1), 1000)

    if not value:
      return web.json_response({"error": "invalid_query", "message": "Query value is required."}, status=400)

    if field not in {"auto", "ip", "asn", "user"}:
      return web.json_response({"error": "invalid_field", "message": "Field must be one of: auto, ip, asn, user."}, status=400)

    if field == "auto":
      try:
        ipaddress.ip_address(value)
        resolved_field = "ip"
      except Exception:
        normalized = value.upper().strip()
        if normalized.startswith("AS") and normalized[2:].isdigit():
          resolved_field = "asn"
        elif normalized.isdigit():
          resolved_field = "asn"
        else:
          resolved_field = "user"
    else:
      resolved_field = field

    event_query = """
      SELECT timestamp, source_ip, player_name, connection_type,
             asn_number, asn_org, risk_score, threat_level, details
      FROM connection_events
    """
    event_params: list[object] = []

    if resolved_field == "ip":
      event_query += " WHERE source_ip = ?"
      event_params.append(value)
    elif resolved_field == "asn":
      normalized = value.upper().strip()
      asn_number: Optional[int] = None
      if normalized.startswith("AS"):
        normalized = normalized[2:]
      if normalized.isdigit():
        asn_number = int(normalized)
      if asn_number is not None:
        event_query += " WHERE asn_number = ? OR LOWER(COALESCE(asn_org, '')) LIKE ?"
        event_params.extend([asn_number, f"%{value.lower()}%"])
      else:
        event_query += " WHERE LOWER(COALESCE(asn_org, '')) LIKE ?"
        event_params.append(f"%{value.lower()}%")
    else:
      event_query += " WHERE LOWER(COALESCE(player_name, '')) LIKE ?"
      event_params.append(f"%{value.lower()}%")

    event_query += " ORDER BY timestamp DESC LIMIT ?"
    event_params.append(limit)

    records: list[dict[str, object]] = []

    async with self._db._lock:
      async with self._db._db.execute(event_query, event_params) as cursor:
        rows = await cursor.fetchall()
      for timestamp, source_ip, player_name, connection_type, asn_number, asn_org, risk_score, threat_level, details_value in rows:
        details_obj = {}
        if isinstance(details_value, str) and details_value:
          try:
            details_obj = json.loads(details_value)
          except Exception:
            details_obj = {}
        elif isinstance(details_value, dict):
          details_obj = details_value
        records.append(
          {
            "kind": "event",
            "timestamp": timestamp,
            "source_ip": source_ip,
            "player_name": player_name,
            "connection_type": connection_type,
            "event_type": str(details_obj.get("event_type") or ""),
            "asn_number": asn_number,
            "asn_org": asn_org,
            "risk_score": risk_score,
            "threat_level": threat_level,
          }
        )

      if resolved_field == "ip":
        async with self._db._db.execute(
          """
          SELECT banned_at, source_ip, reason, risk_score, ban_duration, expires_at, is_active
          FROM ban_history
          WHERE source_ip = ?
          ORDER BY banned_at DESC
          LIMIT ?
          """,
          (value, limit),
        ) as cursor:
          ban_rows = await cursor.fetchall()
        for banned_at, source_ip, reason, risk_score, ban_duration, expires_at, is_active in ban_rows:
          records.append(
            {
              "kind": "ban",
              "timestamp": banned_at,
              "source_ip": source_ip,
              "reason": reason,
              "risk_score": risk_score,
              "ban_duration": ban_duration,
              "expires_at": expires_at,
              "is_active": bool(is_active),
            }
          )

    records.sort(
      key=lambda item: self._parse_timestamp_unix(item.get("timestamp")) or 0,
      reverse=True,
    )
    if len(records) > limit:
      records = records[:limit]

    await self._log_audit(
      request,
      "admin.query_records",
      actor_username=actor,
      details={"field": resolved_field, "value": value, "count": len(records), "limit": limit},
    )

    return web.json_response(
      {
        "ok": True,
        "field": resolved_field,
        "value": value,
        "count": len(records),
        "records": records,
      }
    )

  async def _handle_admin_flush_firewall(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    flushed = await self._firewall.flush()
    updated = await self._db.deactivate_all_bans()
    await self._log_audit(request, "admin.flush_firewall", actor_username=actor, details={"flushed": flushed, "deactivated_records": updated})
    return web.json_response({"ok": flushed, "deactivated_records": updated})

  async def _handle_admin_clear_events(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    deleted = await self._db.clear_events()
    await self._log_audit(request, "admin.clear_events", actor_username=actor, details={"deleted": deleted})
    return web.json_response({"ok": True, "deleted": deleted})

  async def _handle_admin_clear_ban_history(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    deleted = await self._db.clear_ban_history()
    await self._log_audit(request, "admin.clear_ban_history", actor_username=actor, details={"deleted": deleted})
    return web.json_response({"ok": True, "deleted": deleted})

  async def _handle_admin_test_notification(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    if not self._notifier:
      return web.json_response(
        {"error": "notifications_unavailable", "message": "Notification manager is not available."},
        status=503,
      )
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    channel = str(payload.get("channel", "all")).strip().lower() or "all"
    try:
      result = await self._notifier.send_test_notification(channel)
    except ValueError as exc:
      return web.json_response({"error": "invalid_channel", "message": str(exc)}, status=400)
    except RuntimeError as exc:
      return web.json_response({"error": "notification_unavailable", "message": str(exc)}, status=503)
    summary = ", ".join(f"{name}: {status}" for name, status in result["results"].items())
    await self._log_audit(request, "admin.test_notification", actor_username=actor, details={"channel": channel, "results": result.get("results", {})})
    return web.json_response({"ok": True, "message": f"Test notification dispatched ({summary}).", **result})

  async def _handle_admin_update_status(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    checker = UpdateChecker(current_version=__version__)
    return web.json_response(await checker.get_status())

  def _set_nested_config_value(self, payload: dict, dotted_path: str, value) -> None:
    current = payload
    segments = [segment for segment in str(dotted_path).split(".") if segment]
    for segment in segments[:-1]:
      if segment not in current or not isinstance(current[segment], dict):
        current[segment] = {}
      current = current[segment]
    if segments:
      current[segments[-1]] = value

  async def _handle_admin_get_config(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    config_data = self._config.raw
    yaml_text = await self._config.get_yaml_text()
    return web.json_response(
      {
        "ok": True,
        "config": config_data,
        "yaml": yaml_text,
        "message": "Some runtime changes apply immediately in the dashboard, while service-level changes may require a restart.",
      }
    )

  async def _handle_admin_save_config(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    yaml_text = str(payload.get("yaml", "")).strip()
    if not yaml_text:
      return web.json_response({"error": "invalid_config", "message": "YAML content is required."}, status=400)
    try:
      await self._config.save_yaml_text(yaml_text)
    except Exception as exc:
      return web.json_response({"error": "config_write_failed", "message": str(exc)}, status=500)
    self._initialize_config()
    desired_simulation, effective_simulation = self._sync_firewall_simulation_mode()
    await self._log_audit(request, "admin.save_config", actor_username=actor, details={"mode": "yaml", "bytes": len(yaml_text)})
    current_yaml = await self._config.get_yaml_text()
    message = "Configuration saved. Restart WardenIPS if you changed firewall, plugin, or notification wiring."
    if (not desired_simulation) and effective_simulation:
      message = (
        "Configuration saved. Simulation mode remains active because firewall tools/permissions are not currently available at runtime."
      )
    return web.json_response(
      {
        "ok": True,
        "message": message,
        "config": self._config.raw,
        "yaml": current_yaml,
      }
    )

  async def _handle_admin_patch_config(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    try:
      payload = await request.json()
    except Exception:
      payload = {}
    changes = payload.get("changes") or {}
    if not isinstance(changes, dict) or not changes:
      return web.json_response({"error": "invalid_changes", "message": "At least one config change is required."}, status=400)
    try:
      normalized_changes = {str(key): value for key, value in changes.items()}
      await self._config.patch_values(normalized_changes)
    except Exception as exc:
      return web.json_response({"error": "config_write_failed", "message": str(exc)}, status=500)
    self._initialize_config()
    desired_simulation, effective_simulation = self._sync_firewall_simulation_mode()
    await self._log_audit(request, "admin.patch_config", actor_username=actor, details={"changes": sorted(str(key) for key in changes.keys())})
    current_yaml = await self._config.get_yaml_text()
    message = "Configuration updated."
    if (not desired_simulation) and effective_simulation:
      message = (
        "Configuration updated. Simulation mode remains active because firewall tools/permissions are not currently available at runtime."
      )
    return web.json_response(
      {
        "ok": True,
        "message": message,
        "config": self._config.raw,
        "yaml": current_yaml,
      }
    )

  async def _handle_dashboard(self, request: web.Request) -> web.Response:
    if not self._public_dashboard_enabled:
      auth_redirect = self._require_dashboard_auth(request)
      if auth_redirect is not None:
        return auth_redirect
    is_authenticated = self._is_session_authenticated(request)
    if is_authenticated:
      self._touch_session(request)
    admin_href = "/admin" if is_authenticated else f"/login?{urlencode({'next': '/admin'})}"
    admin_label = "Open Admin" if is_authenticated else "Admin Login"
    html = DASHBOARD_HTML.replace("__ADMIN_HREF__", admin_href)
    html = html.replace("__ADMIN_LABEL__", admin_label)
    html = self._render_ui_template(html)
    return web.Response(text=html, content_type="text/html")

  async def _handle_dashboard_v2(self, request: web.Request) -> web.Response:
    auth_redirect = self._require_dashboard_auth(request)
    if auth_redirect is not None:
      return auth_redirect
    if request.path == "/v2":
      raise web.HTTPFound("/admin")
    self._touch_session(request)
    html = DASHBOARD_V2_HTML.replace("__SESSION_TIMEOUT_MS__", str(self._session_ttl * 1000))
    html = self._render_ui_template(html)
    return web.Response(text=html, content_type="text/html")


# ══════════════════════════════════════════════════════════════════════
#  Full SPA Dashboard — Dark theme, auto-refresh, CSS-only charts
# ══════════════════════════════════════════════════════════════════════

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WardenIPS Login</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#110f18;--bg2:#1d1730;--panel:#1d1a29;--panel2:#171420;--surface:#140f1f;--surface2:#120d1b;--b:#3b3150;--txt:#f5f1ea;--muted:#b8accc;--blue:#5ea1ff;--cyan:#39d0c6;--green:#4fd18f;--yellow:#ffbe5c;--red:#ff6f7e;--accent:#ff875f;--shadow:0 30px 80px #00000045}
html{font-size:clamp(13px,0.32vw + 12px,16px)}
body{min-height:100vh;display:grid;place-items:center;font-family:Georgia,"Aptos",serif;background:radial-gradient(circle at top left,var(--bg2) 0%,var(--bg) 48%,var(--surface) 100%);color:var(--txt);padding:20px;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(circle at 85% 12%,color-mix(in srgb,var(--accent) 18%,transparent) 0%,transparent 24%),radial-gradient(circle at 12% 78%,color-mix(in srgb,var(--cyan) 16%,transparent) 0%,transparent 28%);pointer-events:none}
.shell{width:min(100%,1120px);display:grid;grid-template-columns:1.1fr .9fr;gap:20px;align-items:stretch}
.info-card,.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:24px;padding:28px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:var(--surface);border:1px solid var(--b);color:var(--blue);font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}
h1{font-size:2rem;letter-spacing:-.04em;margin-bottom:8px}
p{color:var(--muted);line-height:1.6;margin-bottom:16px}
.lead{font-size:1rem;color:var(--txt);max-width:38ch}
.feature-list{display:grid;gap:12px;margin:20px 0}
.feature{padding:14px 16px;border-radius:16px;border:1px solid var(--b);background:linear-gradient(180deg,var(--surface),var(--surface2))}
.feature strong{display:block;font-size:.9rem;margin-bottom:6px}
.feature span{font-size:.82rem;color:var(--muted);line-height:1.5}
.quick-meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:6px}
.quick-meta span{display:inline-flex;align-items:center;gap:8px;padding:8px 10px;border-radius:999px;background:var(--surface);border:1px solid var(--b);font-size:.76rem;color:var(--muted)}
.field{display:grid;gap:7px;margin-bottom:14px}
label{font-size:.8rem;font-weight:700;color:var(--txt)}
input{width:100%;background:var(--surface2);border:1px solid var(--b);color:var(--txt);border-radius:14px;padding:13px 14px;font-size:.95rem;outline:none;transition:border-color .2s ease,box-shadow .2s ease}
input:focus{border-color:var(--blue);box-shadow:0 0 0 4px color-mix(in srgb,var(--blue) 18%,transparent)}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:8px}
button{appearance:none;border:0;background:linear-gradient(135deg,var(--accent),#ff6f61);color:white;padding:13px 16px;border-radius:14px;font-size:.95rem;font-weight:800;cursor:pointer;min-width:150px}
button.secondary{background:var(--surface2);border:1px solid var(--b);color:var(--txt)}
a.button-link{display:inline-flex;align-items:center;justify-content:center;background:var(--surface2);border:1px solid var(--b);color:var(--txt);padding:13px 16px;border-radius:14px;font-size:.92rem;font-weight:700;text-decoration:none;min-width:180px}
button[disabled]{opacity:.65;cursor:wait}
.hint{font-size:.78rem;color:var(--muted)}
.msg{margin-top:14px;padding:12px 14px;border-radius:12px;font-size:.85rem;display:none}
.msg.err{display:block;background:#32131a;color:#ffb3bc;border:1px solid #6a2432}
.msg.ok{display:block;background:#0d2e26;color:#8ef0c7;border:1px solid #175343}
.foot{margin-top:14px;font-size:.76rem;color:var(--muted);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.secondary-actions{display:flex;gap:12px;margin-top:14px;flex-wrap:wrap}
.secondary-actions[hidden]{display:none}
.aux-links{display:flex;gap:12px;flex-wrap:wrap;margin-top:12px}
.aux-links a{color:var(--blue);text-decoration:none;font-size:.82rem}
.aux-links a:hover{text-decoration:underline}
.panel{display:none}
.panel.active{display:block}
.stack{display:grid;gap:12px}
.code-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px}
.code-grid input{text-align:center;font-size:1.05rem;font-weight:800;padding:12px 0}
@media(max-width:900px){.shell{grid-template-columns:1fr}.info-card{order:2}.card{order:1}}
@media(max-width:640px){.row,.secondary-actions{flex-direction:column;align-items:stretch}button,a.button-link{width:100%}.foot{flex-direction:column}.code-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="shell">
  <div class="info-card">
    <div class="eyebrow">Admin Access</div>
    <h1>Operational access with a tighter boundary.</h1>
    <p class="lead">Admin sessions are separated from the public dashboard and can require a second factor when database-backed accounts are enabled.</p>
    <div class="feature-list">
      <div class="feature"><strong>Scoped operations</strong><span>Firewall changes, ban maintenance, notification tests, and configuration editing stay behind the session boundary.</span></div>
      <div class="feature"><strong>Two-stage login</strong><span>Password verification can hand off to a TOTP challenge without exposing privileged routes.</span></div>
      <div class="feature"><strong>Managed identities</strong><span>Admin access is handled by managed users created during first-boot setup, with optional TOTP verification.</span></div>
    </div>
    <div class="quick-meta">
      <span>Route: /admin</span>
      <span>Auth mode: password + optional TOTP</span>
      <span>Session: 10m idle timeout</span>
    </div>
    <div class="aux-links">
      <a href="/dashboard">Open Public Dashboard</a>
      <a href="https://github.com/msncakma/WardenIPS" target="_blank" rel="noopener">Repository</a>
      <a href="https://github.com/msncakma/WardenIPS/stargazers" target="_blank" rel="noopener">Star on GitHub</a>
      <a href="https://github.com/msncakma/WardenIPS/issues" target="_blank" rel="noopener">Report an Issue</a>
      <a href="https://ko-fi.com/msncakma" target="_blank" rel="noopener">Support on Ko-fi</a>
    </div>
  </div>
  <div class="card">
    <div id="passwordPanel" class="panel active">
      <div class="eyebrow">Sign In</div>
      <h1>Sign in to WardenIPS</h1>
      <p id="intro">Use your admin username and password. Managed admin users can require TOTP after the password step.</p>
      <form id="loginForm">
        <div class="field">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" autocomplete="username" spellcheck="false">
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password">
        </div>
        <div class="row">
          <div class="hint" id="hint">Input changes are throttled and login attempts are rate-limited.</div>
          <button id="submitBtn" type="submit">Continue</button>
        </div>
      </form>
    </div>
    <div id="totpPanel" class="panel">
      <div class="eyebrow">Second Factor</div>
      <h1>Enter your authenticator code</h1>
      <p>Use the 6-digit code from your TOTP app to complete the login.</p>
      <form id="totpForm" class="stack">
        <div class="field">
          <label for="totpCode">Authenticator Code</label>
          <input id="totpCode" name="totpCode" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456">
        </div>
        <div class="row">
          <button id="totpSubmitBtn" type="submit">Verify</button>
          <button id="backBtn" class="secondary" type="button">Back</button>
        </div>
      </form>
    </div>
    <div id="message" class="msg"></div>
    <div id="guestActions" class="secondary-actions">
      <a class="button-link" href="/dashboard">View Dashboard Without Login</a>
    </div>
    <div class="foot"><span id="modeHint">WardenIPS v__APP_VERSION__ · by __APP_AUTHOR__</span></div>
  </div>
</div>
<script>
(function(){
'use strict';
var nextPath = __NEXT_PATH__;
var authReady = __AUTH_READY__;
var publicDashboardEnabled = __PUBLIC_DASHBOARD_ENABLED__;
var setupMessage = __SETUP_MESSAGE__;
var typingTimer = null;
var submitLocked = false;
var pendingToken = '';
function $(s){return document.querySelector(s)}
function showMessage(kind, text){ var box = $('#message'); box.className = 'msg ' + kind; box.textContent = text; }
function clearMessage(){ var box = $('#message'); box.className = 'msg'; box.textContent = ''; }
function rateLimitedInput(handler, wait){ return function(ev){ clearTimeout(typingTimer); typingTimer = setTimeout(function(){ handler(ev); }, wait); }; }
function setPanel(name){ ['passwordPanel','totpPanel'].forEach(function(id){ $('#'+id).classList.toggle('active', id === name); }); }

$('#username').value = 'admin';
$('#modeHint').textContent = 'Managed admin users are enabled.';
if(!publicDashboardEnabled){ $('#guestActions').hidden = true; }
var flashMessage = sessionStorage.getItem('wardenips_logout_message');
if(flashMessage){
  showMessage('ok', flashMessage);
  sessionStorage.removeItem('wardenips_logout_message');
}
if(!authReady){
  $('#submitBtn').disabled = true;
  $('#password').disabled = true;
  $('#username').disabled = true;
  $('#hint').textContent = 'Dashboard login is not configured yet.';
  $('#intro').textContent = setupMessage;
  showMessage('err', setupMessage);
}
['username','password','totpCode'].forEach(function(id){
  var field = $('#'+id);
  if(!field){ return; }
  field.addEventListener('input', rateLimitedInput(function(){
    $('#hint').textContent = 'Ready to submit';
    clearMessage();
  }, 250));
});

$('#loginForm').addEventListener('submit', async function(ev){
  ev.preventDefault();
  if(!authReady || submitLocked){ return; }
  submitLocked = true;
  $('#submitBtn').disabled = true;
  $('#hint').textContent = 'Submitting password verification';
  clearMessage();

  try {
    var response = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: $('#username').value.trim(),
        password: $('#password').value,
        next: nextPath
      })
    });
    var payload = await response.json();
    if(!response.ok){
      if(payload.redirect_to === '/setup'){ window.location.href = '/setup'; return; }
      showMessage('err', payload.message || 'Login failed.');
      return;
    }
    if(payload.requires_totp){
      pendingToken = payload.pending_token || '';
      setPanel('totpPanel');
      $('#totpCode').focus();
      $('#hint').textContent = 'Password accepted. Waiting for TOTP verification.';
      showMessage('ok', 'Password accepted. Enter your authenticator code.');
      return;
    }
    showMessage('ok', 'Login accepted, redirecting...');
    window.location.href = payload.redirect_to || nextPath || '/dashboard';
  } catch (error) {
    showMessage('err', 'Login request failed.');
  } finally {
    setTimeout(function(){
      submitLocked = false;
      $('#submitBtn').disabled = false;
      $('#hint').textContent = 'Input changes are throttled and login attempts are rate-limited.';
    }, 900);
  }
});

$('#totpForm').addEventListener('submit', async function(ev){
  ev.preventDefault();
  if(submitLocked || !pendingToken){ return; }
  submitLocked = true;
  $('#totpSubmitBtn').disabled = true;
  clearMessage();
  try {
    var response = await fetch('/api/login/totp', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ pending_token: pendingToken, totp_code: $('#totpCode').value.trim() })
    });
    var payload = await response.json();
    if(!response.ok){
      showMessage('err', payload.message || 'TOTP verification failed.');
      return;
    }
    showMessage('ok', 'TOTP accepted, redirecting...');
    window.location.href = payload.redirect_to || nextPath || '/admin';
  } catch (error) {
    showMessage('err', 'TOTP verification request failed.');
  } finally {
    setTimeout(function(){
      submitLocked = false;
      $('#totpSubmitBtn').disabled = false;
    }, 900);
  }
});

$('#backBtn').addEventListener('click', function(){
  pendingToken = '';
  $('#totpCode').value = '';
  setPanel('passwordPanel');
  clearMessage();
});
})();
</script>
</body>
</html>"""

SETUP_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WardenIPS Initial Setup</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#120f18;--bg2:#211934;--panel:#1d1a29;--panel2:#171420;--surface:#140f1f;--surface2:#120d1b;--b:#3b3150;--txt:#f5f1ea;--muted:#b8accc;--blue:#5ea1ff;--cyan:#39d0c6;--green:#4fd18f;--red:#ff6f7e;--accent:#ff875f;--shadow:0 30px 80px #00000045}
html{font-size:clamp(13px,0.32vw + 12px,16px)}
body{min-height:100vh;display:grid;place-items:center;font-family:Georgia,"Aptos",serif;background:radial-gradient(circle at top left,var(--bg2) 0%,var(--bg) 48%,var(--surface) 100%);color:var(--txt);padding:20px}
.shell{width:min(100%,1160px);display:grid;grid-template-columns:1fr 1fr;gap:20px}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:24px;padding:28px;box-shadow:var(--shadow)}
.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:var(--surface);border:1px solid var(--b);color:var(--blue);font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}
h1{font-size:2rem;letter-spacing:-.04em;margin-bottom:10px}
p{color:var(--muted);line-height:1.6;margin-bottom:16px}
.meta{display:grid;gap:10px;margin-top:18px}
.meta div{padding:12px 14px;border-radius:14px;border:1px solid var(--b);background:linear-gradient(180deg,var(--surface),var(--surface2));font-size:.85rem;color:var(--muted)}
.field{display:grid;gap:7px;margin-bottom:14px}
label{font-size:.8rem;font-weight:700;color:var(--txt)}
input{width:100%;background:var(--surface2);border:1px solid var(--b);color:var(--txt);border-radius:14px;padding:13px 14px;font-size:.95rem;outline:none}
input:focus{border-color:var(--blue);box-shadow:0 0 0 4px color-mix(in srgb,var(--blue) 18%,transparent)}
button{appearance:none;border:0;background:linear-gradient(135deg,var(--accent),#ff6f61);color:white;padding:13px 16px;border-radius:14px;font-size:.95rem;font-weight:800;cursor:pointer;min-width:150px}
button.secondary{background:var(--surface2);border:1px solid var(--b);color:var(--txt)}
button[disabled]{opacity:.65;cursor:wait}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:8px}
.msg{margin-top:14px;padding:12px 14px;border-radius:12px;font-size:.85rem;display:none}
.msg.err{display:block;background:#32131a;color:#ffb3bc;border:1px solid #6a2432}
.msg.ok{display:block;background:#0d2e26;color:#8ef0c7;border:1px solid #175343}
.panel{display:none}
.panel.active{display:block}
.qr-wrap{display:grid;gap:14px;justify-items:start}
.qr-wrap img{width:min(100%,240px);border-radius:18px;border:1px solid var(--b);background:white;padding:12px}
.secret{font-family:'Cascadia Code','Fira Code',monospace;font-size:.86rem;padding:12px 14px;border-radius:14px;border:1px solid var(--b);background:var(--surface2);word-break:break-all}
@media(max-width:900px){.shell{grid-template-columns:1fr}}
@media(max-width:640px){.row{flex-direction:column;align-items:stretch}button{width:100%}}
</style>
</head>
<body>
<div class="shell">
  <div class="card">
    <div class="eyebrow">First-Boot Setup</div>
    <h1>Create the first admin account.</h1>
    <p>Fresh installs no longer ship with a durable default admin secret. Use the bootstrap token from the installer output, create a named admin account, and bind it to a TOTP authenticator.</p>
    <div class="meta">
      <div>Bootstrap window: <strong>__SETUP_EXPIRY__</strong></div>
      <div>Requirements: non-default username, strong password, working authenticator app.</div>
      <div>Result: bootstrap token is invalidated and the first admin account is stored in the configured backend.</div>
    </div>
  </div>
  <div class="card">
    <div id="setupBeginPanel" class="panel active">
      <div class="eyebrow">Step 1</div>
      <h1>Bootstrap credentials</h1>
      <form id="setupBeginForm">
        <div class="field">
          <label for="bootstrapToken">Bootstrap Token</label>
          <input id="bootstrapToken" type="text" autocomplete="off" spellcheck="false">
        </div>
        <div class="field">
          <label for="setupUsername">Admin Username</label>
          <input id="setupUsername" type="text" autocomplete="username" spellcheck="false" placeholder="ops-admin">
        </div>
        <div class="field">
          <label for="setupPassword">Password</label>
          <input id="setupPassword" type="password" autocomplete="new-password">
        </div>
        <div class="field">
          <label for="setupPasswordConfirm">Confirm Password</label>
          <input id="setupPasswordConfirm" type="password" autocomplete="new-password">
        </div>
        <div class="row">
          <p style="margin:0;font-size:.78rem">Password policy: at least 12 chars, uppercase, lowercase, number, and symbol.</p>
          <button id="setupBeginBtn" type="submit">Generate TOTP</button>
        </div>
      </form>
    </div>
    <div id="setupVerifyPanel" class="panel">
      <div class="eyebrow">Step 2</div>
      <h1>Verify your authenticator</h1>
      <div class="qr-wrap">
        <img id="totpQr" alt="TOTP QR Code">
        <div class="secret" id="totpSecret"></div>
      </div>
      <form id="setupCompleteForm" style="margin-top:16px">
        <div class="field">
          <label for="setupTotpCode">Authenticator Code</label>
          <input id="setupTotpCode" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456">
        </div>
        <div class="row">
          <button id="setupCompleteBtn" type="submit">Finish Setup</button>
          <button id="setupBackBtn" class="secondary" type="button">Back</button>
        </div>
      </form>
    </div>
    <div id="setupMessage" class="msg"></div>
  </div>
</div>
<script>
(function(){
'use strict';
var pendingSetupToken = '';
var busy = false;
function $(s){return document.querySelector(s)}
function setPanel(name){ ['setupBeginPanel','setupVerifyPanel'].forEach(function(id){ $('#'+id).classList.toggle('active', id === name); }); }
function showMessage(kind, text){ var box = $('#setupMessage'); box.className = 'msg ' + kind; box.textContent = text; }
function clearMessage(){ var box = $('#setupMessage'); box.className = 'msg'; box.textContent = ''; }

$('#setupBeginForm').addEventListener('submit', async function(ev){
  ev.preventDefault();
  if(busy){ return; }
  busy = true;
  $('#setupBeginBtn').disabled = true;
  clearMessage();
  try {
    var response = await fetch('/api/setup/begin', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        bootstrap_token: $('#bootstrapToken').value.trim(),
        username: $('#setupUsername').value.trim(),
        password: $('#setupPassword').value,
        password_confirm: $('#setupPasswordConfirm').value
      })
    });
    var payload = await response.json();
    if(!response.ok){
      showMessage('err', payload.message || 'Setup could not start.');
      return;
    }
    pendingSetupToken = payload.pending_setup_token || '';
    $('#totpQr').src = payload.totp_qr_data_url || '';
    $('#totpSecret').textContent = payload.totp_secret || '';
    setPanel('setupVerifyPanel');
    showMessage('ok', 'Scan the QR code or copy the secret, then enter a TOTP code to finish setup.');
  } catch (error) {
    showMessage('err', 'Setup request failed.');
  } finally {
    busy = false;
    $('#setupBeginBtn').disabled = false;
  }
});

$('#setupCompleteForm').addEventListener('submit', async function(ev){
  ev.preventDefault();
  if(busy || !pendingSetupToken){ return; }
  busy = true;
  $('#setupCompleteBtn').disabled = true;
  clearMessage();
  try {
    var response = await fetch('/api/setup/complete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        pending_setup_token: pendingSetupToken,
        totp_code: $('#setupTotpCode').value.trim()
      })
    });
    var payload = await response.json();
    if(!response.ok){
      showMessage('err', payload.message || 'Setup completion failed.');
      return;
    }
    showMessage('ok', payload.message || 'Setup completed. Redirecting...');
    window.location.href = payload.redirect_to || '/admin';
  } catch (error) {
    showMessage('err', 'Setup completion request failed.');
  } finally {
    busy = false;
    $('#setupCompleteBtn').disabled = false;
  }
});

$('#setupBackBtn').addEventListener('click', function(){
  pendingSetupToken = '';
  $('#setupTotpCode').value = '';
  setPanel('setupBeginPanel');
  clearMessage();
});
})();
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WardenIPS Dashboard</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#110f18;--bg2:#1d1730;--card:#1d1a29;--card-h:#261f36;
  --bdr:#3b3150;--bdr-g:#5ea1ff20;
  --txt:#f5f1ea;--dim:#b8accc;--dim2:#8e82a6;
  --accent:#ff875f;--accent-g:#ff875f40;
  --red:#ff6f7e;--red-d:#ff6f7e20;
  --warn:#ffbe5c;--warn-d:#ffbe5c20;
  --grn:#4fd18f;--grn-d:#4fd18f20;
  --pur:#7e7bff;--pur-d:#7e7bff20;
  --cyan:#39d0c6;--cyan-d:#39d0c620;
  --r:18px;--rs:12px;--shadow:0 30px 80px #00000045;
}
:root[data-theme="light"]{
  --bg:#f4eee4;--bg2:#e9ddcf;--card:#fffdf8;--card-h:#f3eadf;
  --bdr:#dac8b2;--bdr-g:#2f6fe420;
  --txt:#221d17;--dim:#74685b;--dim2:#8a7868;
  --accent:#c95c2b;--accent-g:#c95c2b22;
  --red:#c84e58;--red-d:#c84e5820;
  --warn:#c98410;--warn-d:#c9841020;
  --grn:#1f8b57;--grn-d:#1f8b5720;
  --pur:#5f58d6;--pur-d:#5f58d620;
  --cyan:#0f8f92;--cyan-d:#0f8f9220;
  --shadow:0 22px 48px rgba(73,49,19,.12);
}
html{font-size:clamp(13px,0.28vw + 12px,15px);scroll-behavior:smooth}
body{font-family:Georgia,"Aptos",serif;background:radial-gradient(circle at top left,var(--bg2) 0%,var(--bg) 48%,color-mix(in srgb,var(--bg) 92%,#000 8%) 100%);color:var(--txt);min-height:100vh;overflow-x:hidden;transition:background .25s ease,color .25s ease}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(circle at 82% 14%,color-mix(in srgb,var(--accent) 18%,transparent) 0%,transparent 24%),radial-gradient(circle at 12% 78%,color-mix(in srgb,var(--cyan) 14%,transparent) 0%,transparent 28%);pointer-events:none;z-index:0}
.sh{max-width:1440px;margin:0 auto;padding:1.5rem;position:relative;z-index:1}
header{display:flex;align-items:center;justify-content:space-between;padding:1rem 0 2rem;flex-wrap:wrap;gap:1rem}
.logo{display:flex;align-items:center;gap:.75rem}
.logo svg{width:36px;height:36px;filter:drop-shadow(0 0 10px var(--accent-g))}
.logo h1{font-size:1.7rem;font-weight:800;letter-spacing:-.03em;background:linear-gradient(135deg,var(--accent),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.logo-copy{display:grid;gap:.3rem}
.hero-note{font-size:.92rem;color:var(--dim);max-width:48ch;line-height:1.5}
.meta{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.bdg{display:inline-flex;align-items:center;gap:.4rem;padding:.35rem .75rem;border-radius:20px;font-size:.75rem;font-weight:600;letter-spacing:.03em}
.bdg-live{background:var(--grn-d);color:var(--grn);animation:pls 2s infinite}
.bdg-sim{background:var(--warn-d);color:var(--warn)}
.admin-link{display:inline-flex;align-items:center;justify-content:center;padding:.7rem 1rem;border-radius:999px;border:1px solid var(--bdr);background:color-mix(in srgb,var(--card) 85%,transparent);color:var(--txt);text-decoration:none;font-size:.82rem;font-weight:800;transition:border-color .2s ease,transform .2s ease,background .2s ease;box-shadow:var(--shadow)}
button.admin-link{font:inherit;cursor:pointer}
.admin-link:hover{border-color:var(--accent);transform:translateY(-1px);background:var(--card-h)}
.hero-band{display:grid;grid-template-columns:1.35fr .9fr;gap:1rem;margin-bottom:1.5rem}
.hero-panel,.signal-panel{background:linear-gradient(180deg,var(--card),color-mix(in srgb,var(--card) 90%,#000 10%));border:1px solid var(--bdr);border-radius:20px;padding:1.1rem 1.2rem;box-shadow:var(--shadow)}
.hero-panel strong,.signal-panel strong{display:block;font-size:.88rem;margin-bottom:.4rem}
.hero-panel p,.signal-panel p{font-size:.82rem;line-height:1.6;color:var(--dim);margin:0}
.signal-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin-top:.8rem}
.signal-grid div{padding:.75rem;border-radius:14px;background:color-mix(in srgb,var(--card-h) 88%,transparent);border:1px solid var(--bdr)}
.signal-grid span{display:block;font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:.3rem}
@keyframes pls{0%,100%{opacity:1}50%{opacity:.6}}
.dot{width:6px;height:6px;border-radius:50%;background:var(--grn);display:inline-block;margin-right:4px}

/* Stats */
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem;margin-bottom:2rem}
.sc{background:linear-gradient(180deg,var(--card),color-mix(in srgb,var(--card) 92%,#000 8%));border:1px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem;transition:all .25s ease;position:relative;overflow:hidden;box-shadow:var(--shadow)}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent);border-radius:var(--r) var(--r) 0 0;opacity:.6;transition:opacity .3s}
.sc:hover{transform:translateY(-2px);border-color:var(--accent);box-shadow:0 8px 32px var(--accent-g)}
.sc:hover::before{opacity:1}
.sc.dng::before{background:var(--red)}.sc.wrn::before{background:var(--warn)}.sc.suc::before{background:var(--grn)}.sc.prp::before{background:var(--pur)}
.sc .lb{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:.5rem;display:flex;align-items:center;gap:.4rem}
.sc .lb svg{width:14px;height:14px;opacity:.7}
.sc .vl{font-size:2rem;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.vl.bl{color:var(--accent)}.vl.rd{color:var(--red)}.vl.gn{color:var(--grn)}.vl.yl{color:var(--warn)}.vl.pp{color:var(--pur)}
.sc .sb{font-size:.7rem;color:var(--dim2);margin-top:.35rem}

/* Panels */
.pn{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem;align-items:start}
@media(max-width:900px){.pn{grid-template-columns:1fr}}
.pl{background:linear-gradient(180deg,var(--card),color-mix(in srgb,var(--card) 92%,#000 8%));border:1px solid var(--bdr);border-radius:var(--r);overflow:hidden;transition:all .25s ease;box-shadow:var(--shadow);height:auto}
.pl:hover{border-color:var(--bdr-g)}
.ph{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.25rem;border-bottom:1px solid var(--bdr)}
.ph h2{font-size:.95rem;font-weight:600;display:flex;align-items:center;gap:.5rem}
.ph h2 svg{width:18px;height:18px;color:var(--accent)}
.pill{font-size:.65rem;padding:.2rem .55rem;background:var(--accent);color:#fff;border-radius:10px;font-weight:700}
.pb{padding:1.25rem;max-height:420px;overflow-y:auto}
.pb::-webkit-scrollbar{width:4px}
.pb::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:4px}
.fw{grid-column:1/-1}

/* Bar Chart */
.cb{display:flex;flex-direction:column;gap:.5rem}
.br{display:flex;align-items:center;gap:.75rem}
.bl2{min-width:90px;font-size:.75rem;color:var(--dim);text-align:right;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bt{flex:1;height:26px;background:#1e293b;border-radius:6px;overflow:hidden;position:relative}
.bf{height:100%;border-radius:6px;transition:width .8s cubic-bezier(.25,.46,.45,.94);display:flex;align-items:center;padding:0 .6rem;font-size:.7rem;font-weight:600;color:#fff;white-space:nowrap;min-width:fit-content}
.bf.c0{background:linear-gradient(90deg,#3b82f6,#60a5fa)}
.bf.c1{background:linear-gradient(90deg,#ef4444,#f87171)}
.bf.c2{background:linear-gradient(90deg,#10b981,#34d399)}
.bf.c3{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.bf.c4{background:linear-gradient(90deg,#8b5cf6,#a78bfa)}
.bf.c5{background:linear-gradient(90deg,#06b6d4,#22d3ee)}

/* Timeline */
.tc{display:flex;align-items:flex-end;gap:3px;height:160px;padding-top:1rem}
.tb{flex:1;min-width:4px;background:linear-gradient(to top,var(--accent),var(--cyan));border-radius:3px 3px 0 0;transition:height .6s cubic-bezier(.25,.46,.45,.94);position:relative;cursor:pointer}
.tb:hover{opacity:.8}
.tb:hover::after{content:attr(data-t);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#1e293b;color:var(--txt);font-size:.65rem;padding:.3rem .5rem;border-radius:4px;white-space:nowrap;z-index:10;box-shadow:0 4px 24px #00000040}
.tl{display:flex;gap:3px;margin-top:.4rem}
.tl span{flex:1;font-size:.55rem;color:var(--dim2);text-align:center;overflow:hidden;text-overflow:ellipsis}

/* Table */
.t{width:100%;border-collapse:separate;border-spacing:0}
.t th{text-align:left;font-size:.65rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);padding:.6rem .75rem;border-bottom:1px solid var(--bdr);position:sticky;top:0;background:var(--card);z-index:2}
.t td{padding:.55rem .75rem;font-size:.8rem;border-bottom:1px solid #1e293b10;vertical-align:middle}
.t tr:hover td{background:var(--card-h)}
.h{font-family:'Fira Code','Cascadia Code',monospace;font-size:.7rem;color:var(--dim);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rb{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;font-weight:700;min-width:38px;text-align:center}
.rh{background:var(--red-d);color:var(--red)}.rm{background:var(--warn-d);color:var(--warn)}.rl{background:var(--grn-d);color:var(--grn)}
.tg{display:inline-block;padding:.1rem .45rem;border-radius:4px;font-size:.65rem;font-weight:600;text-transform:uppercase}
.tg-H,.tg-C{background:var(--red-d);color:var(--red)}
.tg-M{background:var(--warn-d);color:var(--warn)}
.tg-L{background:var(--grn-d);color:var(--grn)}
.tg-N{background:#1e293b;color:var(--dim2)}
.pt{display:inline-block;padding:.1rem .45rem;border-radius:4px;font-size:.65rem;font-weight:600;background:var(--cyan-d);color:var(--cyan)}
.em{padding:2rem;text-align:center;color:var(--dim2);font-size:.85rem}
.em svg{width:40px;height:40px;margin-bottom:.75rem;opacity:.3}
.mesh-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem;margin-bottom:1rem}
.mesh-stat{padding:.9rem;border:1px solid var(--bdr);border-radius:12px;background:var(--card-h)}
.mesh-stat .k{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:.35rem}
.mesh-stat .v{font-size:1.1rem;font-weight:700}
.mesh-topology{display:grid;place-items:center;min-height:220px;margin:1rem 0 1.2rem;border:1px solid var(--bdr);border-radius:16px;background:radial-gradient(circle at center,color-mix(in srgb,var(--accent) 12%,var(--card-h)) 0%,var(--card-h) 42%,color-mix(in srgb,var(--card) 90%,#000 10%) 100%);overflow:hidden;position:relative}
.mesh-topology::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at center,color-mix(in srgb,var(--accent) 12%,transparent) 0%,transparent 52%);pointer-events:none}
.mesh-canvas{position:relative;width:min(100%,520px);height:200px}
.mesh-node{position:absolute;display:flex;align-items:center;justify-content:center;border-radius:999px;border:1px solid var(--bdr);font-size:.72rem;font-weight:700;letter-spacing:.01em;box-shadow:0 10px 28px #00000035}
.mesh-node.local{left:50%;top:50%;transform:translate(-50%,-50%);width:112px;height:112px;background:linear-gradient(135deg,#2563eb,#0f766e);color:#eff6ff;border-color:#60a5fa}
.mesh-node.peer{width:78px;height:78px;background:var(--card);color:var(--txt)}
.mesh-node.peer.ok{border-color:#34d399;background:linear-gradient(135deg,#0f172a,#0b2b22)}
.mesh-node.peer.bad{border-color:#f87171;background:linear-gradient(135deg,#0f172a,#311313)}
.mesh-line{position:absolute;height:2px;transform-origin:left center;background:linear-gradient(90deg,#60a5fa55,#22d3ee20)}
.mesh-node small{display:block;font-size:.62rem;color:#cbd5e1;font-weight:600;opacity:.85}
.peer-list{display:grid;gap:.65rem}
.peer-card{padding:.85rem 1rem;border:1px solid var(--bdr);border-radius:12px;background:var(--card-h)}
.peer-head{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:.45rem}
.peer-url{font-size:.8rem;font-weight:700;color:var(--txt);word-break:break-all}
.peer-meta{font-size:.72rem;color:var(--dim);display:flex;gap:.85rem;flex-wrap:wrap}
.st{display:inline-flex;align-items:center;gap:.35rem;padding:.2rem .5rem;border-radius:999px;font-size:.68rem;font-weight:700}
.st.ok{background:var(--grn-d);color:var(--grn)}
.st.bad{background:var(--red-d);color:var(--red)}
.desc{font-size:.78rem;line-height:1.5;color:var(--dim);margin-bottom:.9rem}
.geo-map{position:relative;min-height:240px;border:1px solid var(--bdr);border-radius:14px;background:radial-gradient(circle at 50% 50%,color-mix(in srgb,var(--cyan) 8%,transparent) 0%,transparent 55%),linear-gradient(180deg,color-mix(in srgb,var(--card-h) 86%,transparent),color-mix(in srgb,var(--card) 88%,transparent));overflow:hidden}
.geo-grid{position:absolute;inset:0;z-index:1;opacity:.22;background-image:linear-gradient(to right,var(--bdr) 1px,transparent 1px),linear-gradient(to bottom,var(--bdr) 1px,transparent 1px);background-size:32px 32px}
.geo-world{position:absolute;inset:0;z-index:2;pointer-events:none;opacity:.32}
.geo-world .land{fill:color-mix(in srgb,var(--cyan) 15%,transparent);stroke:color-mix(in srgb,var(--cyan) 26%,var(--bdr));stroke-width:1.1;stroke-linejoin:round}
.geo-world .island{fill:color-mix(in srgb,var(--cyan) 13%,transparent);stroke:color-mix(in srgb,var(--cyan) 24%,var(--bdr));stroke-width:.9}
.geo-point{position:absolute;z-index:3;transform:translate(-50%,-50%);border-radius:999px;border:1px solid color-mix(in srgb,var(--red) 65%,white);background:color-mix(in srgb,var(--red) 42%,transparent);cursor:pointer;box-shadow:0 0 0 1px #00000033,0 0 18px color-mix(in srgb,var(--red) 45%,transparent)}
.geo-point.is-new::after{content:'';position:absolute;inset:-6px;border-radius:999px;border:1px solid color-mix(in srgb,var(--red) 72%,white);opacity:.8;animation:geoPulse 1.2s ease-out}
@keyframes geoPulse{0%{transform:scale(.65);opacity:.9}100%{transform:scale(2.1);opacity:0}}
.geo-legend{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-top:.75rem;font-size:.72rem;color:var(--dim)}
.geo-legend .bar{flex:1;height:8px;border-radius:999px;background:linear-gradient(90deg,color-mix(in srgb,var(--red) 18%,transparent),color-mix(in srgb,var(--red) 75%,white))}
.geo-meta{margin-top:.55rem;font-size:.76rem;color:var(--dim)}
.advice-tip{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border-radius:999px;border:1px solid var(--bdr);background:var(--card-h);font-size:.72rem;font-weight:800;cursor:help}
footer{text-align:center;padding:2rem 0 1rem;color:var(--dim2);font-size:.75rem}
footer a{color:var(--accent);text-decoration:none}
footer a:hover{text-decoration:underline}
.kofi-fab{position:fixed;right:18px;bottom:18px;z-index:20;display:inline-flex;align-items:center;gap:.45rem;padding:.55rem .9rem;border-radius:999px;background:linear-gradient(135deg,var(--card-h),var(--card));border:1px solid var(--bdr);color:var(--txt);text-decoration:none;font-size:.78rem;font-weight:700;box-shadow:0 10px 30px #00000055;transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease;backdrop-filter:blur(4px)}
.kofi-fab .heart{font-size:.9rem;line-height:1;color:#fb7185}
.kofi-fab .sub{font-size:.68rem;color:var(--dim);font-weight:600}
.kofi-fab:hover{transform:translateY(-2px);border-color:var(--accent);box-shadow:0 14px 34px #00000070;text-decoration:none}
@keyframes kofiPulse{0%,100%{box-shadow:0 10px 30px #00000055}50%{box-shadow:0 12px 34px #0ea5e93a}}
.kofi-fab{animation:kofiPulse 3.4s ease-in-out infinite}
@keyframes fi{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.ai{animation:fi .4s cubic-bezier(.4,0,.2,1) both}
.d1{animation-delay:.05s}.d2{animation-delay:.1s}.d3{animation-delay:.15s}.d4{animation-delay:.2s}.d5{animation-delay:.25s}.d6{animation-delay:.3s}
@media(max-width:900px){.mesh-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.hero-band{grid-template-columns:1fr}.signal-grid{grid-template-columns:1fr 1fr}}
@media(max-width:640px){.sg{grid-template-columns:repeat(2,1fr)}.sc .vl{font-size:1.5rem}.logo h1{font-size:1.2rem}.sh{padding:1rem}.kofi-fab{right:12px;bottom:12px;padding:.5rem .75rem}.kofi-fab .sub{display:none}.mesh-grid{grid-template-columns:1fr}.signal-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="sh">
  <header>
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--accent)"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <div class="logo-copy">
        <h1>WardenIPS</h1>
        <div class="hero-note">Public security overview with a separate admin entry point for operational actions.</div>
      </div>
    </div>
    <div class="meta">
      <span class="bdg bdg-live" id="sb"><span class="dot"></span>LIVE</span>
      <span style="font-size:.8rem;color:var(--dim)" id="ut">Service: --:--:-- • System: --</span>
      <button class="admin-link" id="themeToggle" type="button">Light Mode</button>
      <a class="admin-link" href="__ADMIN_HREF__">__ADMIN_LABEL__</a>
    </div>
  </header>

  <div class="hero-band ai d1">
    <div class="hero-panel">
      <strong>What you can see here</strong>
      <p>Live totals, attacker concentration, event history, country spread, plugin activity, and blocklist status are available without exposing write operations.</p>
    </div>
    <div class="signal-panel">
      <strong>Access split</strong>
      <div class="signal-grid">
        <div><span>Public</span>Overview only</div>
        <div><span>Admin</span>Maintenance actions</div>
        <div><span>Session</span>10m idle timeout</div>
      </div>
    </div>
  </div>

  <div class="sg">
    <div class="sc ai d1"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Service Uptime</div><div class="vl bl" id="su">--:--:--</div></div>
    <div class="sc ai d2"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h18"/><path d="M12 3v18"/><circle cx="12" cy="12" r="9"/></svg>System Uptime</div><div class="vl bl" id="ssu">--</div></div>
    <div class="sc ai d3"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Total Events</div><div class="vl bl" id="se">0</div></div>
    <div class="sc dng ai d4"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>Total Bans</div><div class="vl rd" id="stb">0</div></div>
    <div class="sc wrn ai d5"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Active Bans</div><div class="vl yl" id="sab">0</div></div>
    <div class="sc suc ai d6"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Firewall</div><div class="vl gn" id="sfw">0</div></div>
  </div>

  <div class="pn">
    <div class="pl fw ai d2">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Recent Events</h2><span class="pill" id="ec">0</span></div>
      <div class="pb" style="max-height:400px">
        <table class="t" id="evt"><thead><tr><th>Time</th><th>Source IP</th><th>Plugin</th><th>User</th><th>Origin</th><th>Risk</th><th>Threat</th><th>ASN</th><th>Advice</th></tr></thead><tbody id="evb"></tbody></table>
        <div class="em" id="eve" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><div>No events recorded yet</div></div>
      </div>
    </div>
    <div class="pl ai d3">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Threat Levels</h2></div>
      <div class="pb"><div class="cb" id="thc"></div></div>
    </div>
    <div class="pl ai d4">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>Top Countries</h2></div>
      <div class="pb"><div class="cb" id="coc"></div></div>
    </div>
    <div class="pl ai d3">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="M20 8v6m3-3h-6"/></svg>Top Portscanned Ports</h2><span class="pill" id="ac">0</span></div>
      <div class="pb"><div class="cb" id="atc"></div></div>
    </div>
    <div class="pl ai d4">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/></svg>Plugins</h2></div>
      <div class="pb"><div class="cb" id="plc"></div></div>
    </div>
    <div class="pl fw ai d3" hidden aria-hidden="true">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2c3 3 4.5 6.5 4.5 10S15 19 12 22c-3-3-4.5-6.5-4.5-10S9 5 12 2z"/></svg>Attack Heatmap (Public)</h2></div>
      <div class="pb">
        <div id="geoMap" class="geo-map">
          <div class="geo-grid"></div>
          <svg class="geo-world" viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
            <path class="land" d="M113 209c8-24 33-47 63-57 29-10 57-8 76 6 17 13 30 34 27 53-3 17-22 29-43 38-19 8-31 22-38 40-8 20-24 30-46 29-22-1-39-12-49-30-11-21-1-50 10-79z"/>
            <path class="land" d="M286 293c17-19 42-28 65-22 20 5 39 22 42 42 2 17-9 30-23 40-17 11-36 15-55 10-18-5-33-18-38-35-5-13 0-25 9-35z"/>
            <path class="land" d="M403 171c24-32 63-52 105-53 42-2 84 13 115 37 26 20 52 16 79 30 20 11 38 30 40 51 1 19-16 34-37 42-24 10-49 9-74 4-25-5-48-2-71 7-25 10-52 11-78 4-30-8-61-7-88 2-22 8-42 8-61-4-19-12-29-31-25-50 4-27 18-49 35-70z"/>
            <path class="land" d="M523 274c18-10 41-14 62-10 18 3 34 15 38 31 3 14-4 26-16 35-14 11-33 17-52 17-20 0-38-8-50-20-10-10-14-24-8-36 4-8 13-13 26-17z"/>
            <path class="land" d="M714 180c26-23 62-38 101-38 37 0 73 13 99 35 22 20 28 43 14 62-13 18-37 28-64 31-24 2-46 6-67 17-22 11-45 13-66 7-21-6-35-20-41-39-7-27 1-55 24-75z"/>
            <path class="land" d="M806 271c14-9 33-14 51-12 21 3 41 16 47 35 5 15-2 31-14 44-14 13-32 22-51 23-18 1-36-6-47-19-11-13-15-32-9-48 4-10 11-17 23-23z"/>
            <path class="land" d="M845 366c12-9 29-14 44-12 16 1 31 10 36 24 6 16-2 34-16 47-15 14-34 20-50 16-16-4-29-17-31-33-2-15 4-31 17-42z"/>
            <circle class="island" cx="678" cy="152" r="4.3"/>
            <circle class="island" cx="696" cy="162" r="3.5"/>
            <circle class="island" cx="739" cy="330" r="4.1"/>
            <circle class="island" cx="773" cy="342" r="2.9"/>
            <circle class="island" cx="885" cy="221" r="3.2"/>
          </svg>
        </div>
        <div class="geo-legend"><span>Low</span><div class="bar"></div><span>High</span></div>
        <div id="geoMeta" class="geo-meta">No country telemetry available yet.</div>
      </div>
    </div>
  </div>

  <div class="pn">
    <div class="pl fw ai d2">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></svg>Events Timeline (24h)</h2></div>
      <div class="pb" style="overflow:visible"><div class="tc" id="tlc"></div><div class="tl" id="tll"></div></div>
    </div>
    <div class="pl fw ai d2">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Blocklist Protection</h2></div>
      <div class="pb">
        <div class="desc" id="tid">Blocklist protection is disabled.</div>
        <div class="mesh-grid">
          <div class="mesh-stat"><div class="k">Mode</div><div class="v" id="tim">Disabled</div></div>
          <div class="mesh-stat"><div class="k">First Setup</div><div class="v" id="tip">--</div></div>
          <div class="mesh-stat"><div class="k">Active IPs</div><div class="v" id="tis">0</div></div>
          <div class="mesh-stat"><div class="k">Last Fetch</div><div class="v" id="tir">--</div></div>
        </div>
      </div>
    </div>
    <div class="pl fw ai d2">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Active Bans</h2><span class="pill" id="bc">0</span></div>
      <div class="pb" style="max-height:350px">
        <table class="t" id="bnt"><thead><tr><th>Source IP</th><th>Risk</th><th>Reason</th><th>Duration</th><th>Banned At</th><th>Expires</th></tr></thead><tbody id="bnb"></tbody></table>
        <div class="em" id="bne" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg><div>No active bans — all clear!</div></div>
      </div>
    </div>
  </div>

  <footer>WardenIPS v__APP_VERSION__ &mdash; by __APP_AUTHOR__ &middot; Autonomous Intrusion Prevention &middot; <a href="https://github.com/msncakma/WardenIPS" target="_blank" rel="noopener">GitHub</a> &middot; <a href="https://github.com/msncakma/WardenIPS/stargazers" target="_blank" rel="noopener">Star</a> &middot; <a href="https://github.com/msncakma/WardenIPS/issues" target="_blank" rel="noopener">Issues</a></footer>
</div>

<a class="kofi-fab" href="https://ko-fi.com/msncakma" target="_blank" rel="noopener" title="Support WardenIPS on Ko-fi">
  <span class="heart">♥</span>
  <span>Support the project <span class="sub">on Ko-fi</span></span>
</a>

<script>
(function(){
'use strict';
var R=1000;
function $(s){return document.querySelector(s)}
function N(n){return(n||0).toLocaleString()}
function E(s){var d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
function parseTs(v){
  if(v===null||v===undefined||v==='')return null;
  if(typeof v==='number')return v<1e12?v*1000:v;
  var s=String(v).trim();
  if(!s)return null;
  if(/^\d+$/.test(s)){var n=Number(s);return n<1e12?n*1000:n;}
  if(s.indexOf(' ')>0&&s.indexOf('T')===-1)s=s.replace(' ','T');
  var d=new Date(s),ms=d.getTime();
  return Number.isFinite(ms)?ms:null;
}
function T(iso){
  var ts=parseTs(iso);
  if(ts===null)return'-';
  var df=Math.floor((Date.now()-ts)/1000);
  if(df<0)df=0;
  if(df<60)return df+'s ago';if(df<3600)return Math.floor(df/60)+'m ago';
  if(df<86400)return Math.floor(df/3600)+'h ago';return Math.floor(df/86400)+'d ago';
}
function D(s){
  if(!s||s<=0)return'Permanent';
  if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';
  return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
}
function TG(iso){return iso?T(iso):'-'}
function RC(r){return r>=70?'rh':r>=40?'rm':'rl'}
function CF(c){
  if(!c||c.length!==2)return'';
  return String.fromCodePoint(...[...c.toUpperCase()].map(x=>x.charCodeAt(0)+127397));
}
var CC=['c0','c1','c2','c3','c4','c5'];
var GEO_COUNTS={};
var GEO_SEEN=false;
var CENTROIDS={US:[37.1,-95.7],CA:[56.1,-106.3],MX:[23.6,-102.5],BR:[-14.2,-51.9],AR:[-38.4,-63.6],CL:[-35.7,-71.5],CO:[4.6,-74.1],PE:[-9.2,-75.0],GB:[55.3,-3.4],IE:[53.1,-8.2],FR:[46.2,2.2],DE:[51.2,10.4],NL:[52.1,5.3],BE:[50.5,4.5],ES:[40.4,-3.7],PT:[39.4,-8.2],IT:[41.9,12.5],CH:[46.8,8.2],AT:[47.5,14.6],SE:[60.1,18.6],NO:[60.5,8.5],FI:[61.9,25.7],DK:[56.2,9.5],PL:[51.9,19.1],CZ:[49.8,15.5],RO:[45.9,24.9],UA:[48.3,31.2],TR:[38.9,35.2],RU:[61.5,105.3],SA:[23.9,45.1],AE:[23.4,53.8],IL:[31.0,35.0],EG:[26.8,30.8],ZA:[-30.6,22.9],NG:[9.1,8.7],KE:[-0.0,37.9],ET:[9.1,40.5],MA:[31.8,-7.1],DZ:[28.0,1.7],IN:[20.6,78.9],PK:[30.4,69.3],BD:[23.7,90.3],CN:[35.9,104.1],JP:[36.2,138.2],KR:[35.9,127.8],TW:[23.7,121.0],HK:[22.3,114.2],SG:[1.3,103.8],ID:[-2.5,118.0],MY:[4.2,102.0],TH:[15.8,100.9],VN:[14.0,108.3],PH:[12.9,121.8],AU:[-25.3,133.8],NZ:[-40.9,174.8]};
function applyTheme(theme){
  var next=theme==='light'?'light':'dark';
  document.documentElement.setAttribute('data-theme',next);
  try{localStorage.setItem('wardenips_public_theme',next)}catch(e){}
  var btn=$('#themeToggle');
  if(btn)btn.textContent=next==='light'?'Dark Mode':'Light Mode';
}
function initTheme(){
  var saved='dark';
  try{saved=localStorage.getItem('wardenips_public_theme')||'dark'}catch(e){}
  applyTheme(saved);
}
async function A(p){try{var r=await fetch(p);if(!r.ok)return null;return await r.json()}catch(e){return null}}

function bars(id,items,lk,vk,ci){
  var el=$('#'+id);
  if(!items||!items.length){el.innerHTML='<div class="em" style="padding:1rem 0"><div>No data</div></div>';return}
  var mx=Math.max(...items.map(function(i){return i[vk]}),1);
  el.innerHTML=items.map(function(it,idx){
    var pct=Math.max((it[vk]/mx)*100,3);
    var c=CC[((ci||0)+idx)%6];
    var lb=it[lk]||'Unknown';
    var em=lk==='country'?CF(lb)+' ':'';
    return '<div class="br"><span class="bl2">'+em+E(lb)+'</span><div class="bt"><div class="bf '+c+'" style="width:'+pct+'%">'+N(it[vk])+'</div></div></div>';
  }).join('');
}

function renderBlocklist(ti){
  $('#tim').textContent = ti&&ti.enabled ? (ti.mode||'Enabled') : 'Disabled';
  if(ti&&ti.enabled&&ti.first_setup){
    var fs=ti.first_setup;
    $('#tip').textContent = fs.completed ? 'Completed' : (fs.remaining||fs.mode);
    $('#tis').textContent = N(ti.active&&ti.active.total_ips_loaded ? ti.active.total_ips_loaded : 0);
    $('#tir').textContent = ti.active&&ti.active.last_fetch_at ? ti.active.last_fetch_at.split('T')[0] : '--';
  } else {
    $('#tip').textContent = '--';
    $('#tis').textContent = '0';
    $('#tir').textContent = '--';
  }
  $('#tid').textContent = ti&&ti.description ? ti.description : 'Blocklist protection is disabled.';
}

function geoToXY(lat,lon,w,h){
  var x=((lon+180)/360)*w;
  var y=((90-lat)/180)*h;
  return [x,y];
}

function renderGeoHeatmap(payload){
  var wrap=$('#geoMap');
  var meta=$('#geoMeta');
  if(!wrap||!meta){ return; }
  wrap.querySelectorAll('.geo-point').forEach(function(node){ node.remove(); });
  var points=(payload&&payload.points)?payload.points:[];
  if(!points.length){
    meta.textContent='No country telemetry available yet.';
    return;
  }
  var valid=points.filter(function(item){
    var code=String(item.country||'').trim().toUpperCase();
    return code.length===2 && code!=='ZZ' && !!CENTROIDS[code];
  }).map(function(item){
    return {country:String(item.country||'').trim().toUpperCase(), count:item.count||0};
  });
  if(!valid.length){
    meta.textContent='No mappable country telemetry available yet.';
    return;
  }
  var max=Math.max.apply(null, valid.map(function(item){ return item.count||0; })) || 1;
  var rect=wrap.getBoundingClientRect();
  var hasBaseline=GEO_SEEN;
  var nextCounts={};
  valid.forEach(function(item){
    var prevCount=GEO_COUNTS[item.country]||0;
    var isNewPoint=hasBaseline && (item.count||0) > prevCount;
    nextCounts[item.country]=item.count||0;
    var c=CENTROIDS[item.country];
    var xy=geoToXY(c[0],c[1],rect.width,rect.height);
    var intensity=(item.count||0)/max;
    var size=8 + Math.round(intensity*22);
    var point=document.createElement('button');
    point.type='button';
    point.className='geo-point'+(isNewPoint?' is-new':'');
    point.style.left=xy[0]+'px';
    point.style.top=xy[1]+'px';
    point.style.width=size+'px';
    point.style.height=size+'px';
    point.title=item.country+': '+N(item.count)+' events';
    point.addEventListener('click', function(){
      meta.textContent='Country '+item.country+' generated '+N(item.count)+' events in the last '+(payload.hours||24)+'h.';
    });
    wrap.appendChild(point);
  });
  GEO_COUNTS=nextCounts;
  GEO_SEEN=true;
  meta.textContent='Showing '+valid.length+' countries from the last '+(payload.hours||24)+'h. Click a point for details.';
}

async function refresh(){
  var h=await A('/api/health');
  var s=await A('/api/stats');
  var bn=await A('/api/bans');
  var ev=await A('/api/events?limit=50');
  var tl=await A('/api/events-timeline?hours=24');
  var co=await A('/api/asn-stats');
  var th=await A('/api/threat-distribution');
  var pg=await A('/api/plugin-stats');
  var at=await A('/api/top-portscanned-ports?limit=10');
  var ti=await A('/api/blocklist');
  var gh=await A('/api/geo-heatmap?hours=24');

  // Health
  if(h){
    var serviceUptime=h.uptime||'--:--:--';
    var systemUptime=h.system_uptime||'--';
    $('#su').textContent=serviceUptime;
    $('#ssu').textContent=systemUptime;
    $('#ut').textContent='Service: '+serviceUptime+' • System: '+systemUptime;
  }

  // Stats
  if(s){
    $('#se').textContent=N(s.total_events);
    $('#stb').textContent=N(s.total_bans);
    $('#sab').textContent=N(s.active_bans);
    $('#sfw').textContent=N(s.firewall_active_bans);
    var sim=s.simulation_mode;
    var bd=$('#sb');
    if(sim){bd.className='bdg bdg-sim';bd.innerHTML='SIMULATION'}
    else{bd.className='bdg bdg-live';bd.innerHTML='<span class="dot"></span>LIVE'}
  }

  // Bans Table
  var btb=$('#bnb'),be=$('#bne'),bp=$('#bc');
  if(!bn||!bn.bans||!bn.bans.length){btb.innerHTML='';be.style.display='block';bp.textContent='0'}
  else{be.style.display='none';bp.textContent=bn.count;
    btb.innerHTML=bn.bans.map(function(b){
      return '<tr><td class="h" title="'+E(b.source_ip)+'">'+E((b.source_ip||'').substring(0,16))+'&hellip;</td><td><span class="rb '+RC(b.risk_score)+'">'+b.risk_score+'</span></td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(b.reason)+'">'+E(b.reason)+'</td><td>'+D(b.ban_duration)+'</td><td>'+T(b.banned_at_unix||b.banned_at)+'</td><td>'+(b.expires_at?T(b.expires_at_unix||b.expires_at):'Never')+'</td></tr>';
    }).join('')}

  // Events Table
  var etb=$('#evb'),ee=$('#eve'),ep=$('#ec');
  if(!ev||!ev.events||!ev.events.length){etb.innerHTML='';ee.style.display='block';ep.textContent='0'}
  else{ee.style.display='none';ep.textContent=ev.count;
    etb.innerHTML=ev.events.map(function(e){
      var pl=(e.connection_type||'unknown').toUpperCase();
      var tc=e.threat_level;
      var tcl=tc==='HIGH'||tc==='CRITICAL'?'tg-H':tc==='MEDIUM'?'tg-M':tc==='LOW'?'tg-L':'tg-N';
      var advice=e.operator_advice||'No specific operator advice for this event.';
      var cc=(e.country_code||'').toUpperCase();
      var origin=cc?CF(cc)+' '+cc:'-';
      return '<tr><td style="white-space:nowrap;font-size:.75rem">'+T(e.timestamp_unix||e.timestamp)+'</td><td class="h" title="'+E(e.source_ip)+'">'+E((e.source_ip||'').substring(0,14))+'&hellip;</td><td><span class="pt">'+E(pl)+'</span></td><td>'+E(e.player_name||'-')+'</td><td style="font-size:.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(origin)+'">'+E(origin)+'</td><td><span class="rb '+RC(e.risk_score)+'">'+e.risk_score+'</span></td><td><span class="tg '+tcl+'">'+E(tc)+'</span></td><td style="font-size:.75rem;color:var(--dim);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(e.asn_org)+'">'+E(e.asn_org||'-')+'</td><td><span class="advice-tip" title="'+E(advice)+'">i</span></td></tr>';
    }).join('')}

  // Timeline
  var tc2=$('#tlc'),tl2=$('#tll');
  if(!tl||!tl.timeline||!tl.timeline.length){tc2.innerHTML='<div class="em" style="width:100%;padding:2rem 0"><div>No timeline data</div></div>';tl2.innerHTML=''}
  else{
    var mx=Math.max(...tl.timeline.map(function(t){return t.count}),1);
    tc2.innerHTML=tl.timeline.map(function(t){
      var pct=Math.max((t.count/mx)*100,2);
      var hr=t.hour?(t.hour.split(' ')[1]||t.hour):'';
      return '<div class="tb" style="height:'+pct+'%" data-t="'+hr+': '+t.count+' events"></div>';
    }).join('');
    tl2.innerHTML=tl.timeline.map(function(t,i){
      var hr=t.hour?(t.hour.split(' ')[1]||''):'';
      var show=i%Math.max(1,Math.floor(tl.timeline.length/12))===0;
      return '<span>'+(show?hr:'')+'</span>';
    }).join('')}

  // Threat Distribution
  if(th&&th.distribution){
    var cm={HIGH:1,CRITICAL:1,MEDIUM:3,LOW:2,NONE:5};
    var el=$('#thc');
    var tmx=Math.max(...th.distribution.map(function(d){return d.count}),1);
    el.innerHTML=th.distribution.map(function(d){
      var pct=Math.max((d.count/tmx)*100,3);
      return '<div class="br"><span class="bl2">'+E(d.level)+'</span><div class="bt"><div class="bf '+CC[cm[d.level]||0]+'" style="width:'+pct+'%">'+N(d.count)+'</div></div></div>';
    }).join('')}
  else bars('thc',[],'level','count',0);

  // Country
  var countryItems=co&&co.countries?co.countries.filter(function(item){
    var code=String((item&&item.country)||'').toUpperCase();
    return code && code!=='ZZ';
  }):null;
  bars('coc',countryItems,'country','count',2);

  // Plugins
  bars('plc',pg?pg.plugins:null,'plugin','count',3);

  // Top scanned ports
  var ap=$('#ac');
  if(at&&at.ports){ap.textContent=at.ports.length;
    var ait=at.ports.map(function(p){return{label:'Port '+String(p.port||'-'),count:p.scan_count||0}});
    bars('atc',ait,'label','count',1)}
  else{ap.textContent='0';bars('atc',[],'label','count',1)}

  renderBlocklist(ti);
  renderGeoHeatmap(gh);
}

initTheme();
$('#themeToggle').addEventListener('click',function(){
  applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');
});
refresh();
setInterval(refresh,R);
})();
</script>
</body>
</html>"""


DASHBOARD_V2_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WardenIPS Admin Console</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#110f18;--bg2:#1d1730;--panel:#1d1a29;--panel2:#171420;--surface:#140f1f;--surface2:#120d1b;--b:#3b3150;--txt:#f5f1ea;--muted:#b8accc;--blue:#5ea1ff;--cyan:#39d0c6;--green:#4fd18f;--yellow:#ffbe5c;--red:#ff6f7e;--accent:#ff875f;--shadow:0 30px 80px #00000045}
:root[data-theme="light"]{--bg:#f4eee4;--bg2:#e9ddcf;--panel:#fffdf8;--panel2:#f7f1e8;--surface:#f3eadf;--surface2:#f9f4eb;--b:#dac8b2;--txt:#221d17;--muted:#74685b;--blue:#2f6fe4;--cyan:#0f8f92;--green:#1f8b57;--yellow:#c98410;--red:#c84e58;--accent:#c95c2b;--shadow:0 22px 48px rgba(73,49,19,.12)}
html{font-size:clamp(13px,0.26vw + 12px,16px)}
body{font-family:Georgia,"Aptos",serif;background:radial-gradient(circle at top left,var(--bg2) 0%,var(--bg) 48%,var(--surface) 100%);color:var(--txt);min-height:100vh;transition:background .25s ease,color .25s ease}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(circle at 85% 12%,color-mix(in srgb,var(--accent) 18%,transparent) 0%,transparent 24%),radial-gradient(circle at 12% 78%,color-mix(in srgb,var(--cyan) 16%,transparent) 0%,transparent 28%);pointer-events:none}
.app{max-width:1600px;margin:0 auto;padding:26px;position:relative;z-index:1}.top{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;gap:18px;margin-bottom:22px}.brand h1{font-size:2rem;font-weight:800;letter-spacing:-.04em}.brand p{font-size:.95rem;color:var(--muted);margin-top:6px;max-width:58ch;line-height:1.5}.utility-strip{display:grid;grid-template-columns:1.45fr .95fr;gap:16px;margin-bottom:16px}.utility-card,.hero-card,.side-card,.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:20px;padding:18px;box-shadow:var(--shadow)}.utility-card strong{display:block;font-size:.9rem;margin-bottom:6px}.utility-card p{font-size:.82rem;color:var(--muted);line-height:1.6}.utility-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.utility-metrics div{padding:12px;border-radius:14px;background:var(--surface);border:1px solid var(--b)}.utility-metrics span{display:block;font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:4px}
.actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}.toolbar,.action-grid,.notification-grid,.config-actions,.quick-toggle-grid,.action-columns,.modal-header{display:flex;gap:10px;flex-wrap:wrap}.toolbar-grid{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;margin-bottom:12px}.ctrl,.btn,.config-editor,.config-input,.config-select{background:var(--surface2);border:1px solid var(--b);color:var(--txt);border-radius:14px;padding:10px 13px;font-size:.88rem;transition:transform .18s ease,background .18s ease,border-color .18s ease}.btn{cursor:pointer;font-weight:700}.btn:hover{transform:translateY(-1px)}.btn.primary{background:linear-gradient(135deg,var(--accent),#ff6f61);border-color:color-mix(in srgb,var(--accent) 60%,white)}.btn.warn{background:linear-gradient(135deg,#b45309,#ea580c);border-color:#fb923c}.btn.danger{background:linear-gradient(135deg,#9f1239,#e11d48);border-color:#fb7185}.btn.ghost{background:var(--surface)}.btn.cyan{background:linear-gradient(135deg,var(--cyan),#0f9ea6);border-color:color-mix(in srgb,var(--cyan) 70%,white)}.btn.theme{background:linear-gradient(135deg,var(--blue),#6d78ff);border-color:color-mix(in srgb,var(--blue) 65%,white)}.btn.small{padding:7px 10px;font-size:.78rem}.search{flex:1;min-width:220px}.action-grid button,.notification-grid button,.quick-toggle-grid label{flex:1 1 220px}
.hero{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:18px;align-items:start}.hero-card h2,.card h2,.side-card h2{font-size:1rem;font-weight:800;margin-bottom:10px}.hero-meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.metric{padding:14px;border:1px solid var(--b);border-radius:16px;background:linear-gradient(180deg,var(--surface),var(--surface2))}.metric .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px}.metric .v{font-size:1.65rem;font-weight:800}
.layout{display:grid;grid-template-columns:1.45fr 1fr;gap:16px}.stack{display:grid;gap:16px}.split{display:grid;grid-template-columns:1fr 1fr;gap:16px}.table-wrap{max-height:420px;overflow:auto;border:1px solid var(--b);border-radius:14px;background:var(--surface)}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--b);font-size:.84rem;vertical-align:middle}th{position:sticky;top:0;background:var(--surface2);color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}tr:hover td{background:color-mix(in srgb,var(--surface2) 82%,var(--blue) 18%)}
.mono{font-family:Cascadia Code,Fira Code,monospace;font-size:.76rem}.tag{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:999px;font-size:.72rem;font-weight:800}.t-red{background:color-mix(in srgb,var(--red) 20%,transparent);color:#ffd3d7}.t-green{background:color-mix(in srgb,var(--green) 18%,transparent);color:#b8ffe0}.t-yellow{background:color-mix(in srgb,var(--yellow) 18%,transparent);color:#ffe1a7}.t-blue{background:color-mix(in srgb,var(--blue) 18%,transparent);color:#c9deff}
.advice-tip{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border-radius:999px;border:1px solid var(--b);background:var(--surface2);font-size:.72rem;font-weight:800;cursor:help}
.list,.advice{display:grid;gap:10px}.list-item,.advice-item,.panel-box{padding:13px;border:1px solid var(--b);border-radius:14px;background:linear-gradient(180deg,var(--surface),var(--surface2))}.list-item strong,.advice-item strong,.panel-box strong{display:block;margin-bottom:6px}.sub{font-size:.78rem;color:var(--muted);line-height:1.5}.status{min-height:52px}.status.ok{border-color:color-mix(in srgb,var(--green) 55%,var(--b));background:color-mix(in srgb,var(--green) 14%,var(--surface))}.status.err{border-color:color-mix(in srgb,var(--red) 55%,var(--b));background:color-mix(in srgb,var(--red) 14%,var(--surface))}.status strong{margin-bottom:4px}.linkbar{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}.linkbar a{color:var(--blue);text-decoration:none;font-size:.82rem}.linkbar a:hover{text-decoration:underline}.empty{padding:24px;text-align:center;color:var(--muted)}.admin-footer{margin-top:16px;text-align:center;color:var(--muted);font-size:.76rem}.admin-footer a{color:var(--blue);text-decoration:none}.notification-grid{margin-top:4px}.theme-chip{display:inline-flex;align-items:center;gap:8px;padding:8px 10px;border-radius:999px;background:var(--surface);border:1px solid var(--b);font-size:.76rem;color:var(--muted)}.toast-stack{position:fixed;top:22px;right:22px;display:grid;gap:10px;z-index:45;max-width:min(420px,calc(100vw - 28px))}.toast{padding:14px 16px;border-radius:16px;border:1px solid var(--b);background:linear-gradient(180deg,var(--panel),var(--surface));box-shadow:var(--shadow);backdrop-filter:blur(10px);transform:translateY(-6px);opacity:0;pointer-events:none;transition:opacity .18s ease,transform .18s ease}.toast.show{opacity:1;transform:translateY(0);pointer-events:auto}.toast.ok{border-color:color-mix(in srgb,var(--green) 55%,var(--b));background:linear-gradient(180deg,color-mix(in srgb,var(--green) 16%,var(--panel)),var(--surface))}.toast.err{border-color:color-mix(in srgb,var(--red) 55%,var(--b));background:linear-gradient(180deg,color-mix(in srgb,var(--red) 18%,var(--panel)),var(--surface))}.toast.info{border-color:color-mix(in srgb,var(--blue) 45%,var(--b));background:linear-gradient(180deg,color-mix(in srgb,var(--blue) 10%,var(--panel)),var(--surface))}.toast-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:4px}.toast-close{appearance:none;border:0;background:transparent;color:var(--muted);cursor:pointer;font-size:1rem;line-height:1}.update-banner{margin-bottom:16px;padding:16px 18px;border:1px solid var(--b);border-radius:18px;background:linear-gradient(180deg,var(--panel),var(--surface));box-shadow:var(--shadow)}.update-banner[hidden]{display:none}.update-banner.warn{border-color:color-mix(in srgb,var(--accent) 55%,var(--b));background:linear-gradient(180deg,color-mix(in srgb,var(--accent) 16%,var(--panel)),var(--surface))}.update-banner.info{border-color:color-mix(in srgb,var(--cyan) 45%,var(--b));background:linear-gradient(180deg,color-mix(in srgb,var(--cyan) 10%,var(--panel)),var(--surface))}.update-banner-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:8px}.update-banner-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}.update-banner-list{display:grid;gap:6px;margin-top:10px;padding-left:18px;color:var(--txt)}.config-editor{width:100%;min-height:280px;resize:vertical;font-family:Cascadia Code,Fira Code,monospace;line-height:1.55}.field-switch{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:12px 14px;border:1px solid var(--b);border-radius:14px;background:linear-gradient(180deg,var(--surface),var(--surface2))}.field-switch strong{display:block;font-size:.84rem;margin-bottom:4px}.field-switch span{display:block}.field-switch input{width:18px;height:18px;accent-color:var(--accent)}.toolbar-note{margin-bottom:12px;color:var(--muted);font-size:.8rem}.config-actions{margin-top:12px}.utility-note{display:flex;align-items:center;justify-content:space-between;gap:14px}.utility-note .sub{max-width:58ch}.modal-backdrop{position:fixed;inset:0;background:#09060f88;backdrop-filter:blur(8px);display:grid;place-items:center;padding:22px;z-index:30}.modal-backdrop[hidden]{display:none}.modal-card{width:min(100%,1080px);max-height:min(88vh,920px);overflow:auto;background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:22px;padding:20px;box-shadow:var(--shadow)}.modal-header{align-items:center;justify-content:space-between;margin-bottom:12px}.modal-header p{margin:0;color:var(--muted);font-size:.84rem;line-height:1.5}.modal-body{display:grid;gap:14px}.config-sections{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.config-section{padding:16px;border:1px solid var(--b);border-radius:18px;background:linear-gradient(180deg,var(--surface),var(--surface2))}.config-section h3{font-size:.92rem;margin-bottom:6px}.config-section p{color:var(--muted);font-size:.78rem;line-height:1.5;margin-bottom:12px}.config-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 12px}.config-field{display:grid;gap:6px}.config-field label{font-size:.76rem;color:var(--muted);font-weight:700}.config-field.full,.config-toggle.full{grid-column:1/-1}.config-toggle{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border:1px solid var(--b);border-radius:14px;background:var(--surface2)}.config-toggle span{font-size:.8rem}.advanced-wrap{border-top:1px solid var(--b);padding-top:14px}.advanced-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px}.advanced-body[hidden]{display:none}.kofi-fab{position:fixed;right:18px;bottom:18px;z-index:20;display:inline-flex;align-items:center;gap:.45rem;padding:.55rem .9rem;border-radius:999px;background:linear-gradient(135deg,var(--surface2),var(--surface));border:1px solid var(--b);color:var(--txt);text-decoration:none;font-size:.78rem;font-weight:700;box-shadow:0 10px 30px #00000055;transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease;backdrop-filter:blur(4px)}.kofi-fab .heart{font-size:.9rem;line-height:1;color:#fb7185}.kofi-fab .sub{font-size:.68rem;color:var(--muted);font-weight:600}.kofi-fab:hover{transform:translateY(-2px);border-color:var(--accent);box-shadow:0 14px 34px #00000070;text-decoration:none}
@media(max-width:1100px){.top,.utility-strip,.hero,.layout,.split,.toolbar-grid{grid-template-columns:1fr}.hero-meta{grid-template-columns:repeat(2,minmax(0,1fr))}.utility-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.actions{justify-content:flex-start}}
@media(max-width:900px){.config-sections,.config-grid{grid-template-columns:1fr}}
@media(max-width:680px){.app{padding:14px}.hero-meta,.utility-metrics{grid-template-columns:1fr}.actions,.toolbar,.action-grid,.notification-grid,.config-actions,.quick-toggle-grid,.modal-header{width:100%}.ctrl,.btn,.config-input,.config-select{width:100%}}
</style>
<style>
.modal-card{padding:0;max-height:min(92vh,980px);display:flex;flex-direction:column;overflow:hidden}
.modal-header{position:sticky;top:0;z-index:4;margin:0;padding:16px 18px;border-bottom:1px solid var(--b);background:linear-gradient(180deg,var(--panel),color-mix(in srgb,var(--panel2) 85%,var(--surface) 15%))}
.modal-body{padding:14px 16px 18px;overflow:auto}
.modal-header-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.config-filter{min-width:260px;background:var(--surface);border-color:color-mix(in srgb,var(--blue) 35%,var(--b))}
.config-sections{display:block;column-count:2;column-gap:14px}
.config-section{position:relative;display:inline-block;width:100%;margin:0 0 14px;break-inside:avoid;transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease}
.config-section{overflow:hidden}
.config-section:hover{transform:translateY(-1px);border-color:color-mix(in srgb,var(--accent) 45%,var(--b));box-shadow:0 14px 28px #00000022}
.config-section h3{display:flex;align-items:center;justify-content:space-between}
.config-section h3::after{content:'Section';font-size:.64rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:3px 7px;border:1px solid var(--b);border-radius:999px;background:var(--surface2)}
.config-grid{grid-template-columns:repeat(2,minmax(150px,1fr))}
.config-field{min-width:0}
.config-field label{white-space:normal;line-height:1.3}
.config-input,.config-select{width:100%;min-width:0}
.toolbar-grid.three{grid-template-columns:minmax(0,1fr) 120px 160px}
.toolbar-grid.query-grid{grid-template-columns:170px minmax(0,1fr) 150px}
.toolbar-grid.dual-actions{grid-template-columns:minmax(0,1fr) auto auto}
.toolbar-grid.stack-label{margin-bottom:6px}
.chip-editor{display:flex;flex-wrap:wrap;gap:8px;min-height:42px;padding:8px 10px;border:1px solid var(--b);border-radius:12px;background:var(--surface2)}
.chip-editor.empty::before{content:'No ignored ports';color:var(--muted);font-size:.78rem}
.chip{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;background:color-mix(in srgb,var(--blue) 20%,var(--surface));border:1px solid color-mix(in srgb,var(--blue) 40%,var(--b));font-size:.78rem}
.chip button{all:unset;cursor:pointer;font-weight:700;color:var(--muted);line-height:1}
.chip button:hover{color:var(--txt)}
.primary-actions{position:sticky;bottom:0;z-index:3;background:linear-gradient(180deg,color-mix(in srgb,var(--panel2) 80%,transparent),var(--panel2));padding:12px;border:1px solid var(--b);border-radius:14px;backdrop-filter:blur(2px)}
.advanced-wrap{margin-top:2px}
@media(max-width:1280px){.config-sections{column-count:2}}
@media(max-width:900px){.config-sections{column-count:1}}
@media(max-width:680px){.modal-header-actions,.primary-actions{width:100%}.config-filter{min-width:0;width:100%}.toolbar-grid.three,.toolbar-grid.dual-actions{grid-template-columns:1fr}}
@media(max-width:680px){.toolbar-grid.query-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="app">
  <div class="top">
    <div class="brand">
      <h1>WardenIPS Admin Console</h1>
      <p>Interactive operational view for bans, firewall state, events, and blocklist intelligence.</p>
      <div class="linkbar">
        <a href="/dashboard">Open Public Dashboard</a>
        <a href="/admin">Admin Route</a>
        <a href="https://github.com/msncakma/WardenIPS" target="_blank" rel="noopener">Repository</a>
        <a href="https://github.com/msncakma/WardenIPS/stargazers" target="_blank" rel="noopener">Star on GitHub</a>
        <a href="https://github.com/msncakma/WardenIPS/issues" target="_blank" rel="noopener">Issues</a>
        <a href="https://ko-fi.com/msncakma" target="_blank" rel="noopener">Support on Ko-fi</a>
      </div>
    </div>
    <div class="actions">
      <input id="globalSearch" class="ctrl search" placeholder="Filter events, source IPs, plugins, countries...">
      <select id="refreshRate" class="ctrl">
        <option value="1000">Refresh 1s</option>
        <option value="3000">Refresh 3s</option>
        <option value="5000">Refresh 5s</option>
      </select>
      <button id="openConfigBtn" class="btn ghost">Config</button>
      <button id="themeToggle" class="btn theme">Light Mode</button>
      <button id="logoutBtn" class="btn">Log Out</button>
      <button id="refreshNow" class="btn primary">Refresh Now</button>
    </div>
  </div>

  <div class="utility-strip">
    <div class="utility-card">
      <div class="utility-note">
        <div>
          <strong>Operations Overview</strong>
          <p class="sub">Everything sensitive stays here: firewall actions, cleanup tools, and live configuration control.</p>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end">
          <div id="simulationTopNotice" class="theme-chip" hidden style="border-color:color-mix(in srgb,var(--red) 55%,var(--b));color:#ffd6db;background:color-mix(in srgb,var(--red) 16%,var(--surface));">Warning: Simulation mode is enabled. No blocking actions will be applied.</div>
          <div class="theme-chip" id="themeChip">Theme: Dark</div>
        </div>
      </div>
    </div>
    <div class="utility-card">
      <div class="utility-metrics">
        <div><span>Access</span>Login required</div>
        <div><span>Session</span>Idle expires</div>
        <div><span>Route</span>/admin</div>
        <div><span>Config</span>Editable</div>
      </div>
    </div>
  </div>

  <div id="updateNotice" class="update-banner" hidden>
    <div class="update-banner-head">
      <div>
        <strong id="updateNoticeTitle">Update Notice</strong>
        <div class="sub" id="updateNoticeBody">Checking release metadata...</div>
      </div>
      <button id="dismissUpdateNoticeBtn" class="btn ghost">Dismiss</button>
    </div>
    <ul id="updateNoticeList" class="update-banner-list"></ul>
    <div class="update-banner-actions">
      <a id="updateNoticeLink" class="btn ghost" href="https://github.com/msncakma/WardenIPS/releases" target="_blank" rel="noopener">Open Release</a>
    </div>
  </div>

  <div class="hero">
    <div class="hero-card">
      <h2>Operational Summary</h2>
      <div class="hero-meta">
        <div class="metric"><div class="k">Total Events</div><div class="v" id="mEvents">0</div></div>
        <div class="metric"><div class="k">Active DB Bans</div><div class="v" id="mDbBans">0</div></div>
        <div class="metric"><div class="k">Firewall IPs</div><div class="v" id="mFwBans">0</div></div>
        <div class="metric"><div class="k">Blocklist</div><div class="v" id="mPeers">Disabled</div></div>
      </div>
    </div>
    <div class="side-card">
      <h2>Runtime</h2>
      <div class="list">
        <div class="list-item"><strong id="runtimeMode">Mode: --</strong><span class="sub" id="runtimeUptime">Uptime: --</span></div>
        <div class="list-item"><strong id="lastUpdated">Last updated: --</strong><span class="sub">The admin session logs out after 10 minutes of no real user activity.</span></div>
        <div class="list-item"><strong id="idleStatus">Idle timeout: 10m</strong><span class="sub" id="idleCountdown">Monitoring operator activity.</span></div>
      </div>
    </div>
  </div>

  <div class="layout">
    <div class="stack">
      <div class="card">
        <h2>Action Center</h2>
        <div class="toolbar-grid stack-label">
          <div class="sub">Manual Ban</div>
        </div>
        <div class="toolbar-grid three">
          <input id="manualBanIp" class="ctrl search" placeholder="Enter an IP address to ban manually">
          <input id="manualBanDuration" class="ctrl" type="number" min="0" value="0" placeholder="Duration (sec, 0=permanent)">
          <button id="banManualBtn" class="btn warn">Ban IP</button>
        </div>
        <div class="toolbar-grid">
          <input id="manualBanReason" class="ctrl search" placeholder="Optional reason (default: [ADMIN] Manual ban from dashboard)">
        </div>
        <div class="toolbar-grid stack-label">
          <div class="sub">Manual Unban</div>
        </div>
        <div class="toolbar-grid">
          <input id="manualIp" class="ctrl search" placeholder="Enter an IP address to unban from the firewall">
          <button id="unbanManualBtn" class="btn primary">Unban IP</button>
        </div>
        <div class="toolbar-grid stack-label">
          <div class="sub">Whitelist Management (allowed IP/CIDR)</div>
        </div>
        <div class="toolbar-grid dual-actions">
          <input id="manualWhitelist" class="ctrl search" placeholder="Enter IP or CIDR (example: 203.0.113.4 or 203.0.113.0/24)">
          <button id="addWhitelistBtn" class="btn cyan">Add Whitelist</button>
          <button id="removeWhitelistBtn" class="btn ghost">Remove From Whitelist</button>
        </div>
        <div class="toolbar-grid stack-label">
          <div class="sub">Record Query (IP / ASN / Username)</div>
        </div>
        <div class="toolbar-grid query-grid">
          <select id="queryField" class="ctrl">
            <option value="auto">Auto Detect</option>
            <option value="ip">IP</option>
            <option value="asn">ASN</option>
            <option value="user">Username</option>
          </select>
          <input id="queryValue" class="ctrl search" placeholder="Example: 203.0.113.4, AS15169, notch">
          <button id="queryRunBtn" class="btn ghost">Run Query</button>
        </div>
        <div class="table-wrap" style="max-height:240px">
          <table>
            <thead><tr><th>Type</th><th>Time</th><th>IP</th><th>Details</th><th>Risk</th></tr></thead>
            <tbody id="queryRows"></tbody>
          </table>
        </div>
        <div class="toolbar-grid stack-label">
          <div class="sub">Admin Security</div>
        </div>
        <div class="toolbar-grid query-grid">
          <div id="adminTotpLabel" class="sub">Require TOTP on login for this admin account</div>
          <input id="adminTotpEnabled" class="ctrl" type="checkbox" aria-label="Require TOTP for this admin account" style="width:1.15rem;height:1.15rem;justify-self:start;align-self:center">
          <button id="saveAdminTotpBtn" class="btn ghost">Save TOTP Setting</button>
        </div>
        <div class="action-grid">
          <button id="enforceSimBansBtn" class="btn primary" hidden>Apply Simulated Bans To Firewall</button>
          <button id="reconcileBansBtn" class="btn cyan">Push Active DB Bans -> Firewall</button>
          <button id="deactivateAllBansBtn" class="btn ghost">Deactivate All DB Bans</button>
          <button id="flushFirewallBtn" class="btn warn">Flush Firewall Bans</button>
          <button id="clearEventsBtn" class="btn ghost">Clear Event History</button>
          <button id="clearBanHistoryBtn" class="btn danger">Clear Ban History</button>
        </div>
      </div>

      <div class="card">
        <h2>Recent Security Events</h2>
        <div class="toolbar">
          <select id="eventPluginFilter" class="ctrl"><option value="">All Plugins</option></select>
          <select id="eventThreatFilter" class="ctrl"><option value="">All Threats</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option><option value="SUCCESS">Successful Login</option><option value="NONE">None</option></select>
          <select id="eventCountryFilter" class="ctrl"><option value="">All Countries</option></select>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Source IP</th><th>Plugin</th><th>Country</th><th>Risk</th><th>Threat</th><th>ASN</th><th>Advice</th></tr></thead>
            <tbody id="eventsRows"></tbody>
          </table>
        </div>
      </div>

      <div class="split">
        <div class="card">
          <h2>Active Database Bans</h2>
          <div class="toolbar"><select id="banSort" class="ctrl"><option value="recent">Sort: Recent</option><option value="risk">Sort: Highest Risk</option></select></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Source IP</th><th>Risk</th><th>Reason</th><th>Expires</th><th>Action</th></tr></thead>
              <tbody id="banRows"></tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <h2>Active Firewall IPs</h2>
          <div class="toolbar"><select id="ipFamilyFilter" class="ctrl"><option value="">All Families</option><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>IP Address</th><th>Family</th><th>Action</th></tr></thead>
              <tbody id="firewallRows"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div class="stack">
      <div class="card"><h2>Operator Advice</h2><div class="advice" id="adviceList"></div></div>
      <div class="card"><h2>Blocklist Protection</h2><div class="list" id="meshList"></div></div>
      <div class="card"><h2>Top Portscanned Ports</h2><div class="list" id="topPortsList"></div></div>
    </div>
  </div>

  <div class="admin-footer">WardenIPS v__APP_VERSION__ · by __APP_AUTHOR__ · Authenticated operational console · <a href="https://github.com/msncakma/WardenIPS" target="_blank" rel="noopener">GitHub</a> · <a href="https://github.com/msncakma/WardenIPS/stargazers" target="_blank" rel="noopener">Star</a> · <a href="https://github.com/msncakma/WardenIPS/issues" target="_blank" rel="noopener">Issues</a></div>
</div>

<div id="configModal" class="modal-backdrop" hidden>
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="configModalTitle">
    <div class="modal-header">
      <div>
        <h2 id="configModalTitle">Config Studio</h2>
        <p>Use the section cards for normal operations. Advanced YAML stays available, but out of the way.</p>
      </div>
      <div class="modal-header-actions">
        <input id="configSectionSearch" class="ctrl config-filter" placeholder="Filter sections and settings...">
        <button id="closeConfigBtn" class="btn ghost">Close</button>
      </div>
    </div>
    <div class="modal-body">
      <div class="toolbar-note" id="configFilterHint">Quick filter by section name or setting label.</div>
      <div class="config-sections">
        <section class="config-section">
          <h3>Monitoring</h3>
          <p>Core analysis cadence and how successful sign-ins affect risk history.</p>
          <div class="config-grid">
            <div class="config-field">
              <label for="cfgLogLevel">Log Level</label>
              <select id="cfgLogLevel" class="config-select">
                <option value="DEBUG">DEBUG</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
              </select>
            </div>
            <div class="config-field">
              <label for="cfgAnalysisInterval">Analysis Window (min)</label>
              <input id="cfgAnalysisInterval" class="config-input" type="number" min="1">
            </div>
            <label class="config-toggle"><span>Log Successful Sign-ins</span><input id="cfgSuccessEnabled" type="checkbox"></label>
            <label class="config-toggle"><span>Reset Risk On Success</span><input id="cfgSuccessReset" type="checkbox"></label>
          </div>
        </section>
        <section class="config-section">
          <h3>Dashboard Access</h3>
          <p>Visibility, session timing, and operator login rate controls.</p>
          <div class="config-grid">
            <label class="config-toggle full"><span>Enable Public Dashboard</span><input id="cfgPublicDashboard" type="checkbox"></label>
            <div class="config-field">
              <label for="cfgSessionTtl">Session TTL (sec)</label>
              <input id="cfgSessionTtl" class="config-input" type="number" min="60">
            </div>
            <div class="config-field">
              <label for="cfgLoginRate">Login Rate Limit / min</label>
              <input id="cfgLoginRate" class="config-input" type="number" min="1">
            </div>
          </div>
        </section>
        <section class="config-section">
          <h3>Firewall Policy</h3>
          <p>Ban thresholding and default ban duration for enforced actions.</p>
          <div class="config-grid">
            <label class="config-toggle full"><span>Simulation Mode (No Action)</span><input id="cfgSimulationMode" type="checkbox"></label>
            <div class="config-field">
              <label for="cfgBanThreshold">Ban Threshold</label>
              <input id="cfgBanThreshold" class="config-input" type="number" min="0" max="100">
            </div>
            <div class="config-field">
              <label for="cfgBanDuration">Default Ban Duration (sec)</label>
              <input id="cfgBanDuration" class="config-input" type="number" min="0">
            </div>
          </div>
        </section>
        <section class="config-section">
          <h3>Notifications</h3>
          <p>Channel toggles and delivery endpoints for operator alerts.</p>
          <div class="config-grid">
            <label class="config-toggle full"><span>Telegram Enabled</span><input id="cfgTelegramEnabled" type="checkbox"></label>
            <div class="config-field full">
              <label for="cfgTelegramChatId">Telegram Chat ID</label>
              <input id="cfgTelegramChatId" class="config-input" type="text" spellcheck="false">
            </div>
            <label class="config-toggle full"><span>Discord Enabled</span><input id="cfgDiscordEnabled" type="checkbox"></label>
            <div class="config-field full">
              <label for="cfgDiscordWebhook">Discord Webhook URL</label>
              <input id="cfgDiscordWebhook" class="config-input" type="text" spellcheck="false">
            </div>
            <label class="config-toggle full"><span>Notify On Ban Events</span><input id="cfgNotifOnBan" type="checkbox"></label>
            <label class="config-toggle full"><span>Notify On Burst Flood Events</span><input id="cfgNotifOnBurst" type="checkbox"></label>
            <label class="config-toggle full"><span>Notify On Manual Admin Bans</span><input id="cfgNotifOnManualBan" type="checkbox"></label>
            <div class="config-field">
              <label for="cfgNotifMinRisk">Minimum Risk For Ban Alerts</label>
              <input id="cfgNotifMinRisk" class="config-input" type="number" min="0" max="100">
            </div>
            <div class="config-field full">
              <label>Delivery Tests</label>
              <div class="notification-grid">
                <button id="testAllNotificationsBtn" class="btn primary" type="button">Send All Test Messages</button>
                <button id="testTelegramBtn" class="btn cyan" type="button">Test Telegram</button>
                <button id="testDiscordBtn" class="btn ghost" type="button">Test Discord</button>
              </div>
            </div>
            <div class="toolbar-note full">Notification triggers are now selectable from this panel and applied immediately after saving.</div>
          </div>
        </section>
        <section class="config-section">
          <h3>Plugins</h3>
          <p>Plugin activation, Minecraft burst heuristics, and Portscan exclusions.</p>
          <div class="config-grid">
            <label class="config-toggle full"><span>SSH Plugin Enabled</span><input id="cfgSshEnabled" type="checkbox"></label>
            <label class="config-toggle full"><span>Minecraft Plugin Enabled</span><input id="cfgMinecraftEnabled" type="checkbox"></label>
            <div class="config-field">
              <label for="cfgMinecraftBurstThreshold">MC Burst Threshold</label>
              <input id="cfgMinecraftBurstThreshold" class="config-input" type="number" min="2">
            </div>
            <div class="config-field">
              <label for="cfgMinecraftBurstWindow">MC Burst Window (sec)</label>
              <input id="cfgMinecraftBurstWindow" class="config-input" type="number" min="1">
            </div>
            <div class="config-field full">
              <label for="cfgPortscanIgnoredPortsEntry">Portscan Ignored Ports (chip list)</label>
              <input id="cfgPortscanIgnoredPorts" type="hidden">
              <div id="cfgPortscanIgnoredPortsChips" class="chip-editor"></div>
              <input id="cfgPortscanIgnoredPortsEntry" class="config-input" type="text" spellcheck="false" placeholder="Type port and press Enter (example: 19132)">
              <div class="sub">Press Enter or comma to add. Click x on a chip to remove.</div>
            </div>
          </div>
        </section>
      </div>
      <div class="config-actions primary-actions">
        <button id="reloadConfigBtn" class="btn ghost">Reload From Disk</button>
        <button id="saveFormConfigBtn" class="btn primary">Save Form</button>
      </div>
      <div class="advanced-wrap">
        <div class="advanced-head">
          <div>
            <strong>Advanced YAML</strong>
            <div class="sub">Full-file editing stays here for edge cases and uncommon settings.</div>
          </div>
          <button id="toggleAdvancedYamlBtn" class="btn ghost">Show YAML</button>
        </div>
        <div id="advancedYamlBody" class="advanced-body" hidden>
          <textarea id="configEditor" class="config-editor" spellcheck="false" placeholder="Loading config.yaml..."></textarea>
          <div class="config-actions">
            <button id="saveConfigBtn" class="btn primary">Save YAML</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="toastStack" class="toast-stack" aria-live="polite" aria-atomic="true"></div>

<a class="kofi-fab" href="https://ko-fi.com/msncakma" target="_blank" rel="noopener" title="Support WardenIPS on Ko-fi">
  <span class="heart">♥</span>
  <span>Support the project <span class="sub">on Ko-fi</span></span>
</a>

<script>
(function(){
'use strict';
var timer = null;
var inputTimers = {};
var activityPingTimer = null;
var idleTimer = null;
var toastTimer = null;
var SESSION_IDLE_MS = __SESSION_TIMEOUT_MS__;
var state = {events:[], bans:[], firewall:[], topPorts:[], mesh:null, stats:null, health:null, theme:'dark', config:null, configYaml:'', advancedYamlOpen:false, updateInfo:null, portscanIgnoredPorts:[], authSettings:null};
function $(s){return document.querySelector(s)}
function N(n){return (n||0).toLocaleString()}
function E(s){var d=document.createElement('div'); d.textContent=s||''; return d.innerHTML}
function isSimulationEnabled(value){
  if(value===true||value===1) return true;
  if(typeof value==='string'){
    var normalized=value.trim().toLowerCase();
    return normalized==='true'||normalized==='1'||normalized==='yes'||normalized==='on';
  }
  return false;
}
function parseTs(v){
  if(v===null||v===undefined||v==='')return null;
  if(typeof v==='number')return v<1e12?v*1000:v;
  var s=String(v).trim();
  if(!s)return null;
  if(/^\d+$/.test(s)){var n=Number(s);return n<1e12?n*1000:n;}
  if(s.indexOf(' ')>0&&s.indexOf('T')===-1)s=s.replace(' ','T');
  var d=new Date(s),ms=d.getTime();
  return Number.isFinite(ms)?ms:null;
}
function ago(value){
  var ts=parseTs(value);
  if(ts===null) return '-';
  var df=Math.floor((Date.now()-ts)/1000);
  if(df<0)df=0;
  if(df<60)return df+'s';
  if(df<3600)return Math.floor(df/60)+'m';
  if(df<86400)return Math.floor(df/3600)+'h';
  return Math.floor(df/86400)+'d';
}
function tagRisk(r){ return r>=70?'t-red':r>=40?'t-yellow':'t-green'; }
function tagThreat(t){ return t==='CRITICAL'||t==='HIGH'?'t-red':t==='MEDIUM'?'t-yellow':t==='LOW'||t==='SUCCESS'?'t-green':'t-blue'; }
function debounce(key, fn, wait){ clearTimeout(inputTimers[key]); inputTimers[key] = setTimeout(fn, wait); }
function filterText(){ return ($('#globalSearch').value||'').trim().toLowerCase(); }
function setStatus(kind, title, message){
  var stack=$('#toastStack');
  var tone=(kind==='err'||kind==='ok')?kind:'info';
  stack.innerHTML='<div id="actionToast" class="toast '+tone+'"><div class="toast-head"><strong>'+E(title)+'</strong><button id="closeActionToast" class="toast-close" type="button" aria-label="Dismiss notification">×</button></div><div class="sub">'+E(message)+'</div></div>';
  var toast=$('#actionToast');
  clearTimeout(toastTimer);
  requestAnimationFrame(function(){ toast.classList.add('show'); });
  var close=function(){ if(!toast){ return; } toast.classList.remove('show'); clearTimeout(toastTimer); toastTimer=setTimeout(function(){ if(stack.contains(toast)){ stack.innerHTML=''; } }, 220); };
  $('#closeActionToast').addEventListener('click', close);
  toastTimer=setTimeout(close, tone==='err' ? 7000 : 4200);
}
function getConfigValue(path, fallback){ var value=state.config||{}; String(path).split('.').forEach(function(part){ value = value && typeof value==='object' ? value[part] : undefined; }); return value===undefined ? fallback : value; }
function parsePortList(value){
  var seen={};
  return String(value||'').split(',').map(function(item){ return item.trim(); }).filter(function(item){
    if(!item || !/^\d+$/.test(item)){ return false; }
    var num=parseInt(item,10);
    if(!Number.isFinite(num) || num<1 || num>65535){ return false; }
    if(seen[num]){ return false; }
    seen[num]=true;
    return true;
  }).map(function(item){ return parseInt(item,10); });
}
function syncPortscanIgnoredPortsField(){ $('#cfgPortscanIgnoredPorts').value=(state.portscanIgnoredPorts||[]).join(','); }
function renderPortscanIgnoredPortChips(){
  var host=$('#cfgPortscanIgnoredPortsChips');
  var ports=state.portscanIgnoredPorts||[];
  host.classList.toggle('empty', ports.length===0);
  host.innerHTML=ports.map(function(port){ return '<span class="chip" data-port="'+E(String(port))+'">'+E(String(port))+'<button type="button" class="chip-remove" aria-label="Remove port">x</button></span>'; }).join('');
}
function setPortscanIgnoredPorts(value){
  if(Array.isArray(value)){
    state.portscanIgnoredPorts=parsePortList(value.join(','));
  }else{
    state.portscanIgnoredPorts=parsePortList(value);
  }
  syncPortscanIgnoredPortsField();
  renderPortscanIgnoredPortChips();
}
function addPortscanIgnoredPortsFromInput(raw){
  var incoming=parsePortList(raw);
  if(!incoming.length){ return false; }
  var existing=state.portscanIgnoredPorts||[];
  var set={};
  existing.concat(incoming).forEach(function(p){ set[p]=true; });
  state.portscanIgnoredPorts=Object.keys(set).map(function(k){ return parseInt(k,10); }).sort(function(a,b){ return a-b; });
  syncPortscanIgnoredPortsField();
  renderPortscanIgnoredPortChips();
  return true;
}
function getDismissKey(info){ return info&&info.update_available&&info.latest_version ? 'wardenips_update_dismissed_'+info.latest_version : info&&info.current_version ? 'wardenips_whatsnew_seen_'+info.current_version : ''; }
function applyTheme(theme){ state.theme = theme==='light' ? 'light' : 'dark'; document.documentElement.setAttribute('data-theme', state.theme); try{ localStorage.setItem('wardenips_admin_theme', state.theme); }catch(error){} $('#themeToggle').textContent = state.theme==='light' ? 'Dark Mode' : 'Light Mode'; $('#themeChip').textContent = 'Theme: ' + (state.theme==='light' ? 'Light' : 'Dark'); }
function initTheme(){ var saved='dark'; try{ saved = localStorage.getItem('wardenips_admin_theme') || 'dark'; }catch(error){} applyTheme(saved); }
function filterConfigSections(){
  var input=$('#configSectionSearch');
  var hint=$('#configFilterHint');
  var query=input?(input.value||'').trim().toLowerCase():'';
  var sections=Array.from(document.querySelectorAll('.config-section'));
  if(!sections.length){ return; }
  var visible=0;
  sections.forEach(function(section){
    var ok=!query || section.textContent.toLowerCase().indexOf(query)!==-1;
    section.style.display=ok?'':'none';
    if(ok){ visible+=1; }
  });
  if(hint){
    hint.textContent=query
      ? ('Showing '+visible+' section(s) for "'+query+'".')
      : 'Quick filter by section name or setting label.';
  }
}
function openConfigModal(){ $('#configModal').hidden=false; document.body.style.overflow='hidden'; filterConfigSections(); var input=$('#configSectionSearch'); if(input){ setTimeout(function(){ input.focus(); }, 0); } }
function closeConfigModal(){ $('#configModal').hidden=true; document.body.style.overflow=''; }
function syncAdvancedYaml(){ $('#advancedYamlBody').hidden=!state.advancedYamlOpen; $('#toggleAdvancedYamlBtn').textContent=state.advancedYamlOpen?'Hide YAML':'Show YAML'; }
function renderUpdateNotice(){
  var box=$('#updateNotice');
  var info=state.updateInfo;
  if(!info || !info.checked){ box.hidden=true; return; }
  var dismissKey=getDismissKey(info);
  try{ if(dismissKey && localStorage.getItem(dismissKey)==='1'){ box.hidden=true; return; } }catch(error){}
  var notes=Array.isArray(info.release_notes_preview)?info.release_notes_preview.filter(Boolean):[];
  var link=info.release_url||'https://github.com/msncakma/WardenIPS/releases';
  $('#updateNoticeLink').href=link;
  if(info.update_available){
    box.className='update-banner warn';
    $('#updateNoticeTitle').textContent='Update available: v'+(info.latest_version||'?');
    $('#updateNoticeBody').textContent='This node runs v'+(info.current_version||'?')+'. A newer release is available with operator-facing improvements.';
  }else if(notes.length){
    box.className='update-banner info';
    $('#updateNoticeTitle').textContent='What\'s new in v'+(info.current_version||'?');
    $('#updateNoticeBody').textContent='This panel detected a newer installed version and is surfacing the latest release highlights once.';
  }else{
    box.hidden=true;
    return;
  }
  $('#updateNoticeList').innerHTML=notes.length?notes.map(function(note){ return '<li>'+E(note)+'</li>'; }).join(''):'<li>Release metadata is available on GitHub.</li>';
  box.hidden=false;
}
async function loadUpdateStatus(){
  var payload=await api('/api/admin/update-status');
  if(!payload){ return; }
  state.updateInfo=payload;
  renderUpdateNotice();
}
async function api(path, options){
  try{
    var response = await fetch(path, options || {});
    var payload = await response.json().catch(function(){ return {}; });
    if(response.status===401 || response.status===503){
      setStatus('err','Session issue', payload.message || 'Authentication is required. Redirecting to login.');
      setTimeout(function(){ window.location.href='/login?next=/admin'; }, 700);
      return null;
    }
    if(!response.ok){
      setStatus('err','Request failed', payload.message || payload.error || 'The request could not be completed.');
      return null;
    }
    return payload;
  }catch(error){
    setStatus('err','Network error','The admin console could not reach the dashboard API.');
    return null;
  }
}
async function sendActivityPing(){
  if(activityPingTimer){ return; }
  activityPingTimer = setTimeout(function(){ activityPingTimer = null; }, 30000);
  await api('/api/session/activity', {method:'POST'});
}
function resetIdleTimer(){
  clearTimeout(idleTimer);
  $('#idleCountdown').textContent = 'Session is active. Idle logout triggers after 10 minutes without input.';
  idleTimer = setTimeout(function(){ logout('Logged out automatically after 10 minutes of inactivity.'); }, SESSION_IDLE_MS);
}
function handleUserActivity(){
  resetIdleTimer();
  sendActivityPing();
}
function renderSummary(){
  var simulation = isSimulationEnabled(state.stats&&state.stats.simulation_mode);
  $('#mEvents').textContent = N(state.stats&&state.stats.total_events);
  $('#mDbBans').textContent = N(state.stats&&state.stats.active_bans);
  $('#mFwBans').textContent = N(state.firewall.length);
  $('#mPeers').textContent = state.blocklist&&state.blocklist.enabled ? (state.blocklist.first_setup&&state.blocklist.first_setup.completed?'Active Only':'First Setup + Active') : 'Disabled';
  $('#runtimeMode').textContent = 'Mode: '+(simulation?'Simulation':'Live');
  $('#runtimeUptime').textContent = 'Service: '+((state.health&&state.health.uptime)||'--')+' | System: '+((state.health&&state.health.system_uptime)||'--');
  $('#lastUpdated').textContent = 'Last updated: '+new Date().toLocaleTimeString();
  $('#simulationTopNotice').hidden = !simulation;
  $('#enforceSimBansBtn').hidden = !simulation;
}
function renderEvents(){
  var simulation = isSimulationEnabled(state.stats&&state.stats.simulation_mode);
  var rows=state.events.slice(); var q=filterText(); var plugin=$('#eventPluginFilter').value; var threat=$('#eventThreatFilter').value; var country=$('#eventCountryFilter').value;
  rows=rows.filter(function(e){ var effectiveThreat=(e.threat_label||e.threat_level||'NONE').toUpperCase(); var eventCountry=String(e.country_code||'').toUpperCase(); var blob=[e.source_ip,e.connection_type,e.threat_level,e.threat_label,e.asn_org,e.asn_number,e.player_name,eventCountry].join(' ').toLowerCase(); return (!q||blob.indexOf(q)!==-1)&&(!plugin||e.connection_type===plugin)&&(!threat||effectiveThreat===threat)&&(!country||eventCountry===country); });
  rows.sort(function(a,b){
    var ta=Date.parse(String(a.timestamp||'')); var tb=Date.parse(String(b.timestamp||''));
    if(Number.isFinite(ta)&&Number.isFinite(tb)&&ta!==tb){ return tb-ta; }
    return (Number(b.id)||0)-(Number(a.id)||0);
  });
  $('#eventsRows').innerHTML = rows.length ? rows.map(function(e){ var advice=e.operator_advice||'No specific operator advice for this event.'; if(simulation){ advice += ' Simulation mode is enabled, so no firewall blocking is applied.'; } var cc=(e.country_code||'').toUpperCase(); var country=cc?cc:'-'; var threatLabel=(e.threat_label||e.threat_level||'NONE').toUpperCase(); var rawAsnNum=String(e.asn_number||'').trim(); var asnNum=rawAsnNum ? ('AS'+rawAsnNum.replace(/^AS/i,'')) : ''; var asnOrg=String(e.asn_org||'').trim(); var asnText=asnOrg||asnNum||'-'; if(asnNum&&asnOrg){ asnText=asnNum+' · '+asnOrg; } var asnBadge=e.is_suspicious_asn?'<span class="badge susp" title="Suspicious ASN">⚠</span> ':''; var asnTitle=asnText+(e.is_suspicious_asn?' (Suspicious ASN)':''); return '<tr><td>'+ago(e.timestamp_unix||e.timestamp)+'</td><td class="mono">'+E(e.source_ip||'-')+'</td><td>'+E((e.connection_type||'unknown').toUpperCase())+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(country)+'">'+E(country)+'</td><td><span class="tag '+tagRisk(e.risk_score||0)+'">'+E(String(e.risk_score||0))+'</span></td><td><span class="tag '+tagThreat(threatLabel)+'">'+E(threatLabel)+'</span></td><td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(asnTitle)+'">'+asnBadge+E(asnText)+'</td><td><span class="advice-tip" title="'+E(advice)+'">i</span></td></tr>'; }).join('') : '<tr><td colspan="8" class="empty">No events match the current filters.</td></tr>';
}
function renderBans(){
  var simulation = isSimulationEnabled(state.stats&&state.stats.simulation_mode);
  var rows=state.bans.slice(); var q=filterText(); var sort=$('#banSort').value;
  rows=rows.filter(function(b){ return !q || [b.source_ip,b.reason].join(' ').toLowerCase().indexOf(q)!==-1; });
  rows.sort(function(a,b){ if(sort==='risk'){ return (b.risk_score||0)-(a.risk_score||0); } return String(b.banned_at||'').localeCompare(String(a.banned_at||'')); });
  $('#banRows').innerHTML = rows.length ? rows.map(function(b){ var reason=(b.reason||'-'); if(simulation){ reason += ' [Simulated: not blocked in firewall]'; } return '<tr><td class="mono">'+E(b.source_ip||'-')+'</td><td><span class="tag '+tagRisk(b.risk_score||0)+'">'+E(String(b.risk_score||0))+'</span></td><td>'+E(reason)+'</td><td>'+E(b.expires_at?ago(b.expires_at_unix||b.expires_at)+' left':'Never')+'</td><td><button class="btn small ghost ban-action" data-ip="'+E(b.source_ip)+'">Deactivate</button></td></tr>'; }).join('') : '<tr><td colspan="5" class="empty">'+(simulation?'No simulated ban records match the current filters.':'No active bans match the current filters.')+'</td></tr>';
}
function renderFirewall(){
  var rows=state.firewall.slice(); var q=filterText(); var family=$('#ipFamilyFilter').value;
  rows=rows.filter(function(item){ return (!q||[item.ip,item.family].join(' ').toLowerCase().indexOf(q)!==-1)&&(!family||item.family===family); });
  $('#firewallRows').innerHTML = rows.length ? rows.map(function(item){ return '<tr><td class="mono">'+E(item.ip)+'</td><td>'+E(item.family)+'</td><td><button class="btn small primary fw-action" data-ip="'+E(item.ip)+'">Unban</button></td></tr>'; }).join('') : '<tr><td colspan="3" class="empty">No firewall IPs match the current filters.</td></tr>';
}
function renderQueryResults(rows){
  var target=$('#queryRows');
  if(!rows||!rows.length){
    target.innerHTML='<tr><td colspan="5" class="empty">No records found for this query.</td></tr>';
    return;
  }
  target.innerHTML=rows.map(function(r){
    var kind=String(r.kind||'event').toUpperCase();
    var ts=ago(r.timestamp);
    var ip=E(r.source_ip||'-');
    var details='-';
    if(r.kind==='ban'){
      details=E((r.reason||'-')+' · '+(r.ban_duration&&r.ban_duration>0?(''+r.ban_duration+'s'):'Permanent')+' · '+(r.is_active?'Active':'Inactive'));
    }else{
      var bits=[r.connection_type||'-', r.event_type||'', r.player_name||'', r.asn_org||''];
      details=E(bits.filter(function(v){ return !!v; }).join(' · ')||'-');
    }
    return '<tr><td>'+E(kind)+'</td><td>'+E(ts)+'</td><td class="mono">'+ip+'</td><td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+details+'">'+details+'</td><td>'+E(String(r.risk_score||0))+'</td></tr>';
  }).join('');
}
async function runRecordQuery(){
  var value=$('#queryValue').value.trim();
  if(!value){
    setStatus('err','Missing query','Enter an IP, ASN, or username to search.');
    return;
  }
  var field=$('#queryField').value||'auto';
  var payload=await api('/api/admin/query-records', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({field:field, value:value, limit:300})});
  if(!payload){ return; }
  renderQueryResults(payload.records||[]);
  setStatus('ok','Query complete', 'Found '+N(payload.count||0)+' record(s) for '+(payload.field||field).toUpperCase()+'.');
}
function renderTopPortscannedPorts(){ $('#topPortsList').innerHTML = state.topPorts.length ? state.topPorts.map(function(p){ return '<div class="list-item"><strong class="mono">Port '+E(String(p.port||'-'))+'</strong><div class="sub">Scans: '+N(p.scan_count||0)+' · Last seen: '+ago(p.last_seen)+'</div></div>'; }).join('') : '<div class="empty">No portscan history yet.</div>'; }
function renderAuthSettings(){
  var label=$('#adminTotpLabel');
  var toggle=$('#adminTotpEnabled');
  if(!label||!toggle){ return; }
  var profile=state.authSettings||{};
  var username=String(profile.username||'this admin account');
  var enabled=!!profile.totp_enabled;
  toggle.checked=enabled;
  label.textContent='Require TOTP on login for '+username;
}
async function loadAuthSettings(){
  var payload=await api('/api/admin/auth-settings');
  if(!payload){ return; }
  state.authSettings={ username:String(payload.username||''), totp_enabled:!!payload.totp_enabled };
  renderAuthSettings();
}
function renderBlocklistAdmin(){ var bl=state.blocklist; if(!bl||!bl.enabled){ $('#meshList').innerHTML='<div class="empty">Blocklist protection is disabled.</div>'; return; } var items=[]; if(bl.first_setup){ items.push('<div class="list-item"><strong>First Setup ('+E(bl.first_setup.mode)+')</strong><div class="sub">Status: '+(bl.first_setup.completed?'Completed':'Active — '+E(bl.first_setup.remaining||'unknown')+' remaining')+' · IPs loaded: '+N(bl.first_setup.ips_loaded||0)+'</div></div>'); } if(bl.active){ items.push('<div class="list-item"><strong>Active Blocklist</strong><div class="sub">Total IPs loaded: '+N(bl.active.total_ips_loaded||0)+' · Last fetch: '+ago(bl.active.last_fetch_at)+' · Last count: '+N(bl.active.last_fetch_count||0)+'</div></div>'); } if(bl.last_error){ items.push('<div class="list-item"><strong>Last Error</strong><div class="sub">'+E(bl.last_error)+'</div></div>'); } $('#meshList').innerHTML=items.join('')||'<div class="empty">Blocklist enabled, awaiting first fetch.</div>'; }
function renderConfigStudio(){
  $('#cfgLogLevel').value=String(getConfigValue('general.log_level','INFO'));
  $('#cfgAnalysisInterval').value=String(getConfigValue('general.analysis_interval',5));
  $('#cfgSuccessEnabled').checked=!!getConfigValue('successful_logins.enabled',true);
  $('#cfgSuccessReset').checked=!!getConfigValue('successful_logins.reset_risk_score',true);
  $('#cfgPublicDashboard').checked=!!getConfigValue('dashboard.public_dashboard',true);
  $('#cfgSessionTtl').value=String(getConfigValue('dashboard.session_ttl',600));
  $('#cfgLoginRate').value=String(getConfigValue('dashboard.login_rate_limit_per_minute',10));
  $('#cfgSimulationMode').checked=!!getConfigValue('firewall.simulation_mode',false);
  $('#cfgBanThreshold').value=String(getConfigValue('firewall.ban_threshold',70));
  $('#cfgBanDuration').value=String(getConfigValue('firewall.ipset.default_ban_duration',0));
  $('#manualBanDuration').value=String(getConfigValue('firewall.ipset.default_ban_duration',0));
  $('#cfgTelegramEnabled').checked=!!getConfigValue('notifications.telegram.enabled',false);
  $('#cfgTelegramChatId').value=String(getConfigValue('notifications.telegram.chat_id',''));
  $('#cfgDiscordEnabled').checked=!!getConfigValue('notifications.discord.enabled',false);
  $('#cfgDiscordWebhook').value=String(getConfigValue('notifications.discord.webhook_url',''));
  $('#cfgNotifOnBan').checked=!!getConfigValue('notifications.rules.on_ban',true);
  $('#cfgNotifOnBurst').checked=!!getConfigValue('notifications.rules.on_burst',true);
  $('#cfgNotifOnManualBan').checked=!!getConfigValue('notifications.rules.on_manual_ban',true);
  $('#cfgNotifMinRisk').value=String(getConfigValue('notifications.rules.min_risk_score',70));
  $('#cfgSshEnabled').checked=!!getConfigValue('plugins.ssh.enabled',true);
  $('#cfgMinecraftEnabled').checked=!!getConfigValue('plugins.minecraft.enabled',false);
  $('#cfgMinecraftBurstThreshold').value=String(getConfigValue('plugins.minecraft.global_connection_burst_threshold',12));
  $('#cfgMinecraftBurstWindow').value=String(getConfigValue('plugins.minecraft.global_connection_burst_window_seconds',15));
  setPortscanIgnoredPorts(getConfigValue('plugins.portscan.ignored_ports',[]));
  $('#cfgPortscanIgnoredPortsEntry').value='';
  $('#configEditor').value=state.configYaml||'';
  syncAdvancedYaml();
  filterConfigSections();
}
async function loadConfig(){
  var payload=await api('/api/admin/config');
  if(!payload){ return; }
  state.config=payload.config||{};
  state.configYaml=payload.yaml||'';
  renderConfigStudio();
}
async function saveQuickConfig(){
  var changes={
    'successful_logins.enabled': $('#cfgSuccessEnabled').checked,
    'successful_logins.reset_risk_score': $('#cfgSuccessReset').checked,
    'dashboard.public_dashboard': $('#cfgPublicDashboard').checked
  };
  var payload=await api('/api/admin/config/patch', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({changes:changes})});
  if(!payload){ return false; }
  state.config=payload.config||{};
  state.configYaml=payload.yaml||'';
  renderConfigStudio();
  setStatus('ok','Configuration updated', payload.message||'Config values were updated.');
  return true;
}
async function saveConfigForm(){
  var changes={
    'general.log_level': $('#cfgLogLevel').value,
    'general.analysis_interval': parseInt($('#cfgAnalysisInterval').value,10)||5,
    'successful_logins.enabled': $('#cfgSuccessEnabled').checked,
    'successful_logins.reset_risk_score': $('#cfgSuccessReset').checked,
    'dashboard.public_dashboard': $('#cfgPublicDashboard').checked,
    'dashboard.session_ttl': parseInt($('#cfgSessionTtl').value,10)||600,
    'dashboard.login_rate_limit_per_minute': parseInt($('#cfgLoginRate').value,10)||10,
    'firewall.simulation_mode': $('#cfgSimulationMode').checked,
    'firewall.ban_threshold': parseInt($('#cfgBanThreshold').value,10)||70,
    'firewall.ipset.default_ban_duration': parseInt($('#cfgBanDuration').value,10)||0,
    'notifications.telegram.enabled': $('#cfgTelegramEnabled').checked,
    'notifications.telegram.chat_id': $('#cfgTelegramChatId').value.trim(),
    'notifications.discord.enabled': $('#cfgDiscordEnabled').checked,
    'notifications.discord.webhook_url': $('#cfgDiscordWebhook').value.trim(),
    'notifications.rules.on_ban': $('#cfgNotifOnBan').checked,
    'notifications.rules.on_burst': $('#cfgNotifOnBurst').checked,
    'notifications.rules.on_manual_ban': $('#cfgNotifOnManualBan').checked,
    'notifications.rules.min_risk_score': parseInt($('#cfgNotifMinRisk').value,10)||70,
    'plugins.ssh.enabled': $('#cfgSshEnabled').checked,
    'plugins.minecraft.enabled': $('#cfgMinecraftEnabled').checked,
    'plugins.minecraft.global_connection_burst_threshold': parseInt($('#cfgMinecraftBurstThreshold').value,10)||12,
    'plugins.minecraft.global_connection_burst_window_seconds': parseInt($('#cfgMinecraftBurstWindow').value,10)||15,
    'plugins.portscan.ignored_ports': (state.portscanIgnoredPorts||[])
  };
  var payload=await api('/api/admin/config/patch', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({changes:changes})});
  if(!payload){ return false; }
  state.config=payload.config||{};
  state.configYaml=payload.yaml||'';
  renderConfigStudio();
  setStatus('ok','Configuration updated', payload.message||'Config form values were saved.');
  return true;
}
async function saveConfigYaml(){
  var yamlText=$('#configEditor').value;
  var payload=await api('/api/admin/config', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({yaml:yamlText})});
  if(!payload){ return false; }
  state.config=payload.config||{};
  state.configYaml=payload.yaml||'';
  renderConfigStudio();
  setStatus('ok','Configuration saved', payload.message||'Configuration saved successfully.');
  return true;
}
function renderAdvice(){
  var items=[]; var stats=state.stats||{}; var highRiskEvents=state.events.filter(function(event){ return (event.risk_score||0)>=70; }).length;
  if(isSimulationEnabled(stats.simulation_mode)){ items.push({title:'Simulation mode is enabled', body:'Events and risk scoring continue, but no firewall blocking is applied while simulation mode is active.'}); }
  if((stats.active_bans||0)>0&&state.firewall.length===0){ items.push({title:'Database bans do not match firewall entries', body:'This can be expected in simulation mode. In live mode, check firewall permissions or service startup ordering.'}); }
  if(highRiskEvents>=10){ items.push({title:'High-risk event volume is elevated', body:'Review recent events and confirm whitelist coverage before tightening thresholds further.'}); }
  if(state.blocklist&&state.blocklist.last_error){ items.push({title:'Blocklist fetch encountered an error', body:'Check the configured URLs and network connectivity. Error: '+(state.blocklist.last_error||'unknown')}); }
  if(!items.length){ items.push({title:'No immediate operator action suggested', body:'The current snapshot looks stable. Continue monitoring the live event stream.'}); }
  $('#adviceList').innerHTML=items.map(function(item){ return '<div class="advice-item"><strong>'+E(item.title)+'</strong><div class="sub">'+E(item.body)+'</div></div>'; }).join('');
}
function syncPluginFilter(){ var select=$('#eventPluginFilter'); var current=select.value; var values=Array.from(new Set(state.events.map(function(e){ return e.connection_type||'unknown'; }))).sort(); select.innerHTML='<option value="">All Plugins</option>'+values.map(function(v){ return '<option value="'+E(v)+'">'+E(v.toUpperCase())+'</option>'; }).join(''); select.value=values.indexOf(current)!==-1?current:''; }
function syncCountryFilter(){ var select=$('#eventCountryFilter'); var current=select.value; var values=Array.from(new Set(state.events.map(function(e){ return String(e.country_code||'').toUpperCase(); }).filter(function(v){ return v && v!=='ZZ'; }))).sort(); select.innerHTML='<option value="">All Countries</option>'+values.map(function(v){ return '<option value="'+E(v)+'">'+E(v)+'</option>'; }).join(''); select.value=values.indexOf(current)!==-1?current:''; }
async function refresh(){
  var results = await Promise.all([api('/api/health'),api('/api/stats'),api('/api/events?limit=120'),api('/api/bans'),api('/api/firewall-bans?limit=1000'),api('/api/top-portscanned-ports?limit=12'),api('/api/blocklist')]);
  if(results.some(function(item){ return item===null; })){ return; }
  state.health=results[0]||null; state.stats=results[1]||null; state.events=results[2]&&results[2].events?results[2].events:[]; state.bans=results[3]&&results[3].bans?results[3].bans:[]; state.firewall=results[4]&&results[4].items?results[4].items:[]; state.topPorts=results[5]&&results[5].ports?results[5].ports:[]; state.blocklist=results[6]||null;
  syncPluginFilter(); syncCountryFilter(); renderSummary(); renderEvents(); renderBans(); renderFirewall(); renderTopPortscannedPorts(); renderBlocklistAdmin(); renderAdvice();
}
async function performAction(path, body, successTitle, successMessage){ var payload = await api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{})}); if(!payload){ return false; } setStatus('ok', successTitle, successMessage(payload)); await refresh(); return true; }
async function logout(message){ clearInterval(timer); clearTimeout(idleTimer); await fetch('/api/logout', {method:'POST'}).catch(function(){}); if(message){ sessionStorage.setItem('wardenips_logout_message', message); } window.location.href='/login?next=/admin'; }
function bindActivity(){ ['mousemove','mousedown','keydown','scroll','touchstart','click'].forEach(function(name){ document.addEventListener(name, function(){ debounce('activity', handleUserActivity, 150); }, {passive:true}); }); resetIdleTimer(); }
function bind(){
  ['globalSearch','eventPluginFilter','eventThreatFilter','eventCountryFilter','banSort','ipFamilyFilter','manualIp','manualWhitelist','manualBanIp','manualBanDuration','manualBanReason','cfgPortscanIgnoredPortsEntry'].forEach(function(id){ $('#'+id).addEventListener('input', function(){ debounce(id, function(){ renderEvents(); renderBans(); renderFirewall(); }, 220); }); $('#'+id).addEventListener('change', function(){ debounce(id+'-change', function(){ renderEvents(); renderBans(); renderFirewall(); }, 120); }); });
  $('#themeToggle').addEventListener('click', function(){ applyTheme(state.theme==='dark' ? 'light' : 'dark'); });
  $('#dismissUpdateNoticeBtn').addEventListener('click', function(){ var info=state.updateInfo; var key=getDismissKey(info); if(key){ try{ localStorage.setItem(key,'1'); }catch(error){} } $('#updateNotice').hidden=true; });
  $('#openConfigBtn').addEventListener('click', function(){ handleUserActivity(); openConfigModal(); });
  $('#configSectionSearch').addEventListener('input', function(){ debounce('config-search', filterConfigSections, 120); });
  $('#closeConfigBtn').addEventListener('click', function(){ closeConfigModal(); });
  $('#configModal').addEventListener('click', function(ev){ if(ev.target===this){ closeConfigModal(); } });
  document.addEventListener('keydown', function(ev){ if(ev.key==='Escape' && !$('#configModal').hidden){ closeConfigModal(); } });
  $('#refreshNow').addEventListener('click', function(){ handleUserActivity(); refresh(); });
  $('#logoutBtn').addEventListener('click', function(){ logout('Logged out successfully.'); });
  $('#refreshRate').addEventListener('change', function(){ if(timer){ clearInterval(timer); } timer = setInterval(refresh, parseInt(this.value,10)||1000); });
  $('#queryRunBtn').addEventListener('click', async function(){ handleUserActivity(); await runRecordQuery(); });
  $('#queryValue').addEventListener('keydown', async function(ev){ if(ev.key==='Enter'){ ev.preventDefault(); handleUserActivity(); await runRecordQuery(); } });
  $('#saveAdminTotpBtn').addEventListener('click', async function(){
    handleUserActivity();
    var enabled=$('#adminTotpEnabled').checked;
    var payload=await api('/api/admin/auth-settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({totp_enabled:enabled})});
    if(!payload){ return; }
    state.authSettings={ username:String(payload.username||''), totp_enabled:!!payload.totp_enabled };
    renderAuthSettings();
    setStatus('ok','Admin auth updated', payload.message || (enabled ? 'TOTP is now required at login.' : 'TOTP requirement is now disabled.'));
  });
  $('#banManualBtn').addEventListener('click', async function(){ var ip=$('#manualBanIp').value.trim(); if(!ip){ setStatus('err','Missing input','Enter an IP address before running the ban action.'); return; } var duration=parseInt($('#manualBanDuration').value,10); if(!Number.isFinite(duration)||duration<0){ duration=parseInt(getConfigValue('firewall.ipset.default_ban_duration',0),10); } if(!Number.isFinite(duration)||duration<0){ duration=0; } var reason=$('#manualBanReason').value.trim(); handleUserActivity(); await performAction('/api/admin/ban-ip', {ip:ip, duration:duration, reason:reason}, 'Firewall IP banned', function(payload){ return payload.message || ('Added '+ip+' to firewall bans.'); }); $('#manualBanIp').value=''; });
  $('#unbanManualBtn').addEventListener('click', async function(){ var ip=$('#manualIp').value.trim(); if(!ip){ setStatus('err','Missing input','Enter an IP address before running the unban action.'); return; } handleUserActivity(); await performAction('/api/admin/unban-ip', {ip:ip}, 'Firewall IP removed', function(payload){ return payload.message || ('Removed '+ip+' from the firewall.'); }); $('#manualIp').value=''; });
  $('#addWhitelistBtn').addEventListener('click', async function(){ var value=$('#manualWhitelist').value.trim(); if(!value){ setStatus('err','Missing input','Enter an IP or CIDR before adding to whitelist.'); return; } handleUserActivity(); await performAction('/api/admin/whitelist/add', {value:value}, 'Whitelist updated', function(payload){ return payload.message || ('Added '+value+' to whitelist.'); }); });
  $('#removeWhitelistBtn').addEventListener('click', async function(){ var value=$('#manualWhitelist').value.trim(); if(!value){ setStatus('err','Missing input','Enter an IP or CIDR before removing from whitelist.'); return; } handleUserActivity(); await performAction('/api/admin/whitelist/remove', {value:value}, 'Whitelist updated', function(payload){ return payload.message || ('Removed '+value+' from whitelist.'); }); $('#manualWhitelist').value=''; });
  $('#deactivateAllBansBtn').addEventListener('click', async function(){ if(!confirm('Deactivate every active database ban record?')){ return; } handleUserActivity(); await performAction('/api/admin/deactivate-all-bans', {}, 'Database bans updated', function(payload){ return 'Deactivated '+N(payload.updated||0)+' active ban records.'; }); });
  $('#enforceSimBansBtn').addEventListener('click', async function(){ if(!confirm('Apply current simulated ban records to the real firewall now?')){ return; } handleUserActivity(); await performAction('/api/admin/enforce-simulated-bans', {}, 'Simulated bans applied', function(payload){ return 'Applied '+N(payload.applied||0)+' ban(s) to firewall. Failed: '+N(payload.failed||0)+', skipped: '+N(payload.skipped||0)+'.'; }); });
  $('#reconcileBansBtn').addEventListener('click', async function(){ if(!confirm('Push active DB bans to firewall now? This is one-way (DB -> Firewall).')){ return; } handleUserActivity(); await performAction('/api/admin/reconcile-bans', {}, 'Firewall sync completed', function(payload){ return 'DB total: '+N(payload.db_total_bans||0)+' · DB active: '+N(payload.db_active_considered||0)+' · Requested: '+N(payload.requested||0)+' · Applied: '+N(payload.reapplied||0)+' · Failed: '+N(payload.apply_failed||0)+' · Skipped: '+N(payload.apply_skipped||0)+' · Expired deactivated: '+N(payload.expired_deactivated||0)+' · Firewall extras untouched: '+N(payload.firewall_extra_untouched||0)+'.'; }); });
  $('#flushFirewallBtn').addEventListener('click', async function(){ if(!confirm('Flush every active firewall IP and deactivate matching DB bans?')){ return; } handleUserActivity(); await performAction('/api/admin/flush-firewall', {}, 'Firewall flushed', function(payload){ return 'Removed active firewall entries and deactivated '+N(payload.deactivated_records||0)+' database records.'; }); });
  $('#clearEventsBtn').addEventListener('click', async function(){ if(!confirm('Delete all stored event history? This cannot be undone.')){ return; } handleUserActivity(); await performAction('/api/admin/clear-events', {}, 'Event history cleared', function(payload){ return 'Deleted '+N(payload.deleted||0)+' event records.'; }); });
  $('#clearBanHistoryBtn').addEventListener('click', async function(){ if(!confirm('Delete all ban history records? This cannot be undone.')){ return; } handleUserActivity(); await performAction('/api/admin/clear-ban-history', {}, 'Ban history cleared', function(payload){ return 'Deleted '+N(payload.deleted||0)+' ban history records.'; }); });
  $('#testAllNotificationsBtn').addEventListener('click', async function(){ handleUserActivity(); await performAction('/api/admin/test-notification', {channel:'all'}, 'Notification test sent', function(payload){ return payload.message || 'All configured notification channels were tested.'; }); });
  $('#testTelegramBtn').addEventListener('click', async function(){ handleUserActivity(); await performAction('/api/admin/test-notification', {channel:'telegram'}, 'Telegram test sent', function(payload){ return payload.message || 'Telegram test message was dispatched.'; }); });
  $('#testDiscordBtn').addEventListener('click', async function(){ handleUserActivity(); await performAction('/api/admin/test-notification', {channel:'discord'}, 'Discord test sent', function(payload){ return payload.message || 'Discord test message was dispatched.'; }); });
  ['cfgSuccessEnabled','cfgSuccessReset','cfgPublicDashboard'].forEach(function(id){ $('#'+id).addEventListener('change', async function(){ handleUserActivity(); await saveQuickConfig(); }); });
  $('#reloadConfigBtn').addEventListener('click', async function(){ handleUserActivity(); await loadConfig(); setStatus('ok','Configuration reloaded','Loaded the current config.yaml from disk.'); });
  $('#saveFormConfigBtn').addEventListener('click', async function(){ handleUserActivity(); await saveConfigForm(); });
  $('#saveConfigBtn').addEventListener('click', async function(){ handleUserActivity(); await saveConfigYaml(); });
  $('#toggleAdvancedYamlBtn').addEventListener('click', function(){ state.advancedYamlOpen=!state.advancedYamlOpen; syncAdvancedYaml(); });
  $('#cfgPortscanIgnoredPortsEntry').addEventListener('keydown', function(ev){ if(ev.key==='Enter' || ev.key===','){ ev.preventDefault(); var raw=this.value; if(addPortscanIgnoredPortsFromInput(raw)){ this.value=''; } } });
  $('#cfgPortscanIgnoredPortsEntry').addEventListener('blur', function(){ var raw=this.value; if(addPortscanIgnoredPortsFromInput(raw)){ this.value=''; } });
  $('#cfgPortscanIgnoredPortsChips').addEventListener('click', function(ev){ var button=ev.target.closest('.chip-remove'); if(!button){ return; } var chip=ev.target.closest('.chip'); if(!chip){ return; } var value=parseInt(chip.getAttribute('data-port')||'',10); if(!Number.isFinite(value)){ return; } state.portscanIgnoredPorts=(state.portscanIgnoredPorts||[]).filter(function(p){ return p!==value; }); syncPortscanIgnoredPortsField(); renderPortscanIgnoredPortChips(); });
  $('#banRows').addEventListener('click', async function(ev){ var button = ev.target.closest('.ban-action'); if(!button){ return; } var sourceIp = button.getAttribute('data-ip'); if(!sourceIp || !confirm('Deactivate this database ban record?')){ return; } handleUserActivity(); await performAction('/api/admin/deactivate-ban', {source_ip:sourceIp}, 'Ban record updated', function(payload){ return 'Deactivated '+N(payload.updated||0)+' matching records.'; }); });
  $('#firewallRows').addEventListener('click', async function(ev){ var button = ev.target.closest('.fw-action'); if(!button){ return; } var ip = button.getAttribute('data-ip'); if(!ip || !confirm('Remove this IP from the firewall set?')){ return; } handleUserActivity(); await performAction('/api/admin/unban-ip', {ip:ip}, 'Firewall IP removed', function(payload){ return payload.message || ('Removed '+ip+' from the firewall.'); }); });
}
var flashMessage = sessionStorage.getItem('wardenips_logout_message'); if(flashMessage){ setStatus('ok','Session notice', flashMessage); sessionStorage.removeItem('wardenips_logout_message'); }
initTheme(); bind(); bindActivity(); loadConfig(); loadAuthSettings(); loadUpdateStatus(); refresh(); timer=setInterval(refresh, parseInt($('#refreshRate').value,10)||1000);
})();
</script>
</body>
</html>"""
