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

try:
  import pymysql  # type: ignore
except Exception:
  pymysql = None

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
    abuse_reporter=None,
  ) -> None:
    self._config = config
    self._db = db
    self._firewall = firewall
    self._whitelist = whitelist
    self._start_time = start_time
    self._notifier = notifier
    self._blocklist = blocklist
    self._abuse_reporter = abuse_reporter
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
    if not dash or not isinstance(dash, dict):
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

  @staticmethod
  def _extract_event_port(event: dict, details_obj: Optional[dict] = None) -> Optional[str]:
    details = details_obj if isinstance(details_obj, dict) else {}
    if not details:
      details_value = event.get("details")
      if isinstance(details_value, dict):
        details = details_value
      elif isinstance(details_value, str) and details_value:
        try:
          details = json.loads(details_value)
        except Exception:
          details = {}

    for key in ("port", "target_port", "destination_port", "dest_port", "dst_port", "remote_port"):
      value = details.get(key) if isinstance(details, dict) else None
      if value is None:
        continue
      text = str(value).strip()
      if text:
        return text

    player_name = str(event.get("player_name") or "")
    if player_name.startswith("port_"):
      scanned = player_name.replace("port_", "", 1).strip()
      if scanned:
        return scanned

    return None

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
    self._app.router.add_get("/admin/minecraft", self._handle_minecraft_admin_page)
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
    self._app.router.add_get("/api/minecraft/summary", self._handle_minecraft_summary)
    self._app.router.add_get("/api/minecraft/events", self._handle_minecraft_events)
    self._app.router.add_get("/api/minecraft/bursts", self._handle_minecraft_bursts)
    self._app.router.add_get("/api/minecraft/duplicates/email", self._handle_minecraft_duplicate_emails)
    self._app.router.add_get("/api/minecraft/entity-intel", self._handle_minecraft_entity_intel)
    self._app.router.add_get("/api/blocklist", self._handle_blocklist)
    self._app.router.add_post("/api/admin/ban-ip", self._handle_admin_ban_ip)
    self._app.router.add_post("/api/admin/report-and-ban", self._handle_admin_report_and_ban)
    self._app.router.add_post("/api/admin/bulk-ip-action", self._handle_admin_bulk_ip_action)
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
    limit = min(max(int(request.query.get("limit", "50")), 1), 2000)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT id, timestamp, source_ip, player_name,
               connection_type, asn_number, asn_org,
               is_suspicious_asn, risk_score,
               threat_level, details,
               EXISTS(
                 SELECT 1
                 FROM ban_history bh
                 WHERE bh.source_ip = connection_events.source_ip
                   AND bh.is_active = 1
                   AND (
                     bh.expires_at IS NULL
                     OR bh.expires_at = ''
                     OR COALESCE(strftime('%s', bh.expires_at), 0) > strftime('%s', 'now')
                   )
               ) AS is_banned_current,
               (
                 SELECT MIN(COALESCE(strftime('%s', bh_first.banned_at), 0))
                 FROM ban_history bh_first
                 WHERE bh_first.source_ip = connection_events.source_ip
               ) AS first_ban_unix
          FROM connection_events
          ORDER BY id DESC
          LIMIT ?
          """,
          (limit,),
        ) as cursor:
          rows = await cursor.fetchall()
          columns = [d[0] for d in cursor.description]
          events = [dict(zip(columns, row)) for row in rows]

      firewall_banned_ips: set[str] = set()
      try:
        firewall_items = await self._firewall.list_banned_ips(limit=20000)
        for item in firewall_items:
          if isinstance(item, dict):
            candidate = str(item.get("ip", "")).strip()
            if candidate:
              firewall_banned_ips.add(candidate)
      except Exception:
        firewall_banned_ips = set()

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
        event["is_banned_current"] = bool(event.get("is_banned_current"))
        event["is_post_ban"] = False
        event["is_ban_trigger_event"] = False
        event["country_code"] = self._resolve_country_code(
          details_obj,
          event.get("source_ip"),
        )
        event["threat_label"] = self._get_event_threat_label(event)
        event["timestamp_unix"] = self._parse_timestamp_unix(event.get("timestamp"))
        event["operator_advice"] = self._build_operator_advice(event)
        event["event_port"] = self._extract_event_port(event, details_obj)
        source_ip = str(event.get("source_ip") or "").strip()
        event["is_firewall_blocked"] = bool(source_ip and source_ip in firewall_banned_ips)

      events_by_ip: dict[str, list[int]] = {}
      for index, event in enumerate(events):
        source_ip = str(event.get("source_ip") or "").strip()
        if source_ip:
          events_by_ip.setdefault(source_ip, []).append(index)

      for source_ip, indices in events_by_ip.items():
        _ = source_ip
        first_ban_unix = 0
        for idx in indices:
          raw_first_ban = events[idx].get("first_ban_unix")
          try:
            candidate = int(raw_first_ban or 0)
          except Exception:
            candidate = 0
          if candidate > 0 and (first_ban_unix == 0 or candidate < first_ban_unix):
            first_ban_unix = candidate

        if first_ban_unix <= 0:
          continue

        post_ban_indices: list[int] = []
        for idx in indices:
          event_unix = events[idx].get("timestamp_unix")
          if event_unix is None:
            continue
          if int(event_unix) >= first_ban_unix:
            post_ban_indices.append(idx)

        if not post_ban_indices:
          continue

        trigger_idx = min(
          post_ban_indices,
          key=lambda idx: int(events[idx].get("timestamp_unix") or 0),
        )
        for idx in post_ban_indices:
          events[idx]["is_post_ban"] = True
        events[trigger_idx]["is_ban_trigger_event"] = True

      for event in events:
        is_firewall_blocked = bool(event.get("is_firewall_blocked"))
        is_ban_trigger_event = bool(event.get("is_ban_trigger_event"))
        is_post_ban = bool(event.get("is_post_ban"))
        event["is_banned"] = is_firewall_blocked or is_ban_trigger_event or is_post_ban
        if is_ban_trigger_event:
          event["ban_state"] = "ban_triggered"
        elif is_post_ban:
          event["ban_state"] = "post_ban"
        elif is_firewall_blocked:
          event["ban_state"] = "firewall_blocked"
        else:
          event["ban_state"] = "pre_ban"
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
    hours = max(int(request.query.get("hours", "0")), 0)
    include_honeypot = str(request.query.get("include_honeypot", "1")).strip().lower() not in {"0", "false", "no", "off"}
    try:
      trap_ports_raw = self._config.get("plugins.portscan.trap_ports", [])
      trap_ports = set()
      for value in trap_ports_raw:
        try:
          trap_ports.add(str(int(value)))
        except Exception:
          continue

      timestamp_expr = "COALESCE(strftime('%s', timestamp), CASE WHEN timestamp GLOB '[0-9]*' THEN CAST(timestamp AS INTEGER) ELSE 0 END)"
      time_clause = f"AND {timestamp_expr} >= strftime('%s', 'now', ? || ' hours')" if hours > 0 else ""
      time_params: list = [f"-{hours}"] if hours > 0 else []
      async with self._db._lock:
        async with self._db._db.execute(
          f"""
          SELECT
               CASE
                 WHEN player_name LIKE 'port_%' THEN substr(player_name, 6)
                 ELSE ''
               END AS scanned_port,
               COUNT(*) AS scan_count,
               MAX(timestamp) AS last_seen
          FROM connection_events
          WHERE connection_type = 'portscan'
          {time_clause}
          GROUP BY scanned_port
          HAVING scanned_port <> ''
          ORDER BY scan_count DESC, last_seen DESC
          LIMIT ?
          """,
          tuple(time_params + [limit]),
        ) as cursor:
          rows = await cursor.fetchall()
          ports = []
          for row in rows:
            port_value = str(row[0])
            is_honeypot = port_value in trap_ports
            if not include_honeypot and is_honeypot:
              continue
            ports.append(
              {
                "port": port_value,
                "scan_count": int(row[1]),
                "last_seen": row[2],
                "is_honeypot": is_honeypot,
              }
            )
      return web.json_response({"ports": ports, "count": len(ports), "hours": hours})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_events_timeline(self, request: web.Request) -> web.Response:
    if not self._check_public_dashboard_access(request):
      return self._json_auth_error()
    hours = min(int(request.query.get("hours", "24")), 168)
    try:
      timestamp_expr = "COALESCE(strftime('%s', timestamp), CASE WHEN timestamp GLOB '[0-9]*' THEN CAST(timestamp AS INTEGER) ELSE 0 END)"
      async with self._db._lock:
        async with self._db._db.execute(
          f"""
          SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
               COUNT(*) as count
          FROM connection_events
          WHERE {timestamp_expr} >= strftime('%s', 'now', ? || ' hours')
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
    hours = max(int(request.query.get("hours", "0")), 0)
    try:
      timestamp_expr = "COALESCE(strftime('%s', timestamp), CASE WHEN timestamp GLOB '[0-9]*' THEN CAST(timestamp AS INTEGER) ELSE 0 END)"
      time_clause = f"AND {timestamp_expr} >= strftime('%s', 'now', ? || ' hours')" if hours > 0 else ""
      time_params: list = [f"-{hours}"] if hours > 0 else []
      async with self._db._lock:
        async with self._db._db.execute(
          f"""
          SELECT COALESCE(asn_org, 'Unknown') as org,
               COUNT(*) as count,
               SUM(CASE WHEN is_suspicious_asn=1 THEN 1 ELSE 0 END) as suspicious_count
          FROM connection_events
          WHERE asn_org IS NOT NULL
          {time_clause}
          GROUP BY asn_org
          ORDER BY count DESC
          LIMIT 20
          """,
          tuple(time_params),
        ) as cursor:
          rows = await cursor.fetchall()
          orgs = [{"org": r[0], "count": r[1], "suspicious": r[2]} for r in rows]

      # Country values are optional and inferred from event details JSON.
      async with self._db._lock:
        async with self._db._db.execute(
          f"""
          SELECT source_ip, details
          FROM connection_events
          WHERE 1=1
          {time_clause}
          ORDER BY id DESC
          LIMIT 5000
          """,
          tuple(time_params),
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
    # Apply first-install defaults
    try:
      private_nets = payload.get("whitelist_private_networks") or []
      if private_nets and isinstance(private_nets, list):
        existing_ips = list(self._config.get("whitelist.ips", []) or [])
        existing_cidrs = list(self._config.get("whitelist.cidr_ranges", []) or [])
        for raw in private_nets:
          raw = str(raw).strip()
          if not raw:
            continue
          try:
            if "/" in raw:
              n = str(ipaddress.ip_network(raw, strict=False))
              if n not in existing_cidrs:
                existing_cidrs.append(n)
            else:
              ip_val = str(ipaddress.ip_address(raw))
              if ip_val not in existing_ips:
                existing_ips.append(ip_val)
          except ValueError:
            pass
        await self._config.patch_values({"whitelist.ips": existing_ips, "whitelist.cidr_ranges": existing_cidrs})
        if self._whitelist:
          await self._whitelist.reload(self._config)
      # Ensure monitor mode is active for fresh installs
      await self._config.patch_values({"firewall.simulation_mode": True})
      self._firewall.apply_simulation_config(True)
    except Exception:
      pass
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

  async def _handle_admin_report_and_ban(self, request: web.Request) -> web.Response:
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

    reason = str(payload.get("reason", "")).strip() or "[ADMIN] Report+Ban from dashboard"
    risk_score_value = payload.get("risk_score", 100)
    try:
      risk_score = min(max(int(risk_score_value), 0), 100)
    except Exception:
      risk_score = 100

    raw_categories = payload.get("categories", [14])
    categories: list[int] = []
    if isinstance(raw_categories, list):
      for item in raw_categories:
        try:
          value = int(item)
        except Exception:
          continue
        if 1 <= value <= 24 and value not in categories:
          categories.append(value)
    if not categories:
      categories = [14]

    ban_applied = await self._firewall.ban_ip(ip_value, duration=duration, reason=reason)
    if ban_applied:
      await self._db.log_ban(ip_value, reason, risk_score, duration)
      await self._notifier.notify_ban(
        ip=ip_value,
        reason=reason,
        risk=risk_score,
        duration=duration,
        plugin="admin",
      )

    reported = False
    if self._abuse_reporter:
      try:
        reported = await self._abuse_reporter.report_ip(
          ip=ip_value,
          categories=categories,
          comment=f"{reason} | Trigger: admin report+ban",
        )
      except Exception:
        reported = False

    await self._log_audit(
      request,
      "admin.report_and_ban",
      actor_username=actor,
      details={
        "ip": ip_value,
        "duration": duration,
        "risk_score": risk_score,
        "categories": categories,
        "ban_applied": ban_applied,
        "reported": reported,
      },
    )

    if not ban_applied and not reported:
      return web.json_response(
        {
          "ok": False,
          "message": f"No action taken for {ip_value} (already banned, whitelisted, or reporter unavailable).",
          "ban_applied": False,
          "reported": False,
        },
        status=409,
      )

    result_parts: list[str] = []
    result_parts.append("ban applied" if ban_applied else "ban skipped")
    result_parts.append("reported" if reported else "report skipped")
    return web.json_response(
      {
        "ok": True,
        "message": f"{ip_value}: " + ", ".join(result_parts) + ".",
        "ban_applied": ban_applied,
        "reported": reported,
      }
    )

  async def _handle_admin_bulk_ip_action(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    actor = self._get_session_actor(request)
    try:
      payload = await request.json()
    except Exception:
      payload = {}

    action = str(payload.get("action", "ban") or "ban").strip().lower()
    if action not in {"ban", "report", "report_and_ban"}:
      return web.json_response(
        {
          "error": "invalid_action",
          "message": "action must be one of: ban, report, report_and_ban.",
        },
        status=400,
      )

    lines_text = str(payload.get("lines", "") or "")
    if not lines_text.strip():
      return web.json_response(
        {"error": "invalid_lines", "message": "Provide at least one IP in lines."},
        status=400,
      )

    try:
      duration = max(int(payload.get("duration", self._config.get("firewall.ipset.default_ban_duration", 0))), 0)
    except Exception:
      duration = max(int(self._config.get("firewall.ipset.default_ban_duration", 0)), 0)

    reason_base = str(payload.get("reason", "") or "").strip()
    if not reason_base:
      reason_base = "[ADMIN] Bulk action from dashboard"

    risk_score_value = payload.get("risk_score", 100)
    try:
      risk_score = min(max(int(risk_score_value), 0), 100)
    except Exception:
      risk_score = 100

    raw_categories = payload.get("categories", [14])
    categories: list[int] = []
    if isinstance(raw_categories, list):
      for item in raw_categories:
        try:
          value = int(item)
        except Exception:
          continue
        if 1 <= value <= 24 and value not in categories:
          categories.append(value)
    if not categories:
      categories = [14]

    raw_respect = payload.get("respect_report_rate_limit", True)
    if isinstance(raw_respect, bool):
      respect_report_rate_limit = raw_respect
    elif isinstance(raw_respect, (int, float)):
      respect_report_rate_limit = bool(int(raw_respect))
    elif isinstance(raw_respect, str):
      respect_report_rate_limit = raw_respect.strip().lower() in {"1", "true", "yes", "on"}
    else:
      respect_report_rate_limit = True

    try:
      report_interval_ms = int(payload.get("report_interval_ms", 2200))
    except Exception:
      report_interval_ms = 2200
    report_interval_ms = min(max(report_interval_ms, 500), 15000)
    report_interval_seconds = report_interval_ms / 1000.0
    last_report_at = 0.0

    entries: list[tuple[str, str]] = []
    for raw_line in lines_text.splitlines():
      line = str(raw_line or "").strip()
      if not line or line.startswith("#"):
        continue
      if "|" in line:
        ip_part, note_part = line.split("|", 1)
        ip_value = ip_part.strip()
        per_line_note = note_part.strip()
      else:
        ip_value = line
        per_line_note = ""
      if not ip_value:
        continue
      entries.append((ip_value, per_line_note))

    if not entries:
      return web.json_response(
        {"error": "invalid_lines", "message": "No valid IP lines were found."},
        status=400,
      )

    results: list[dict[str, object]] = []
    for ip_value, per_line_note in entries:
      item = {
        "ip": ip_value,
        "ban_applied": False,
        "reported": False,
        "ok": False,
        "message": "",
      }
      try:
        ipaddress.ip_address(ip_value)
      except Exception:
        item["message"] = "Invalid IP format."
        results.append(item)
        continue

      final_reason = reason_base
      if per_line_note:
        final_reason = f"{reason_base} | {per_line_note}"

      ban_applied = False
      if action in {"ban", "report_and_ban"}:
        ban_applied = await self._firewall.ban_ip(ip_value, duration=duration, reason=final_reason)
        if ban_applied:
          await self._db.log_ban(ip_value, final_reason, risk_score, duration)
          await self._notifier.notify_ban(
            ip=ip_value,
            reason=final_reason,
            risk=risk_score,
            duration=duration,
            plugin="admin",
          )

      reported = False
      if action in {"report", "report_and_ban"} and self._abuse_reporter:
        if respect_report_rate_limit and last_report_at > 0:
          elapsed = time.monotonic() - last_report_at
          wait_seconds = report_interval_seconds - elapsed
          if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)
        try:
          reported = await self._abuse_reporter.report_ip(
            ip=ip_value,
            categories=categories,
            comment=f"{final_reason} | Trigger: admin bulk {action}",
          )
          last_report_at = time.monotonic()
        except Exception:
          reported = False
          last_report_at = time.monotonic()

        # One paced retry helps when bursts hit provider-side throttling.
        if not reported and respect_report_rate_limit:
          await asyncio.sleep(report_interval_seconds)
          try:
            reported = await self._abuse_reporter.report_ip(
              ip=ip_value,
              categories=categories,
              comment=f"{final_reason} | Trigger: admin bulk {action} (retry)",
            )
            last_report_at = time.monotonic()
          except Exception:
            reported = False
            last_report_at = time.monotonic()

      item["ban_applied"] = ban_applied
      item["reported"] = reported
      if action == "ban":
        item["ok"] = bool(ban_applied)
        item["message"] = "ban applied" if ban_applied else "ban skipped"
      elif action == "report":
        item["ok"] = bool(reported)
        item["message"] = "reported" if reported else "report skipped (rate-limit/provider/no-reporter)"
      else:
        item["ok"] = bool(ban_applied or reported)
        parts = ["ban applied" if ban_applied else "ban skipped", "reported" if reported else "report skipped (rate-limit/provider/no-reporter)"]
        item["message"] = ", ".join(parts)
      results.append(item)

    success_count = sum(1 for item in results if item.get("ok"))
    fail_count = len(results) - success_count
    reported_count = sum(1 for item in results if item.get("reported"))
    ban_count = sum(1 for item in results if item.get("ban_applied"))

    await self._log_audit(
      request,
      "admin.bulk_ip_action",
      actor_username=actor,
      details={
        "action": action,
        "total": len(results),
        "success": success_count,
        "failed": fail_count,
        "reported": reported_count,
        "ban_applied": ban_count,
        "categories": categories,
      },
    )

    return web.json_response(
      {
        "ok": True,
        "action": action,
        "total": len(results),
        "success": success_count,
        "failed": fail_count,
        "reported": reported_count,
        "ban_applied": ban_count,
        "categories": categories,
        "respect_report_rate_limit": respect_report_rate_limit,
        "report_interval_ms": report_interval_ms,
        "message": f"Bulk action completed: {success_count}/{len(results)} successful.",
        "results": results,
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
            "event_port": self._extract_event_port({"player_name": player_name}, details_obj),
            "country_code": self._resolve_country_code(details_obj, source_ip),
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

  async def _handle_minecraft_admin_page(self, request: web.Request) -> web.Response:
    auth_redirect = self._require_dashboard_auth(request)
    if auth_redirect is not None:
      return auth_redirect
    self._touch_session(request)
    html = self._render_ui_template(MINECRAFT_ADMIN_HTML)
    return web.Response(text=html, content_type="text/html")

  async def _handle_minecraft_summary(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    hours = min(max(int(request.query.get("hours", "24")), 1), 720)
    try:
      timestamp_expr = "COALESCE(strftime('%s', timestamp), CASE WHEN timestamp GLOB '[0-9]*' THEN CAST(timestamp AS INTEGER) ELSE 0 END)"
      async with self._db._lock:
        async with self._db._db.execute(
          f"""
          SELECT
            COUNT(*) AS event_count,
            COUNT(DISTINCT source_ip) AS unique_ips,
            COUNT(DISTINCT COALESCE(player_name, '')) AS unique_players,
            SUM(CASE WHEN details LIKE '%\"event_type\": \"velocity_connected\"%' OR details LIKE '%\"event_type\": \"login\"%' THEN 1 ELSE 0 END) AS login_like_events,
            SUM(CASE WHEN details LIKE '%\"event_type\": \"velocity_disconnect\"%' OR details LIKE '%\"event_type\": \"ip_disconnect\"%' THEN 1 ELSE 0 END) AS disconnect_events,
            MAX(risk_score) AS peak_risk
          FROM connection_events
          WHERE connection_type = 'minecraft'
            AND {timestamp_expr} >= strftime('%s', 'now', ? || ' hours')
          """,
          (f"-{hours}",),
        ) as cursor:
          row = await cursor.fetchone()

        async with self._db._db.execute(
          """
          SELECT COUNT(*)
          FROM minecraft_burst_alerts
          WHERE COALESCE(strftime('%s', timestamp), 0) >= strftime('%s', 'now', ? || ' hours')
          """,
          (f"-{hours}",),
        ) as burst_cursor:
          burst_row = await burst_cursor.fetchone()

      payload = {
        "hours": hours,
        "event_count": int((row[0] or 0) if row else 0),
        "unique_ips": int((row[1] or 0) if row else 0),
        "unique_players": int((row[2] or 0) if row else 0),
        "login_like_events": int((row[3] or 0) if row else 0),
        "disconnect_events": int((row[4] or 0) if row else 0),
        "peak_risk": int((row[5] or 0) if row else 0),
        "burst_alerts": int((burst_row[0] or 0) if burst_row else 0),
        "observe_only_enabled": bool(self._config.get("plugins.minecraft.observe_only.enabled", False)),
        "enforcement_enabled": bool(self._config.get("plugins.minecraft.observe_only.enforcement_enabled", False)),
      }
      return web.json_response(payload)
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_minecraft_events(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    limit = min(max(int(request.query.get("limit", "100")), 1), 1000)
    offset = max(int(request.query.get("offset", "0")), 0)
    username = str(request.query.get("username", "")).strip()
    source_ip = str(request.query.get("ip", "")).strip()
    event_type = str(request.query.get("event_type", "")).strip().lower()
    try:
      query = """
        SELECT id, timestamp, source_ip, player_name, connection_type,
               asn_number, asn_org, is_suspicious_asn, risk_score, threat_level, details
        FROM connection_events
        WHERE connection_type = 'minecraft'
      """
      params: list[object] = []
      if username:
        query += " AND player_name = ?"
        params.append(username)
      if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
      if event_type:
        query += " AND LOWER(COALESCE(details, '')) LIKE ?"
        params.append(f'%\"event_type\": \"{event_type}%')
      query += " ORDER BY id DESC LIMIT ? OFFSET ?"
      params.extend([limit, offset])

      async with self._db._lock:
        async with self._db._db.execute(query, tuple(params)) as cursor:
          rows = await cursor.fetchall()
          columns = [d[0] for d in cursor.description]
          events = [dict(zip(columns, row)) for row in rows]

      for event in events:
        details_obj = {}
        details_raw = event.get("details")
        if isinstance(details_raw, str) and details_raw:
          try:
            details_obj = json.loads(details_raw)
          except Exception:
            details_obj = {}
        event["event_type"] = str(details_obj.get("event_type") or "")
        event["country_code"] = self._resolve_country_code(details_obj, event.get("source_ip"))

      return web.json_response({"events": events, "count": len(events), "limit": limit, "offset": offset})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_minecraft_bursts(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    limit = min(max(int(request.query.get("limit", "50")), 1), 500)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT id, timestamp, source_ip, event_count, window_seconds, unique_ip_count, plugin_name
          FROM minecraft_burst_alerts
          ORDER BY id DESC
          LIMIT ?
          """,
          (limit,),
        ) as cursor:
          rows = await cursor.fetchall()
          columns = [d[0] for d in cursor.description]
          alerts = [dict(zip(columns, row)) for row in rows]
      return web.json_response({"alerts": alerts, "count": len(alerts)})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_minecraft_duplicate_emails(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)
    limit = min(max(int(request.query.get("limit", "50")), 1), 500)
    try:
      async with self._db._lock:
        async with self._db._db.execute(
          """
          SELECT source_ip, player_name, timestamp, details
          FROM connection_events
          WHERE connection_type = 'minecraft'
            AND COALESCE(details, '') LIKE '%"duplicate_email_count":%'
          ORDER BY id DESC
          LIMIT ?
          """,
          (limit,),
        ) as cursor:
          rows = await cursor.fetchall()

      findings = []
      for source_ip, player_name, timestamp, details_raw in rows:
        details_obj = {}
        if isinstance(details_raw, str) and details_raw:
          try:
            details_obj = json.loads(details_raw)
          except Exception:
            details_obj = {}
        duplicate_count = int(details_obj.get("duplicate_email_count", 0) or 0)
        email_value = str(details_obj.get("email") or "")
        if duplicate_count <= 1:
          continue
        findings.append(
          {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "player_name": player_name,
            "email": email_value,
            "duplicate_email_count": duplicate_count,
          }
        )
      return web.json_response({"findings": findings, "count": len(findings)})
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

  async def _handle_minecraft_entity_intel(self, request: web.Request) -> web.Response:
    if not self._check_auth(request):
      return self._json_auth_error()
    self._touch_session(request)

    entity_type = str(request.query.get("type", "")).strip().lower()
    value = str(request.query.get("value", "")).strip()
    if entity_type not in {"user", "ip", "asn"} or not value:
      return web.json_response({"error": "invalid_query"}, status=400)

    local_events = []
    query = ""
    params: tuple[object, ...] = ()

    if entity_type == "user":
      query = """
        SELECT id, timestamp, source_ip, player_name, asn_number, asn_org, risk_score, threat_level, details
        FROM connection_events
        WHERE connection_type = 'minecraft' AND player_name = ?
        ORDER BY id DESC
        LIMIT 200
      """
      params = (value,)
    elif entity_type == "ip":
      query = """
        SELECT id, timestamp, source_ip, player_name, asn_number, asn_org, risk_score, threat_level, details
        FROM connection_events
        WHERE connection_type = 'minecraft' AND source_ip = ?
        ORDER BY id DESC
        LIMIT 200
      """
      params = (value,)
    else:
      asn_value = value.upper().replace("AS", "").strip()
      if not asn_value.isdigit():
        return web.json_response({"error": "invalid_asn"}, status=400)
      query = """
        SELECT id, timestamp, source_ip, player_name, asn_number, asn_org, risk_score, threat_level, details
        FROM connection_events
        WHERE connection_type = 'minecraft' AND asn_number = ?
        ORDER BY id DESC
        LIMIT 200
      """
      params = (int(asn_value),)

    try:
      async with self._db._lock:
        async with self._db._db.execute(query, params) as cursor:
          rows = await cursor.fetchall()
          cols = [d[0] for d in cursor.description]
          local_events = [dict(zip(cols, row)) for row in rows]
    except Exception as exc:
      return web.json_response({"error": str(exc)}, status=500)

    mysql_payload = None
    mysql_backfilled = False
    if entity_type == "user" and not local_events:
      mysql_payload = await self._fetch_mysql_player_by_username(value)
      if mysql_payload and mysql_payload.get("found"):
        await self._backfill_mysql_player_snapshot(mysql_payload)
        mysql_backfilled = True
        try:
          async with self._db._lock:
            async with self._db._db.execute(query, params) as cursor:
              rows = await cursor.fetchall()
              cols = [d[0] for d in cursor.description]
              local_events = [dict(zip(cols, row)) for row in rows]
        except Exception:
          pass

    unique_ips = sorted({str(e.get("source_ip") or "").strip() for e in local_events if str(e.get("source_ip") or "").strip()})
    unique_users = sorted({str(e.get("player_name") or "").strip() for e in local_events if str(e.get("player_name") or "").strip()})
    risk_peak = max([int(e.get("risk_score") or 0) for e in local_events], default=0)

    return web.json_response(
      {
        "type": entity_type,
        "value": value,
        "count": len(local_events),
        "risk_peak": risk_peak,
        "unique_ips": unique_ips,
        "unique_users": unique_users,
        "events": local_events,
        "mysql": mysql_payload,
        "mysql_backfilled": mysql_backfilled,
      }
    )

  async def _fetch_mysql_player_by_username(self, username: str) -> Optional[dict]:
    conf = self._config.get("plugins.minecraft.player_db", {})
    if not isinstance(conf, dict) or not bool(conf.get("enabled", False)):
      return {"enabled": False, "found": False, "reason": "player_db_disabled"}
    if pymysql is None:
      return {"enabled": True, "found": False, "reason": "pymysql_not_installed"}

    host = str(conf.get("host", "127.0.0.1"))
    port = int(conf.get("port", 3306) or 3306)
    user = str(conf.get("user", ""))
    password = str(conf.get("password", ""))
    database = str(conf.get("database", ""))
    table = str(conf.get("table", "")).strip()
    columns = conf.get("columns", {}) if isinstance(conf.get("columns", {}), dict) else {}
    username_col = str(columns.get("username", "username"))
    ip_col = str(columns.get("ip", "ip"))
    email_col = str(columns.get("email", "email"))
    uuid_col = str(columns.get("uuid", "uuid"))
    creation_ip_col = str(columns.get("creation_ip", "creationIP"))
    creation_date_col = str(columns.get("creation_date", "creationDate"))
    last_login_col = str(columns.get("last_login", "lastlogin"))
    reg_ip_col = str(columns.get("reg_ip", "regip"))
    is_verified_col = str(columns.get("is_verified", "isVerified"))

    if not table or not user or not database:
      return {"enabled": True, "found": False, "reason": "player_db_missing_credentials"}

    def _query() -> dict:
      conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
      )
      try:
        with conn.cursor() as cur:
          sql = (
            f"SELECT `{username_col}` AS username, `{ip_col}` AS ip, `{email_col}` AS email, "
            f"`{uuid_col}` AS uuid, `{creation_ip_col}` AS creation_ip, `{creation_date_col}` AS creation_date, "
            f"`{last_login_col}` AS last_login, `{reg_ip_col}` AS reg_ip, `{is_verified_col}` AS is_verified "
            f"FROM `{table}` WHERE `{username_col}` = %s LIMIT 1"
          )
          cur.execute(sql, (username,))
          row = cur.fetchone()
          if not row:
            return {"enabled": True, "found": False}

          duplicate_count = 0
          email_value = str(row.get("email") or "").strip()
          if email_value:
            dup_sql = f"SELECT COUNT(*) AS c FROM `{table}` WHERE `{email_col}` = %s"
            cur.execute(dup_sql, (email_value,))
            dup = cur.fetchone() or {"c": 0}
            duplicate_count = int(dup.get("c") or 0)

          row["duplicate_email_count"] = duplicate_count
          row["enabled"] = True
          row["found"] = True
          return row
      finally:
        conn.close()

    try:
      return await asyncio.to_thread(_query)
    except Exception as exc:
      return {"enabled": True, "found": False, "reason": f"mysql_error:{exc}"}

  async def _backfill_mysql_player_snapshot(self, payload: dict) -> None:
    try:
      source_ip = str(payload.get("ip") or payload.get("creation_ip") or payload.get("reg_ip") or "0.0.0.0").strip()
      username = str(payload.get("username") or "unknown").strip() or "unknown"
      details = {
        "event_type": "mysql_backfill",
        "parser_source": "mysql_player_db",
        "email": payload.get("email"),
        "uuid": payload.get("uuid"),
        "creation_ip": payload.get("creation_ip"),
        "creation_date": payload.get("creation_date"),
        "last_login": payload.get("last_login"),
        "reg_ip": payload.get("reg_ip"),
        "is_verified": payload.get("is_verified"),
        "duplicate_email_count": int(payload.get("duplicate_email_count") or 0),
      }
      async with self._db._lock:
        await self._db._db.execute(
          """
          INSERT INTO connection_events
            (timestamp, source_ip, player_name, connection_type, asn_number, asn_org, is_suspicious_asn, risk_score, threat_level, details)
          VALUES (?, ?, ?, 'minecraft', NULL, NULL, 0, 0, 'NONE', ?)
          """,
          (
            datetime.utcnow().isoformat(),
            source_ip,
            username,
            json.dumps(details, ensure_ascii=False),
          ),
        )
        await self._db._db.commit()
    except Exception:
      return


# ══════════════════════════════════════════════════════════════════════
#  Full SPA Dashboard — Dark theme, auto-refresh, CSS-only charts
# ══════════════════════════════════════════════════════════════════════

MINECRAFT_ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WardenIPS Minecraft Admin</title>
<style>
*,*::before,*::after{box-sizing:border-box}
:root{--bg:#0f111a;--panel:#171b29;--panel2:#121622;--surface:#0f1420;--b:#2a3345;--txt:#eef2ff;--muted:#9ba7c0;--blue:#5ea1ff;--cyan:#39d0c6;--green:#4fd18f;--orange:#ff995c;--red:#ff6f7e}
body{margin:0;font-family:"Aptos","Segoe UI",sans-serif;color:var(--txt);background:radial-gradient(circle at 10% -20%,#25304f 0%,#0f111a 52%,#0b0d15 100%)}
.wrap{max-width:1280px;margin:0 auto;padding:22px}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.brand h1{margin:0 0 8px 0}
.sub{color:var(--muted);font-size:.88rem}
.linkbar{display:flex;flex-wrap:wrap;gap:10px}
.linkbar a{text-decoration:none;color:#cde3ff;padding:8px 10px;border:1px solid var(--b);border-radius:999px;background:linear-gradient(180deg,var(--surface),#0d1320)}
.badge{display:inline-flex;gap:8px;padding:8px 12px;border-radius:999px;border:1px solid #2f4861;background:#0f1b2b;color:#b9dff8;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:14px}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:14px;padding:14px}
.k{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}
.v{font-size:1.5rem;font-weight:700;margin-top:6px}
.panel{margin-top:14px;background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:14px;padding:14px}
.controls{display:grid;grid-template-columns:1.1fr 1fr 1fr auto;gap:10px;margin-bottom:12px}
.intel-controls{display:grid;grid-template-columns:200px 1fr auto;gap:10px;margin-top:10px}
input,select,button{border-radius:10px;border:1px solid #2f4861;background:#0c1a2a;color:#ecf3fb;padding:10px}
button{background:linear-gradient(135deg,#2ec3d9,#2f80ed);border:0;font-weight:700;cursor:pointer}
button.ghost{background:#111a2a;border:1px solid #344968}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px;border-bottom:1px solid #23394f;font-size:.9rem}
th{color:#a7bfd8;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}
.chip{display:inline-flex;padding:2px 8px;border-radius:999px;border:1px solid #35506e;color:#cde3ff;background:#12263d;font-size:.72rem}
.link-btn{border:0;background:transparent;color:#8ed3ff;text-decoration:underline;cursor:pointer;padding:0}
.modal{position:fixed;inset:0;background:#04070db8;display:none;align-items:center;justify-content:center;padding:16px}
.modal.open{display:flex}
.modal-card{width:min(100%,1000px);max-height:88vh;overflow:auto;background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:14px;padding:14px}
.modal-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px}
.mini{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.mini .item{padding:10px;border:1px solid var(--b);border-radius:10px;background:#0f1726}
@media (max-width:980px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.controls,.intel-controls{grid-template-columns:1fr 1fr}}
@media (max-width:680px){.grid{grid-template-columns:1fr}.controls,.intel-controls{grid-template-columns:1fr}.mini{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="brand">
        <h1>Minecraft Intelligence</h1>
        <div class="sub">Deep investigation panel for player/IP/ASN behavior and burst analytics.</div>
        <div class="badge" id="modeBadge" style="margin-top:10px">Loading mode...</div>
      </div>
      <div class="linkbar">
        <a href="/admin">Main Admin</a>
        <a href="/dashboard">Public Dashboard</a>
      </div>
    </div>

    <div class="grid" id="summaryCards">
      <div class="card"><div class="k">Events (24h)</div><div class="v" id="sumEvents">0</div></div>
      <div class="card"><div class="k">Unique IPs</div><div class="v" id="sumIps">0</div></div>
      <div class="card"><div class="k">Unique Players</div><div class="v" id="sumPlayers">0</div></div>
      <div class="card"><div class="k">Burst Alerts</div><div class="v" id="sumBursts">0</div></div>
    </div>

    <div class="panel">
      <h2 style="margin:0 0 10px 0;font-size:1rem">Entity Investigation</h2>
      <div class="intel-controls">
        <select id="intelType"><option value="user">Username</option><option value="ip">IP</option><option value="asn">ASN</option></select>
        <input id="intelValue" placeholder="Example: atma_12345, 45.141.178.192, AS14061">
        <button id="intelSearchBtn">Investigate</button>
      </div>
      <div class="sub" id="intelHint" style="margin-top:8px">Search opens a popup with timeline and aggregated intel. If user not found locally, MySQL fallback is attempted.</div>
    </div>

    <div class="panel">
      <h2 style="margin:0 0 10px 0;font-size:1rem">Advanced Event Query</h2>
      <div class="controls">
        <input id="fUser" placeholder="Username (exact)">
        <input id="fIp" placeholder="IP (exact)">
        <select id="fType">
          <option value="">All event types</option>
          <option value="login">login</option>
          <option value="velocity_connected">velocity_connected</option>
          <option value="velocity_disconnect">velocity_disconnect</option>
          <option value="ip_disconnect">ip_disconnect</option>
          <option value="failed_packet">failed_packet</option>
          <option value="mysql_backfill">mysql_backfill</option>
        </select>
        <button id="btnFilter">Apply</button>
      </div>
      <table>
        <thead><tr><th>Time</th><th>IP</th><th>Player</th><th>Type</th><th>Risk</th><th>ASN</th><th>Country</th></tr></thead>
        <tbody id="eventRows"></tbody>
      </table>
    </div>

    <div class="panel">
      <h2 style="margin:0 0 10px 0;font-size:1rem">Recent Burst Alerts</h2>
      <table>
        <thead><tr><th>Time</th><th>IP</th><th>Events</th><th>Window (sec)</th><th>Plugin</th></tr></thead>
        <tbody id="burstRows"></tbody>
      </table>
    </div>
  </div>

  <div class="modal" id="intelModal">
    <div class="modal-card">
      <div class="modal-head">
        <div>
          <h3 id="intelTitle" style="margin:0">Entity Intel</h3>
          <div class="sub" id="intelMeta">Loading...</div>
        </div>
        <button class="ghost" id="intelCloseBtn">Close</button>
      </div>
      <div class="mini" id="intelStats"></div>
      <div class="panel" style="margin-top:12px">
        <h4 style="margin:0 0 8px 0">Recent Timeline</h4>
        <table>
          <thead><tr><th>Time</th><th>IP</th><th>User</th><th>Type</th><th>Risk</th><th>ASN</th></tr></thead>
          <tbody id="intelRows"></tbody>
        </table>
      </div>
    </div>
  </div>

<script>
async function api(path){
  const res = await fetch(path, {credentials:'same-origin'});
  if(!res.ok){ throw new Error('HTTP '+res.status); }
  return await res.json();
}
function esc(v){ return String(v ?? '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s])); }

function openIntelModal(){ document.getElementById('intelModal').classList.add('open'); }
function closeIntelModal(){ document.getElementById('intelModal').classList.remove('open'); }

function eventType(details){
  try{ if(typeof details==='string'){ details=JSON.parse(details||'{}'); } }catch(_){ details={}; }
  return (details&&details.event_type)||'';
}

async function loadSummary(){
  const s = await api('/api/minecraft/summary?hours=24');
  document.getElementById('sumEvents').textContent = String(s.event_count || 0);
  document.getElementById('sumIps').textContent = String(s.unique_ips || 0);
  document.getElementById('sumPlayers').textContent = String(s.unique_players || 0);
  document.getElementById('sumBursts').textContent = String(s.burst_alerts || 0);
  const observeOnly = !!s.observe_only_enabled && !s.enforcement_enabled;
  document.getElementById('modeBadge').textContent = observeOnly
    ? 'Observe-Only Active (No Firewall Actions)'
    : 'Enforcement may be enabled for Minecraft';
}

async function loadEvents(){
  const user = encodeURIComponent(document.getElementById('fUser').value.trim());
  const ip = encodeURIComponent(document.getElementById('fIp').value.trim());
  const type = encodeURIComponent(document.getElementById('fType').value);
  const q = '/api/minecraft/events?limit=150&username='+user+'&ip='+ip+'&event_type='+type;
  const data = await api(q);
  const rows = (data.events || []).map(e => {
    const asnLabel = e.asn_number ? ('AS'+String(e.asn_number)) : '-';
    return '<tr>'+
      '<td>'+esc(e.timestamp)+'</td>'+
      '<td><button class="link-btn" data-intel-type="ip" data-intel-value="'+esc(e.source_ip)+'">'+esc(e.source_ip)+'</button></td>'+
      '<td>'+(e.player_name?('<button class="link-btn" data-intel-type="user" data-intel-value="'+esc(e.player_name)+'">'+esc(e.player_name)+'</button>'):'-')+'</td>'+
      '<td><span class="chip">'+esc(e.event_type || eventType(e.details) || '-')+'</span></td>'+
      '<td>'+esc(e.risk_score || 0)+'</td>'+
      '<td>'+(e.asn_number?('<button class="link-btn" data-intel-type="asn" data-intel-value="AS'+esc(String(e.asn_number))+'">'+esc(asnLabel)+'</button>'):'-')+'</td>'+
      '<td>'+esc(e.country_code || '-')+'</td>'+
    '</tr>';
  }).join('');
  document.getElementById('eventRows').innerHTML = rows || '<tr><td colspan="7">No events</td></tr>';
}

async function loadBursts(){
  const data = await api('/api/minecraft/bursts?limit=80');
  const rows = (data.alerts || []).map(a =>
    '<tr>'+
      '<td>'+esc(a.timestamp)+'</td>'+
      '<td><button class="link-btn" data-intel-type="ip" data-intel-value="'+esc(a.source_ip)+'">'+esc(a.source_ip)+'</button></td>'+
      '<td>'+esc(a.event_count)+'</td>'+
      '<td>'+esc(a.window_seconds)+'</td>'+
      '<td>'+esc(a.plugin_name)+'</td>'+
    '</tr>'
  ).join('');
  document.getElementById('burstRows').innerHTML = rows || '<tr><td colspan="5">No burst alerts</td></tr>';
}

async function searchIntel(type, value){
  if(!value){ return; }
  openIntelModal();
  document.getElementById('intelTitle').textContent = 'Entity Intel: '+value;
  document.getElementById('intelMeta').textContent = 'Loading...';
  document.getElementById('intelStats').innerHTML = '';
  document.getElementById('intelRows').innerHTML = '<tr><td colspan="6">Loading...</td></tr>';

  const payload = await api('/api/minecraft/entity-intel?type='+encodeURIComponent(type)+'&value='+encodeURIComponent(value));
  const mysqlInfo = payload.mysql || {};
  const metaBits = ['Type: '+payload.type, 'Events: '+(payload.count||0), 'Peak Risk: '+(payload.risk_peak||0)];
  if(payload.mysql_backfilled){ metaBits.push('MySQL backfill: yes'); }
  if(mysqlInfo && mysqlInfo.reason){ metaBits.push('MySQL: '+mysqlInfo.reason); }
  document.getElementById('intelMeta').textContent = metaBits.join(' · ');

  const uniqueIps = (payload.unique_ips || []).slice(0,5).join(', ') || '-';
  const uniqueUsers = (payload.unique_users || []).slice(0,5).join(', ') || '-';
  document.getElementById('intelStats').innerHTML = ''
    +'<div class="item"><div class="k">Entity</div><div class="v" style="font-size:1rem">'+esc(payload.value||'')+'</div></div>'
    +'<div class="item"><div class="k">Event Count</div><div class="v" style="font-size:1rem">'+esc(payload.count||0)+'</div></div>'
    +'<div class="item"><div class="k">Unique IPs</div><div class="v" style="font-size:.88rem">'+esc(uniqueIps)+'</div></div>'
    +'<div class="item"><div class="k">Unique Users</div><div class="v" style="font-size:.88rem">'+esc(uniqueUsers)+'</div></div>';

  const rows = (payload.events || []).map(e => {
    const t = eventType(e.details) || '-';
    return '<tr>'
      +'<td>'+esc(e.timestamp)+'</td>'
      +'<td>'+esc(e.source_ip||'-')+'</td>'
      +'<td>'+esc(e.player_name||'-')+'</td>'
      +'<td>'+esc(t)+'</td>'
      +'<td>'+esc(e.risk_score||0)+'</td>'
      +'<td>'+esc(e.asn_org || (e.asn_number ? ('AS'+String(e.asn_number)) : '-'))+'</td>'
      +'</tr>';
  }).join('');
  document.getElementById('intelRows').innerHTML = rows || '<tr><td colspan="6">No timeline data</td></tr>';
}

document.getElementById('btnFilter').addEventListener('click', loadEvents);
document.getElementById('intelSearchBtn').addEventListener('click', function(){
  searchIntel(document.getElementById('intelType').value, document.getElementById('intelValue').value.trim());
});
document.getElementById('intelCloseBtn').addEventListener('click', closeIntelModal);
document.getElementById('intelModal').addEventListener('click', function(ev){ if(ev.target===this){ closeIntelModal(); } });
document.body.addEventListener('click', function(ev){
  const btn = ev.target.closest('[data-intel-type]');
  if(!btn){ return; }
  const type = btn.getAttribute('data-intel-type');
  const value = btn.getAttribute('data-intel-value');
  if(type && value){ searchIntel(type, value); }
});

Promise.all([loadSummary(), loadEvents(), loadBursts()]).catch(err => {
  console.error(err);
  document.getElementById('modeBadge').textContent = 'Failed to load Minecraft analytics';
});
</script>
</body>
</html>
"""

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
        <div style="margin-bottom:14px;padding:13px 14px;border-radius:14px;border:1px solid var(--b);background:var(--surface2)">
          <div style="font-size:.8rem;font-weight:700;margin-bottom:6px;">Private Network Whitelist <span style="font-weight:400;color:var(--muted)">(Optional)</span></div>
          <p style="font-size:.76rem;margin-bottom:8px;">Add Tailscale or other overlay network CIDR ranges to automatically protect them from being blocked.</p>
          <label style="display:flex;align-items:center;gap:7px;font-size:.8rem;cursor:pointer;margin-bottom:10px;"><input id="addTailscale" type="checkbox" style="width:auto;accent-color:var(--accent)"> Tailscale (100.64.0.0/10)</label>
          <div style="font-size:.76rem;color:var(--muted);margin-bottom:5px;">Additional ranges (one per line, e.g. 10.0.0.0/8)</div>
          <textarea id="extraNets" style="width:100%;background:var(--surface);border:1px solid var(--b);color:var(--txt);border-radius:10px;padding:8px 10px;font-size:.82rem;height:52px;resize:vertical;outline:none;font-family:inherit"></textarea>
        </div>
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
        totp_code: $('#setupTotpCode').value.trim(),
        whitelist_private_networks: (function(){ var nets=[]; if($('#addTailscale')&&$('#addTailscale').checked){ nets.push('100.64.0.0/10'); } if($('#extraNets')){ ($('#extraNets').value||'').split(/[\n,]+/).forEach(function(s){ var t=s.trim(); if(t) nets.push(t); }); } return nets; })()
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
.pn{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1.5rem;margin-bottom:2rem;align-items:start;grid-auto-flow:dense}
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
.t tr.tr-ban-trigger td{background:color-mix(in srgb,var(--red) 22%,var(--card-h))}
.t tr.tr-post-ban td{background:color-mix(in srgb,var(--red) 12%,var(--card))}
.t tr.tr-firewall-block td{background:color-mix(in srgb,var(--warn) 12%,var(--card))}
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
.geo-map{position:relative;width:100%;aspect-ratio:2/1;min-height:240px;max-height:460px;border:1px solid var(--bdr);border-radius:14px;background:radial-gradient(circle at 50% 50%,color-mix(in srgb,var(--cyan) 8%,transparent) 0%,transparent 55%),linear-gradient(180deg,color-mix(in srgb,var(--card-h) 86%,transparent),color-mix(in srgb,var(--card) 88%,transparent));overflow:hidden}
.geo-grid{position:absolute;inset:0;z-index:1;opacity:.22;background-image:linear-gradient(to right,var(--bdr) 1px,transparent 1px),linear-gradient(to bottom,var(--bdr) 1px,transparent 1px);background-size:32px 32px}
.geo-world{position:absolute;inset:0;z-index:2;pointer-events:none;opacity:.32;width:100%;height:100%;transform:translateX(2%) scale(1.14,1.06);transform-origin:center center}
.geo-world .land{fill:color-mix(in srgb,var(--cyan) 15%,transparent);stroke:color-mix(in srgb,var(--cyan) 26%,var(--bdr));stroke-width:1.1;stroke-linejoin:round}
.geo-world .island{fill:color-mix(in srgb,var(--cyan) 13%,transparent);stroke:color-mix(in srgb,var(--cyan) 24%,var(--bdr));stroke-width:.9}
.geo-point{position:absolute;z-index:3;transform:translate(-50%,-50%);border-radius:999px;border:1px solid color-mix(in srgb,var(--red) 65%,white);background:color-mix(in srgb,var(--red) 42%,transparent);cursor:pointer;box-shadow:0 0 0 1px #00000033,0 0 18px color-mix(in srgb,var(--red) 45%,transparent)}
.geo-point.is-new::after{content:'';position:absolute;inset:-6px;border-radius:999px;border:1px solid color-mix(in srgb,var(--red) 72%,white);opacity:.8;animation:geoPulse 1.2s ease-out}
@keyframes geoPulse{0%{transform:scale(.65);opacity:.9}100%{transform:scale(2.1);opacity:0}}
.geo-legend{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-top:.75rem;font-size:.72rem;color:var(--dim)}
.geo-legend .bar{flex:1;height:8px;border-radius:999px;background:linear-gradient(90deg,color-mix(in srgb,var(--red) 18%,transparent),color-mix(in srgb,var(--red) 75%,white))}
.geo-meta{margin-top:.55rem;font-size:.76rem;color:var(--dim)}
.toggle-chip{display:inline-flex;align-items:center;gap:.45rem;padding:.32rem .58rem;border:1px solid var(--bdr);border-radius:999px;background:var(--card-h);font-size:.72rem;color:var(--dim)}
.toggle-chip input{appearance:none;width:30px;height:18px;border-radius:999px;border:1px solid var(--bdr);background:var(--surface2);position:relative;cursor:pointer;transition:background .18s ease,border-color .18s ease}
.toggle-chip input::after{content:'';position:absolute;top:1px;left:1px;width:14px;height:14px;border-radius:50%;background:var(--muted);transition:transform .18s ease,background .18s ease}
.toggle-chip input:checked{background:color-mix(in srgb,var(--accent) 26%,var(--surface2));border-color:var(--accent)}
.toggle-chip input:checked::after{transform:translateX(12px);background:#fff3eb}
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
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Recent Events</h2><span class="pill" id="ec">0</span><button id="evBannedToggle" style="margin-left:auto;font-size:.7rem;font-weight:700;padding:.2rem .6rem;border-radius:8px;border:1px solid var(--bdr);background:color-mix(in srgb,var(--warn) 18%,var(--card-h));color:var(--warn);cursor:pointer" title="Hide events after a source enters ban/firewall-block state">Hide Post-Ban Traffic</button></div>
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
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>Top Countries</h2><select id="coTimeRange" style="margin-left:auto;font-size:.7rem;padding:.2rem .5rem;border-radius:8px;border:1px solid var(--bdr);background:var(--card-h);color:var(--txt);cursor:pointer"><option value="24">24h</option><option value="72">3 Days</option><option value="168">7 Days</option><option value="720">30 Days</option><option value="0">All Time</option></select></div>
      <div class="pb"><div class="cb" id="coc"></div></div>
    </div>
    <div class="pl ai d3">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="M20 8v6m3-3h-6"/></svg>Top Portscanned Ports</h2><span class="pill" id="ac">0</span><label class="toggle-chip" style="margin-left:auto"><input id="atHoneypotToggle" type="checkbox" checked><span>Include Honeypot</span></label><select id="atTimeRange" style="font-size:.7rem;padding:.2rem .5rem;border-radius:8px;border:1px solid var(--bdr);background:var(--card-h);color:var(--txt);cursor:pointer"><option value="24">24h</option><option value="72">3 Days</option><option value="168">7 Days</option><option value="720">30 Days</option><option value="0">All Time</option></select></div>
      <div class="pb"><div class="cb" id="atc"></div></div>
    </div>
    <div class="pl ai d4">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/></svg>Plugins</h2></div>
      <div class="pb"><div class="cb" id="plc"></div></div>
    </div>
    <div class="pl fw ai d3">
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
var evShowBanned=true;
var includeHoneypotPorts=true;
var lastEvData=[];
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
    var firstSetupCount=Number(fs.ips_loaded||0);
    var activeCount=Number(ti.active&&ti.active.total_ips_loaded ? ti.active.total_ips_loaded : 0);
    $('#tis').textContent = N(activeCount||firstSetupCount||0);
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

function renderEventsTable(events){
  var etb=$('#evb'),ee=$('#eve'),ep=$('#ec');
  var eventsToShow=evShowBanned?events:events.filter(function(e){ return !(e.is_post_ban||e.is_firewall_blocked); });
  if(!eventsToShow.length){etb.innerHTML='';ee.style.display='block';ep.textContent='0';return;}
  ee.style.display='none';ep.textContent=eventsToShow.length;
  etb.innerHTML=eventsToShow.map(function(e){
    var pl=(e.connection_type||'unknown').toUpperCase();
    var tc=e.threat_level;
    var tcl=tc==='HIGH'||tc==='CRITICAL'?'tg-H':tc==='MEDIUM'?'tg-M':tc==='LOW'?'tg-L':'tg-N';
    var advice=e.operator_advice||'No specific operator advice for this event.';
    var cc=(e.country_code||'').toUpperCase();
    var origin=cc?CF(cc)+' '+cc:'-';
    var isBanTrigger=!!e.is_ban_trigger_event;
    var isPostBan=!!e.is_post_ban;
    var isFirewallBlocked=!!e.is_firewall_blocked;
    var rowClass=isBanTrigger?'tr-ban-trigger':(isPostBan?'tr-post-ban':(isFirewallBlocked?'tr-firewall-block':''));
    var bannedMark='';
    if(isBanTrigger){
      bannedMark='<span style="font-size:.6rem;font-weight:700;padding:.1rem .4rem;border-radius:4px;background:var(--red-d);color:var(--red);margin-left:4px">BANNED NOW</span>';
    }else if(isPostBan){
      bannedMark='<span style="font-size:.6rem;font-weight:700;padding:.1rem .4rem;border-radius:4px;background:var(--red-d);color:var(--red);margin-left:4px">BANNED</span>';
    }else if(isFirewallBlocked){
      bannedMark='<span style="font-size:.6rem;font-weight:700;padding:.1rem .4rem;border-radius:4px;background:var(--warn-d);color:var(--warn);margin-left:4px">FIREWALL-BLOCKED</span>';
    }
    return '<tr class="'+rowClass+'"><td style="white-space:nowrap;font-size:.75rem">'+T(e.timestamp_unix||e.timestamp)+'</td><td class="h" title="'+E(e.source_ip)+'">'+E((e.source_ip||'').substring(0,14))+'&hellip;'+bannedMark+'</td><td><span class="pt">'+E(pl)+'</span></td><td>'+E(e.player_name||'-')+'</td><td style="font-size:.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(origin)+'">'+E(origin)+'</td><td><span class="rb '+RC(e.risk_score)+'">'+e.risk_score+'</span></td><td><span class="tg '+tcl+'">'+E(tc)+'</span></td><td style="font-size:.75rem;color:var(--dim);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(e.asn_org)+'">'+E(e.asn_org||'-')+'</td><td><span class="advice-tip" title="'+E(advice)+'">i</span></td></tr>';
  }).join('');
}
function renderTimelineFromEvents(events){
  var tc2=$('#tlc'),tl2=$('#tll');
  if(!tc2||!tl2){ return; }
  var buckets=[];
  var labels=[];
  for(var i=23;i>=0;i--){
    var d=new Date(Date.now()-(i*3600000));
    var hour=String(d.getHours()).padStart(2,'0')+':00';
    labels.push(hour);
    buckets.push({hour:hour,count:0});
  }
  (events||[]).forEach(function(e){
    if(!evShowBanned && (e.is_post_ban||e.is_firewall_blocked)){ return; }
    var ts=parseTs(e.timestamp_unix||e.timestamp);
    if(ts===null){ return; }
    var diff=Math.floor((Date.now()-ts)/3600000);
    if(diff<0||diff>23){ return; }
    var idx=23-diff;
    buckets[idx].count+=1;
  });
  var mx=Math.max.apply(null,buckets.map(function(t){ return t.count; }).concat([1]));
  tc2.innerHTML=buckets.map(function(t){
    var pct=Math.max((t.count/mx)*100,2);
    return '<div class="tb" style="height:'+pct+'%" data-t="'+t.hour+': '+t.count+' events"></div>';
  }).join('');
  tl2.innerHTML=labels.map(function(hr,i){
    var show=i%2===0;
    return '<span>'+(show?hr:'')+'</span>';
  }).join('');
}
async function refreshCountry(){
  var hours=parseInt(($('#coTimeRange')||{value:'24'}).value,10)||0;
  var co=await A('/api/asn-stats'+(hours>0?'?hours='+hours:''));
  var countryItems=co&&co.countries?co.countries.filter(function(item){
    var code=String((item&&item.country)||'').toUpperCase();
    return code && code!=='ZZ';
  }):null;
  bars('coc',countryItems,'country','count',2);
}
async function refreshTopPorts(){
  var hours=parseInt(($('#atTimeRange')||{value:'24'}).value,10)||0;
  includeHoneypotPorts=!!($('#atHoneypotToggle')&&$('#atHoneypotToggle').checked);
  var at=await A('/api/top-portscanned-ports?limit=10'+(hours>0?'&hours='+hours:'')+(includeHoneypotPorts?'':'&include_honeypot=0'));
  var ap=$('#ac');
  if(at&&at.ports){ap.textContent=at.ports.length;
    var ait=at.ports.map(function(p){return{label:'Port '+String(p.port||'-')+(p.is_honeypot?' (H)':''),count:p.scan_count||0}});
    bars('atc',ait,'label','count',1)}
  else{ap.textContent='0';bars('atc',[],'label','count',1)}
}
async function refresh(){
  var h=await A('/api/health');
  var s=await A('/api/stats');
  var bn=await A('/api/bans');
  var ev=await A('/api/events?limit=2000');
  var th=await A('/api/threat-distribution');
  var pg=await A('/api/plugin-stats');
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
    if(sim){bd.className='bdg bdg-sim';bd.innerHTML='MONITOR'}
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
  lastEvData=ev&&ev.events?ev.events:[];
  renderEventsTable(lastEvData);
  renderTimelineFromEvents(lastEvData);

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
  await refreshCountry();

  // Plugins
  bars('plc',pg?pg.plugins:null,'plugin','count',3);

  // Top scanned ports
  await refreshTopPorts();

  renderBlocklist(ti);
  renderGeoHeatmap(gh);
}

initTheme();
$('#themeToggle').addEventListener('click',function(){
  applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');
});
$('#evBannedToggle').addEventListener('click',function(){
  evShowBanned=!evShowBanned;
  this.textContent=evShowBanned?'Hide Post-Ban Traffic':'Show Post-Ban Traffic';
  this.style.background=evShowBanned?'color-mix(in srgb,var(--warn) 18%,var(--card-h))':'color-mix(in srgb,var(--grn) 18%,var(--card-h))';
  this.style.color=evShowBanned?'var(--warn)':'var(--grn)';
  renderEventsTable(lastEvData);
  renderTimelineFromEvents(lastEvData);
});
$('#coTimeRange').addEventListener('change',function(){ refreshCountry(); });
$('#atTimeRange').addEventListener('change',function(){ refreshTopPorts(); });
$('#atHoneypotToggle').addEventListener('change',function(){ refreshTopPorts(); });
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
.layout{display:grid;grid-template-columns:1.45fr 1fr;gap:16px}.stack{display:grid;gap:16px}.split{display:grid;grid-template-columns:1fr 1fr;gap:16px}.table-wrap{max-height:420px;overflow:auto;border:1px solid var(--b);border-radius:14px;background:var(--surface)}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 13px;border-bottom:1px solid var(--b);font-size:.88rem;vertical-align:middle}th{position:sticky;top:0;background:var(--surface2);color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.08em}td:first-child{font-size:.9rem;font-weight:650}tr:hover td{background:color-mix(in srgb,var(--surface2) 82%,var(--blue) 18%)}tr.ev-row-ban-trigger td{background:color-mix(in srgb,var(--red) 20%,var(--surface))}tr.ev-row-post-ban td{background:color-mix(in srgb,var(--red) 12%,var(--surface))}tr.ev-row-firewall td{background:color-mix(in srgb,var(--yellow) 12%,var(--surface))}
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
.config-grid{grid-template-columns:repeat(2,minmax(180px,1fr));gap:14px 16px}
.config-field{min-width:0;padding:0}
.config-field label{white-space:normal;line-height:1.4;font-size:.8rem;margin-bottom:4px}
.config-input,.config-select{width:100%;min-width:0;padding:10px 14px;min-height:40px}
.toolbar-grid.three{align-items:stretch;grid-template-columns:minmax(0,1.35fr) minmax(110px,.55fr) minmax(140px,.7fr)}
.toolbar-grid.query-grid{grid-template-columns:minmax(128px,170px) minmax(0,1fr) minmax(130px,170px)}
.toolbar-grid.dual-actions{grid-template-columns:minmax(0,1fr) auto auto}
.toolbar-grid.stack-label{margin-bottom:6px}
.toolbar-grid.three .ctrl,.toolbar-grid.query-grid .ctrl{width:100%;min-width:0}
.ip-link-btn{all:unset;cursor:pointer;color:var(--blue);text-decoration:underline;text-underline-offset:2px;font-family:Cascadia Code,Fira Code,monospace;font-size:.76rem}
.ip-link-btn:hover{color:color-mix(in srgb,var(--blue) 70%,white)}
.action-center-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.action-panel{padding:14px;border:1px solid var(--b);border-radius:14px;background:linear-gradient(180deg,var(--surface),var(--surface2))}
.action-panel .toolbar-grid{margin-bottom:14px}
.action-panel .toolbar-grid:last-child{margin-bottom:0}
.intel-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px}
.intel-item{padding:10px;border:1px solid var(--b);border-radius:12px;background:var(--surface)}
.intel-item .k{display:block;font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:4px}
.intel-item .v{display:block;font-size:.84rem;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row-kind{font-size:.68rem;font-weight:800;display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;border:1px solid var(--b)}
.row-kind.event{color:#c9deff;background:color-mix(in srgb,var(--blue) 16%,transparent)}
.row-kind.ban{color:#ffd3d7;background:color-mix(in srgb,var(--red) 16%,transparent)}
.row-kind.ok{color:#b8ffe0;background:color-mix(in srgb,var(--green) 16%,transparent)}
.row-kind.fail{color:#ffd3d7;background:color-mix(in srgb,var(--red) 16%,transparent)}
.bulk-result-summary{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-bottom:10px}
.bulk-result-summary .intel-item{padding:9px}
.chip-editor{display:flex;flex-wrap:wrap;gap:8px;min-height:42px;padding:8px 10px;border:1px solid var(--b);border-radius:12px;background:var(--surface2)}
.chip-editor.empty::before{content:'No ignored ports';color:var(--muted);font-size:.78rem}
.chip{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;background:color-mix(in srgb,var(--blue) 20%,var(--surface));border:1px solid color-mix(in srgb,var(--blue) 40%,var(--b));font-size:.78rem}
.chip button{all:unset;cursor:pointer;font-weight:700;color:var(--muted);line-height:1}
.chip button:hover{color:var(--txt)}
.primary-actions{position:sticky;bottom:0;z-index:3;background:linear-gradient(180deg,color-mix(in srgb,var(--panel2) 80%,transparent),var(--panel2));padding:12px;border:1px solid var(--b);border-radius:14px;backdrop-filter:blur(2px)}
.advanced-wrap{margin-top:2px}
.config-toggle input[type="checkbox"],.config-kv-toggle input[type="checkbox"]{appearance:none;-webkit-appearance:none;width:46px;height:26px;border-radius:999px;border:1px solid color-mix(in srgb,var(--accent) 30%,var(--b));background:color-mix(in srgb,var(--surface2) 88%,var(--surface));position:relative;cursor:pointer;transition:background .2s ease,border-color .2s ease,box-shadow .2s ease}
.config-toggle input[type="checkbox"]::before,.config-kv-toggle input[type="checkbox"]::before{content:'';position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:999px;background:var(--txt);box-shadow:0 2px 8px #00000035;transition:transform .2s ease,background .2s ease}
.config-toggle input[type="checkbox"]:checked,.config-kv-toggle input[type="checkbox"]:checked{background:linear-gradient(135deg,var(--accent),#ff6f61);border-color:color-mix(in srgb,var(--accent) 65%,white)}
.config-toggle input[type="checkbox"]:checked::before,.config-kv-toggle input[type="checkbox"]:checked::before{transform:translateX(20px);background:#fff}
.config-toggle input[type="checkbox"]:focus-visible,.config-kv-toggle input[type="checkbox"]:focus-visible{outline:none;box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 34%,transparent)}
.config-all-wrap{display:grid;gap:12px}
.config-all-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.config-all-head .sub{margin:0}
.config-all-list{display:grid;gap:10px;max-height:420px;overflow:auto;padding-right:4px}
.config-kv-item{padding:11px 12px;border:1px solid var(--b);border-radius:13px;background:linear-gradient(180deg,var(--surface),var(--surface2));display:grid;gap:8px}
.config-kv-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.config-kv-path{font-family:Cascadia Code,Fira Code,monospace;font-size:.76rem;line-height:1.4;word-break:break-all}
.config-kv-kind{font-size:.66rem;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);padding:3px 7px;border:1px solid var(--b);border-radius:999px;background:var(--surface2);white-space:nowrap}
.config-kv-toggle{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 12px;border:1px solid var(--b);border-radius:13px;background:linear-gradient(180deg,var(--surface),var(--surface2))}
.config-group{border:1px solid var(--b);border-radius:14px;background:linear-gradient(180deg,var(--surface),var(--surface2));overflow:hidden}
.config-group-toggle{all:unset;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:10px;width:100%;padding:10px 12px;font-size:.84rem;font-weight:800;border-bottom:1px solid color-mix(in srgb,var(--b) 76%,transparent);background:color-mix(in srgb,var(--surface2) 88%,var(--surface))}
.config-group-toggle:hover{background:color-mix(in srgb,var(--surface2) 80%,var(--surface))}
.config-group-sign{font-size:1rem;color:var(--muted);line-height:1}
.config-group-count{font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:700}
.config-group-body{padding:10px;display:grid;gap:10px}
.config-group:not(.open) .config-group-body{display:none}
@media(max-width:1280px){.config-sections{column-count:2}}
@media(max-width:900px){.config-sections{column-count:1}}
@media(max-width:1180px){.toolbar-grid.three{grid-template-columns:minmax(0,1fr) minmax(125px,170px)}.toolbar-grid.three button{grid-column:1/-1}.toolbar-grid.query-grid{grid-template-columns:1fr 1fr}.toolbar-grid.query-grid button{grid-column:1/-1}}
@media(max-width:680px){.modal-header-actions,.primary-actions{width:100%}.config-filter{min-width:0;width:100%}.toolbar-grid.three,.toolbar-grid.dual-actions{grid-template-columns:1fr}}
@media(max-width:680px){.toolbar-grid.query-grid{grid-template-columns:1fr}}
@media(max-width:980px){.action-center-grid{grid-template-columns:1fr}.intel-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:680px){.intel-grid{grid-template-columns:1fr}}
@media(max-width:900px){.bulk-result-summary{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:680px){.bulk-result-summary{grid-template-columns:1fr}}
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
        <a href="/admin/minecraft">Minecraft Intelligence</a>
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
      <a href="/admin/minecraft" class="btn ghost" style="text-decoration:none;display:inline-flex;align-items:center;justify-content:center">Minecraft</a>
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
          <div id="simulationTopNotice" class="theme-chip" hidden style="border-color:color-mix(in srgb,var(--blue) 45%,var(--b));color:#c8e4ff;background:color-mix(in srgb,var(--blue) 12%,var(--surface));">Monitor Mode active — events are recorded but no firewall actions applied. Disable to switch to enforcement.</div>
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
        <div class="action-center-grid">
          <div class="action-panel">
            <div class="toolbar-grid stack-label"><div class="sub">Manual Ban</div></div>
            <div class="toolbar-grid three">
              <input id="manualBanIp" class="ctrl search" placeholder="Enter an IP address to ban manually">
              <input id="manualBanDuration" class="ctrl" type="number" min="0" value="0" placeholder="Duration (sec, 0=permanent)">
              <button id="banManualBtn" class="btn warn">Ban IP</button>
            </div>
            <div class="toolbar-grid">
              <input id="manualBanReason" class="ctrl search" placeholder="Optional reason (default: [ADMIN] Manual ban from dashboard)">
            </div>
            <div class="toolbar-grid stack-label"><div class="sub">Bulk IP Action (one per line)</div></div>
            <div class="toolbar-grid query-grid">
              <select id="bulkActionType" class="ctrl">
                <option value="ban">Ban</option>
                <option value="report_and_ban">Report + Ban</option>
                <option value="report">Report Only</option>
              </select>
              <input id="bulkReason" class="ctrl search" placeholder="Reason/comment for all lines (optional)">
              <input id="bulkCategories" class="ctrl" placeholder="Report categories: 14,15">
            </div>
            <div class="toolbar-grid three">
              <textarea id="bulkIpLines" class="config-editor" style="min-height:110px;grid-column:1/-1" spellcheck="false" placeholder="203.0.113.5&#10;198.51.100.20 | ssh brute force&#10;2001:db8::7 | scanner"></textarea>
              <input id="bulkDuration" class="ctrl" type="number" min="0" value="0" placeholder="Duration (sec)">
              <button id="bulkActionBtn" class="btn cyan">Run Bulk Action</button>
            </div>
            <div class="toolbar-grid query-grid" style="margin-top:-6px">
              <label class="theme-chip" style="padding:6px 10px"><input id="bulkRespectRateLimit" type="checkbox" checked style="accent-color:var(--accent);width:1rem;height:1rem"><span>Respect AbuseIPDB rate-limit</span></label>
              <input id="bulkReportIntervalMs" class="ctrl" type="number" min="500" step="100" value="2200" placeholder="Report interval ms">
              <div class="sub" style="align-self:center">Higher interval = fewer skipped reports.</div>
            </div>
            <div class="sub">Line format: <span class="mono">IP</span> or <span class="mono">IP | note</span>. Notes are appended to report comment/reason.</div>
            <div class="toolbar-grid stack-label"><div class="sub">Manual Unban</div></div>
            <div class="toolbar-grid">
              <input id="manualIp" class="ctrl search" placeholder="Enter an IP address to unban from the firewall">
              <button id="unbanManualBtn" class="btn primary">Unban IP</button>
            </div>
          </div>

          <div class="action-panel">
            <div class="toolbar-grid stack-label"><div class="sub">Whitelist Management (allowed IP/CIDR)</div></div>
            <div class="toolbar-grid dual-actions">
              <input id="manualWhitelist" class="ctrl search" placeholder="Enter IP or CIDR (example: 203.0.113.4 or 203.0.113.0/24)">
              <button id="addWhitelistBtn" class="btn cyan">Add Whitelist</button>
              <button id="removeWhitelistBtn" class="btn ghost">Remove From Whitelist</button>
            </div>
            <div class="toolbar-grid stack-label" style="margin-top:-2px">
              <div class="sub">Current Whitelist Entries</div>
              <button id="refreshWhitelistBtn" class="btn ghost">Refresh List</button>
            </div>
            <div class="table-wrap" style="max-height:220px">
              <table>
                <thead><tr><th>Type</th><th>Entry</th></tr></thead>
                <tbody id="whitelistRows"></tbody>
              </table>
            </div>
          </div>

          <div class="action-panel">
            <div class="toolbar-grid stack-label"><div class="sub">Record Query (IP / ASN / Username)</div></div>
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
          </div>

          <div class="action-panel">
            <div class="toolbar-grid stack-label"><div class="sub">Admin Security</div></div>
            <div class="toolbar-grid query-grid" style="margin-bottom:0">
              <div id="adminTotpLabel" class="sub">Require TOTP on login for this admin account</div>
              <label class="theme-chip" style="justify-self:start;align-self:center;padding:6px 10px"><input id="adminTotpEnabled" type="checkbox" aria-label="Require TOTP for this admin account" style="accent-color:var(--accent);width:1rem;height:1rem"><span>TOTP Required</span></label>
              <button id="saveAdminTotpBtn" class="btn ghost">Save TOTP Setting</button>
            </div>
          </div>
        </div>

        <div class="action-grid" style="margin-top:14px">
          <button id="enforceSimBansBtn" class="btn primary" hidden>Apply Simulated Bans To Firewall</button>
          <button id="reconcileBansBtn" class="btn primary">Push Active DB Bans -> Firewall</button>
          <button id="deactivateAllBansBtn" class="btn ghost">Deactivate All DB Bans</button>
          <button id="flushFirewallBtn" class="btn ghost">Flush Firewall Bans</button>
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
          <select id="eventBanStateFilter" class="ctrl"><option value="all">All Ban States</option><option value="preban">Pre-Ban Only</option><option value="postban">Post-Ban / Blocked</option></select>
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
      <div class="card"><h2>Top Portscanned Ports</h2><div class="toolbar" style="margin-bottom:8px"><select id="adminAtTimeRange" class="ctrl" style="font-size:.78rem;padding:6px 10px"><option value="0">All Time</option><option value="24" selected>Last 24h</option><option value="72">Last 3 Days</option><option value="168">Last 7 Days</option><option value="720">Last 30 Days</option></select><label class="theme-chip" style="padding:6px 10px"><input id="adminIncludeHoneypot" type="checkbox" checked style="accent-color:var(--accent);width:1rem;height:1rem"><span>Include Honeypot</span></label></div><div class="list" id="topPortsList"></div><div class="toolbar-grid" style="margin-top:10px;margin-bottom:0"><button id="topPortsToggleBtn" class="btn ghost" hidden>Show More</button></div></div>
    </div>
  </div>

  <div class="admin-footer" style="margin-top:24px;padding:14px 12px;border:1px solid var(--b);border-radius:14px;background:linear-gradient(180deg,var(--surface),var(--surface2));color:color-mix(in srgb,var(--txt) 72%,var(--muted))">WardenIPS v__APP_VERSION__ · by __APP_AUTHOR__ · Authenticated operational console · <a href="https://github.com/msncakma/WardenIPS" target="_blank" rel="noopener">GitHub</a> · <a href="https://github.com/msncakma/WardenIPS/stargazers" target="_blank" rel="noopener">Star</a> · <a href="https://github.com/msncakma/WardenIPS/issues" target="_blank" rel="noopener">Issues</a></div>
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
            <label class="config-toggle full"><span>Monitor Mode (Observe Only — no firewall actions)</span><input id="cfgSimulationMode" type="checkbox"></label>
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
        <section class="config-section">
          <h3>All Settings</h3>
          <p>Every config key is editable here. Use this section for full control without opening YAML.</p>
          <div class="config-all-wrap">
            <div class="config-all-head">
              <div class="sub">Fields are generated automatically from current config.yaml values.</div>
            </div>
            <div id="cfgAllSettings" class="config-all-list"></div>
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

<div id="ipDetailModal" class="modal-backdrop" hidden>
  <div class="modal-card" style="width:min(100%,920px);max-height:min(88vh,920px)" role="dialog" aria-modal="true" aria-labelledby="ipDetailTitle">
    <div class="modal-header">
      <div>
        <h2 id="ipDetailTitle">IP Activity</h2>
        <p id="ipDetailMeta">Loading intelligence and recent activity...</p>
      </div>
      <div class="modal-header-actions">
        <button id="closeIpDetailBtn" class="btn ghost">Close</button>
      </div>
    </div>
    <div class="modal-body">
      <div class="panel-box" style="margin-bottom:12px">
        <strong>IP Intelligence</strong>
        <div class="intel-grid">
          <div class="intel-item"><span class="k">IP</span><span class="v mono" id="ipIntelAddress">-</span></div>
          <div class="intel-item"><span class="k">ASN</span><span class="v" id="ipIntelAsn">-</span></div>
          <div class="intel-item"><span class="k">Company</span><span class="v" id="ipIntelCompany">-</span></div>
          <div class="intel-item"><span class="k">Location</span><span class="v" id="ipIntelCountry">-</span></div>
          <div class="intel-item"><span class="k">First Seen</span><span class="v" id="ipIntelFirstSeen">-</span></div>
          <div class="intel-item"><span class="k">Last Seen</span><span class="v" id="ipIntelLastSeen">-</span></div>
          <div class="intel-item"><span class="k">Source</span><span class="v" id="ipIntelSource">-</span></div>
          <div class="intel-item"><span class="k">Confidence</span><span class="v" id="ipIntelConfidence">-</span></div>
        </div>
      </div>
      <div class="hero-meta" id="ipDetailStats" style="grid-template-columns:repeat(4,minmax(0,1fr))">
        <div class="metric"><div class="k">Events</div><div class="v" id="ipDetailEventCount">0</div></div>
        <div class="metric"><div class="k">Ban History</div><div class="v" id="ipDetailBanCount">0</div></div>
        <div class="metric"><div class="k">Active Ban Rows</div><div class="v" id="ipDetailActiveBanCount">0</div></div>
        <div class="metric"><div class="k">Firewall</div><div class="v" id="ipDetailFirewallState">--</div></div>
      </div>
      <div class="toolbar-grid dual-actions" style="margin-top:10px">
        <button id="ipDetailToggleBanBtn" class="btn warn" type="button">Ban This IP</button>
        <button id="ipDetailReportBanBtn" class="btn cyan" type="button">Report + Ban</button>
      </div>
      <div class="toolbar-grid stack-label" style="margin-top:10px">
        <div class="sub">Recent Logs For This IP</div>
      </div>
      <div class="table-wrap" style="max-height:420px">
        <table>
          <thead><tr><th>Time</th><th>Type</th><th>Plugin/Event</th><th>Threat/Reason</th><th>Risk</th></tr></thead>
          <tbody id="ipDetailRows"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div id="bulkResultModal" class="modal-backdrop" hidden>
  <div class="modal-card" style="width:min(100%,1000px);max-height:min(88vh,920px)" role="dialog" aria-modal="true" aria-labelledby="bulkResultTitle">
    <div class="modal-header">
      <div>
        <h2 id="bulkResultTitle">Bulk Action Results</h2>
        <p id="bulkResultMeta">Per-IP execution summary.</p>
      </div>
      <div class="modal-header-actions">
        <button id="closeBulkResultBtn" class="btn ghost">Close</button>
      </div>
    </div>
    <div class="modal-body">
      <div id="bulkResultSummary" class="bulk-result-summary"></div>
      <div class="toolbar" style="margin-bottom:10px">
        <select id="bulkResultFilter" class="ctrl" style="max-width:260px">
          <option value="all">Show: All</option>
          <option value="failed">Show: Failed</option>
          <option value="report_skipped">Show: Report Skipped</option>
          <option value="reported_success">Show: Reported Success</option>
        </select>
        <div id="bulkResultFilterMeta" class="sub">Showing 0/0 rows.</div>
      </div>
      <div class="table-wrap" style="max-height:480px">
        <table>
          <thead><tr><th>IP</th><th>Status</th><th>Ban</th><th>Report</th><th>Message</th></tr></thead>
          <tbody id="bulkResultRows"></tbody>
        </table>
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
var state = {events:[], bans:[], firewall:[], topPorts:[], topPortsExpanded:false, mesh:null, stats:null, health:null, theme:'dark', config:null, configYaml:'', advancedYamlOpen:false, updateInfo:null, portscanIgnoredPorts:[], authSettings:null, whitelist:{ips:[],cidr_ranges:[]}, ipDetailOpen:false, ipDetailIp:'', adminIncludeHoneypot:true, bulkResultPayload:null};
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
function detectPortFromEvent(event){
  if(!event){ return ''; }
  var candidates=['event_port','port','target_port','destination_port','dest_port','dst_port','remote_port'];
  for(var i=0;i<candidates.length;i++){
    var key=candidates[i];
    if(event[key]!==undefined&&event[key]!==null&&String(event[key]).trim()){ return String(event[key]).trim(); }
  }
  var details=event.details;
  if(typeof details==='string'&&details.trim()){
    try{ details=JSON.parse(details); }catch(error){ details={}; }
  }
  if(details&&typeof details==='object'){
    for(var j=0;j<candidates.length;j++){
      var dkey=candidates[j];
      if(details[dkey]!==undefined&&details[dkey]!==null&&String(details[dkey]).trim()){ return String(details[dkey]).trim(); }
    }
  }
  var pname=String(event.player_name||'');
  if(pname.indexOf('port_')===0){ return pname.slice(5).trim(); }
  return '';
}
function isIpBannedInFirewall(ip){
  var needle=String(ip||'').trim();
  if(!needle){ return false; }
  return (state.firewall||[]).some(function(item){ return String(item.ip||'').trim()===needle; });
}
function syncIpDetailActionButtons(){
  var ip=String(state.ipDetailIp||'').trim();
  var toggleBtn=$('#ipDetailToggleBanBtn');
  var reportBtn=$('#ipDetailReportBanBtn');
  if(!toggleBtn||!reportBtn){ return; }
  if(!ip){
    toggleBtn.disabled=true;
    reportBtn.disabled=true;
    toggleBtn.textContent='Ban This IP';
    return;
  }
  var active=isIpBannedInFirewall(ip);
  toggleBtn.disabled=false;
  reportBtn.disabled=false;
  toggleBtn.dataset.mode=active?'unban':'ban';
  toggleBtn.textContent=active?'Unban This IP':'Ban This IP';
}
async function runIpDetailToggleBan(){
  var ip=String(state.ipDetailIp||'').trim();
  if(!ip){ return; }
  var active=isIpBannedInFirewall(ip);
  handleUserActivity();
  if(active){
    if(!confirm('Remove this IP from firewall bans?')){ return; }
    var ok=await performAction('/api/admin/unban-ip', {ip:ip}, 'Firewall IP removed', function(payload){ return payload.message || ('Removed '+ip+' from the firewall.'); });
    if(ok){ await openIpDetailModal(ip); }
    return;
  }
  var duration=parseInt(getConfigValue('firewall.ipset.default_ban_duration',0),10);
  if(!Number.isFinite(duration)||duration<0){ duration=0; }
  var ok=await performAction('/api/admin/ban-ip', {ip:ip, duration:duration, reason:'[ADMIN] Ban from IP detail modal'}, 'Firewall IP banned', function(payload){ return payload.message || ('Added '+ip+' to firewall bans.'); });
  if(ok){ await openIpDetailModal(ip); }
}
async function runIpDetailReportAndBan(){
  var ip=String(state.ipDetailIp||'').trim();
  if(!ip){ return; }
  if(!confirm('Report and ban this IP now?')){ return; }
  var duration=parseInt(getConfigValue('firewall.ipset.default_ban_duration',0),10);
  if(!Number.isFinite(duration)||duration<0){ duration=0; }
  handleUserActivity();
  var ok=await performAction('/api/admin/report-and-ban', {ip:ip, duration:duration, reason:'[ADMIN] Report+Ban from IP detail modal'}, 'Report + ban completed', function(payload){ return payload.message || ('Processed report+ban for '+ip+'.'); });
  if(ok){ await openIpDetailModal(ip); }
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
function flattenConfigEntries(node, prefix, output){
  var path=String(prefix||'');
  if(Array.isArray(node) || node===null || typeof node!=='object'){
    if(path){ output.push({path:path, value:node}); }
    return;
  }
  Object.keys(node).sort().forEach(function(key){
    var nextPath=path?path+'.'+key:key;
    flattenConfigEntries(node[key], nextPath, output);
  });
}
function isManagedConfigPath(path){
  var managed={
    'general.log_level':true,
    'general.analysis_interval':true,
    'successful_logins.enabled':true,
    'successful_logins.reset_risk_score':true,
    'dashboard.public_dashboard':true,
    'dashboard.session_ttl':true,
    'dashboard.login_rate_limit_per_minute':true,
    'firewall.simulation_mode':true,
    'firewall.ban_threshold':true,
    'firewall.ipset.default_ban_duration':true,
    'notifications.telegram.enabled':true,
    'notifications.telegram.chat_id':true,
    'notifications.discord.enabled':true,
    'notifications.discord.webhook_url':true,
    'notifications.rules.on_ban':true,
    'notifications.rules.on_burst':true,
    'notifications.rules.on_manual_ban':true,
    'notifications.rules.min_risk_score':true,
    'plugins.ssh.enabled':true,
    'plugins.minecraft.enabled':true,
    'plugins.minecraft.global_connection_burst_threshold':true,
    'plugins.minecraft.global_connection_burst_window_seconds':true,
    'plugins.portscan.ignored_ports':true
  };
  return !!managed[String(path||'')];
}
function renderAllConfigControls(){
  var host=$('#cfgAllSettings');
  if(!host){ return; }
  var entries=[];
  flattenConfigEntries(state.config||{}, '', entries);
  entries=entries.filter(function(entry){ return !isManagedConfigPath(entry.path); });
  if(!entries.length){
    host.innerHTML='<div class="empty">No config keys found.</div>';
    return;
  }
  var groups={};
  entries.forEach(function(entry){
    var path=String(entry.path||'');
    var root=path.indexOf('.')===-1?path:path.split('.')[0];
    if(!groups[root]){ groups[root]=[]; }
    groups[root].push(entry);
  });
  function renderEntryControl(entry){
    var path=String(entry.path||'');
    var value=entry.value;
    var kind=Array.isArray(value)?'array':(value===null?'null':typeof value);
    if(kind==='boolean'){
      return '<label class="config-kv-toggle"><div><div class="config-kv-path">'+E(path)+'</div><div class="sub">boolean</div></div><input type="checkbox" data-allcfg-path="'+E(path)+'" data-allcfg-kind="boolean" '+(value?'checked':'')+'></label>';
    }
    if(kind==='number'){
      return '<div class="config-kv-item"><div class="config-kv-top"><div class="config-kv-path">'+E(path)+'</div><span class="config-kv-kind">number</span></div><input class="config-input" type="number" data-allcfg-path="'+E(path)+'" data-allcfg-kind="number" value="'+E(String(value))+'"></div>';
    }
    if(kind==='array'){
      var rawArray=JSON.stringify(value);
      return '<div class="config-kv-item"><div class="config-kv-top"><div class="config-kv-path">'+E(path)+'</div><span class="config-kv-kind">array</span></div><textarea class="config-editor" rows="3" style="min-height:88px" data-allcfg-path="'+E(path)+'" data-allcfg-kind="json">'+E(rawArray)+'</textarea></div>';
    }
    if(kind==='null'){
      return '<div class="config-kv-item"><div class="config-kv-top"><div class="config-kv-path">'+E(path)+'</div><span class="config-kv-kind">null</span></div><input class="config-input" type="text" data-allcfg-path="'+E(path)+'" data-allcfg-kind="null-or-string" value="" placeholder="Leave empty to keep null"></div>';
    }
    return '<div class="config-kv-item"><div class="config-kv-top"><div class="config-kv-path">'+E(path)+'</div><span class="config-kv-kind">string</span></div><input class="config-input" type="text" data-allcfg-path="'+E(path)+'" data-allcfg-kind="string" value="'+E(String(value||''))+'"></div>';
  }
  var roots=Object.keys(groups).sort();
  host.innerHTML=roots.map(function(root,index){
    var items=groups[root].slice().sort(function(a,b){ return String(a.path||'').localeCompare(String(b.path||'')); });
    var isOpen=index===0;
    return '<section class="config-group'+(isOpen?' open':'')+'"><button type="button" class="config-group-toggle" data-group-toggle aria-expanded="'+(isOpen?'true':'false')+'"><span>'+E(root||'root')+'</span><span style="display:inline-flex;align-items:center;gap:10px"><span class="config-group-count">'+N(items.length)+' keys</span><span class="config-group-sign">'+(isOpen?'-':'+')+'</span></span></button><div class="config-group-body">'+items.map(renderEntryControl).join('')+'</div></section>';
  }).join('');
}
function bindAllSettingsGroupToggles(){
  var host=$('#cfgAllSettings');
  if(!host){ return; }
  host.addEventListener('click', function(ev){
    var btn=ev.target.closest('[data-group-toggle]');
    if(!btn){ return; }
    var group=btn.closest('.config-group');
    if(!group){ return; }
    var open=!group.classList.contains('open');
    group.classList.toggle('open', open);
    btn.setAttribute('aria-expanded', open?'true':'false');
    var sign=btn.querySelector('.config-group-sign');
    if(sign){ sign.textContent=open?'-':'+'; }
  });
}
function collectAllConfigControlChanges(){
  var controls=Array.from(document.querySelectorAll('[data-allcfg-path]'));
  var changes={};
  controls.forEach(function(control){
    var path=String(control.getAttribute('data-allcfg-path')||'').trim();
    var kind=String(control.getAttribute('data-allcfg-kind')||'string');
    if(!path){ return; }
    if(isManagedConfigPath(path)){ return; }
    if(kind==='boolean'){
      changes[path]=!!control.checked;
      return;
    }
    var raw=String(control.value||'');
    if(kind==='number'){
      if(raw.trim()===''){
        var existingNumber=getConfigValue(path, 0);
        changes[path]=Number.isFinite(existingNumber)?existingNumber:Number(existingNumber)||0;
        return;
      }
      var parsed=Number(raw);
      if(!Number.isFinite(parsed)){ throw new Error('Invalid number for '+path); }
      changes[path]=parsed;
      return;
    }
    if(kind==='json'){
      if(raw.trim()===''){
        var existingList=getConfigValue(path, []);
        changes[path]=Array.isArray(existingList)?existingList:[];
        return;
      }
      try{
        changes[path]=raw.trim()?JSON.parse(raw):[];
      }catch(error){
        var fallbackItems=raw.split(/\r?\n|,/).map(function(item){ return String(item||'').trim(); }).filter(Boolean).map(function(item){
          return /^\d+$/.test(item) ? parseInt(item,10) : item;
        });
        if(!fallbackItems.length){ throw new Error('Invalid JSON array for '+path); }
        changes[path]=fallbackItems;
      }
      return;
    }
    if(kind==='null-or-string'){
      changes[path]=raw.trim()===''?null:raw;
      return;
    }
    changes[path]=raw;
  });
  return changes;
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
  var runtimeSimulation = isSimulationEnabled(state.stats&&state.stats.simulation_mode);
  var configSimulation = isSimulationEnabled(getConfigValue('firewall.simulation_mode', runtimeSimulation));
  var simulation = configSimulation;
  $('#mEvents').textContent = N(state.stats&&state.stats.total_events);
  $('#mDbBans').textContent = N(state.stats&&state.stats.active_bans);
  var fwCount = (state.stats&&state.stats.firewall_active_bans!==undefined&&state.stats.firewall_active_bans!==null) ? state.stats.firewall_active_bans : state.firewall.length;
  $('#mFwBans').textContent = N(fwCount);
  $('#mPeers').textContent = state.blocklist&&state.blocklist.enabled ? (state.blocklist.first_setup&&state.blocklist.first_setup.completed?'Active Only':'First Setup + Active') : 'Disabled';
  $('#runtimeMode').textContent = 'Mode: '+(simulation?'Monitor':'Live');
  $('#runtimeUptime').textContent = 'Service: '+((state.health&&state.health.uptime)||'--')+' | System: '+((state.health&&state.health.system_uptime)||'--');
  $('#lastUpdated').textContent = 'Last updated: '+new Date().toLocaleTimeString();
  var simNotice = $('#simulationTopNotice');
  if(runtimeSimulation!==configSimulation){
    simNotice.hidden = false;
    simNotice.textContent = 'Simulation mode config changed. Runtime mode will sync after refresh/reload.';
  }else{
    simNotice.hidden = !simulation;
    simNotice.textContent = 'Monitor Mode active — events are recorded but no firewall actions applied. Disable to switch to enforcement.';
  }
  $('#enforceSimBansBtn').hidden = !simulation;
}
function renderEvents(){
  var simulation = isSimulationEnabled(state.stats&&state.stats.simulation_mode);
  var rows=state.events.slice(); var q=filterText(); var plugin=$('#eventPluginFilter').value; var threat=$('#eventThreatFilter').value; var country=$('#eventCountryFilter').value; var banState=$('#eventBanStateFilter').value||'all';
  rows=rows.filter(function(e){ var effectiveThreat=(e.threat_label||e.threat_level||'NONE').toUpperCase(); var eventCountry=String(e.country_code||'').toUpperCase(); var isBanPhase=!!(e.is_post_ban||e.is_ban_trigger_event||e.is_firewall_blocked); var blob=[e.source_ip,e.connection_type,e.threat_level,e.threat_label,e.asn_org,e.asn_number,e.player_name,eventCountry,e.ban_state].join(' ').toLowerCase(); return (!q||blob.indexOf(q)!==-1)&&(!plugin||e.connection_type===plugin)&&(!threat||effectiveThreat===threat)&&(!country||eventCountry===country)&&((banState==='all')||(banState==='preban'?!isBanPhase:isBanPhase)); });
  rows.sort(function(a,b){
    var ta=Date.parse(String(a.timestamp||'')); var tb=Date.parse(String(b.timestamp||''));
    if(Number.isFinite(ta)&&Number.isFinite(tb)&&ta!==tb){ return tb-ta; }
    return (Number(b.id)||0)-(Number(a.id)||0);
  });
  $('#eventsRows').innerHTML = rows.length ? rows.map(function(e){ var advice=e.operator_advice||'No specific operator advice for this event.'; if(simulation){ advice += ' Monitor mode is active, so no firewall blocking is applied.'; } var cc=(e.country_code||'').toUpperCase(); var country=cc?cc:'-'; var threatLabel=(e.threat_label||e.threat_level||'NONE').toUpperCase(); var rawAsnNum=String(e.asn_number||'').trim(); var asnNum=rawAsnNum ? ('AS'+rawAsnNum.replace(/^AS/i,'')) : ''; var asnOrg=String(e.asn_org||'').trim(); var asnText=asnOrg||asnNum||'-'; if(asnNum&&asnOrg){ asnText=asnNum+' · '+asnOrg; } var asnBadge=e.is_suspicious_asn?'<span class="badge susp" title="Suspicious ASN">⚠</span> ':''; var asnTitle=asnText+(e.is_suspicious_asn?' (Suspicious ASN)':''); var src=String(e.source_ip||'-'); var rowClass=e.is_ban_trigger_event?'ev-row-ban-trigger':(e.is_post_ban?'ev-row-post-ban':(e.is_firewall_blocked?'ev-row-firewall':'')); var bannedBadge=''; if(e.is_ban_trigger_event){ bannedBadge='<span class="tag t-red" style="margin-left:6px">BANNED NOW</span>'; } else if(e.is_post_ban){ bannedBadge='<span class="tag t-red" style="margin-left:6px">BANNED</span>'; } else if(e.is_firewall_blocked){ bannedBadge='<span class="tag t-yellow" style="margin-left:6px">FIREWALL</span>'; } var sourceHtml=src==='-'?'-':'<button class="ip-link-btn" data-ip="'+E(src)+'" title="Open IP details">'+E(src)+'</button>'+bannedBadge; var pluginName=String((e.connection_type||'unknown')).toUpperCase(); var port=detectPortFromEvent(e); var pluginLabel=(port&&String(e.connection_type||'').toLowerCase()==='portscan')?(pluginName+' · Port '+port):pluginName; return '<tr class="'+rowClass+'"><td>'+ago(e.timestamp_unix||e.timestamp)+'</td><td>'+sourceHtml+'</td><td>'+E(pluginLabel)+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(country)+'">'+E(country)+'</td><td><span class="tag '+tagRisk(e.risk_score||0)+'">'+E(String(e.risk_score||0))+'</span></td><td><span class="tag '+tagThreat(threatLabel)+'">'+E(threatLabel)+'</span></td><td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(asnTitle)+'">'+asnBadge+E(asnText)+'</td><td><span class="advice-tip" title="'+E(advice)+'">i</span></td></tr>'; }).join('') : '<tr><td colspan="8" class="empty">No events match the current filters.</td></tr>';
}
function renderWhitelistSnapshot(){
  var target=$('#whitelistRows');
  var ips=(state.whitelist&&state.whitelist.ips)||[];
  var cidrs=(state.whitelist&&state.whitelist.cidr_ranges)||[];
  var rows=[];
  ips.forEach(function(item){ rows.push({type:'IP', value:String(item||'').trim()}); });
  cidrs.forEach(function(item){ rows.push({type:'CIDR', value:String(item||'').trim()}); });
  rows=rows.filter(function(item){ return !!item.value; });
  rows.sort(function(a,b){ return a.value.localeCompare(b.value); });
  target.innerHTML=rows.length ? rows.map(function(item){ return '<tr><td>'+E(item.type)+'</td><td class="mono">'+E(item.value)+'</td></tr>'; }).join('') : '<tr><td colspan="2" class="empty">No custom whitelist entries found.</td></tr>';
}
async function loadWhitelist(){
  var payload=await api('/api/admin/whitelist');
  if(!payload){ return false; }
  state.whitelist={
    ips:Array.isArray(payload.ips)?payload.ips:[],
    cidr_ranges:Array.isArray(payload.cidr_ranges)?payload.cidr_ranges:[]
  };
  renderWhitelistSnapshot();
  return true;
}
function closeIpDetailModal(){
  state.ipDetailOpen=false;
  state.ipDetailIp='';
  $('#ipDetailModal').hidden=true;
  document.body.style.overflow='';
}
async function openIpDetailModal(ip){
  var sourceIp=String(ip||'').trim();
  if(!sourceIp){ return; }
  state.ipDetailOpen=true;
  state.ipDetailIp=sourceIp;
  $('#ipDetailTitle').textContent='IP Activity: '+sourceIp;
  $('#ipDetailMeta').textContent='Loading recent records for this source...';
  $('#ipIntelAddress').textContent=sourceIp;
  $('#ipIntelAsn').textContent='-';
  $('#ipIntelCompany').textContent='-';
  $('#ipIntelCountry').textContent='-';
  $('#ipIntelFirstSeen').textContent='-';
  $('#ipIntelLastSeen').textContent='-';
  $('#ipIntelSource').textContent='-';
  $('#ipIntelConfidence').textContent='-';
  $('#ipDetailEventCount').textContent='0';
  $('#ipDetailBanCount').textContent='0';
  $('#ipDetailActiveBanCount').textContent='0';
  $('#ipDetailFirewallState').textContent='--';
  $('#ipDetailRows').innerHTML='<tr><td colspan="5" class="empty">Loading...</td></tr>';
  syncIpDetailActionButtons();
  $('#ipDetailModal').hidden=false;
  document.body.style.overflow='hidden';

  var payload=await api('/api/admin/query-records', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({field:'ip', value:sourceIp, limit:150})
  });
  if(!payload){
    $('#ipDetailMeta').textContent='Could not load IP activity data.';
    $('#ipDetailRows').innerHTML='<tr><td colspan="5" class="empty">Request failed.</td></tr>';
    return;
  }

  var records=Array.isArray(payload.records)?payload.records:[];
  var eventRows=records.filter(function(r){ return r&&r.kind==='event'; });
  var banRows=records.filter(function(r){ return r&&r.kind==='ban'; });
  var activeBanCount=banRows.filter(function(r){ return !!r.is_active; }).length;
  var firewallState=isIpBannedInFirewall(sourceIp) ? 'Active' : 'Not active';
  $('#ipDetailEventCount').textContent=N(eventRows.length);
  $('#ipDetailBanCount').textContent=N(banRows.length);
  $('#ipDetailActiveBanCount').textContent=N(activeBanCount);
  $('#ipDetailFirewallState').textContent=firewallState;
  syncIpDetailActionButtons();

  var firstSeen='-';
  var lastSeen='-';
  var firstSeenLabel='-';
  var lastSeenLabel='-';
  if(records.length){
    var unixValues=records.map(function(r){ return parseTs(r.timestamp); }).filter(function(v){ return v!==null; }).sort(function(a,b){ return a-b; });
    if(unixValues.length){
      firstSeen=ago(unixValues[0]);
      lastSeen=ago(unixValues[unixValues.length-1]);
      firstSeenLabel=new Date(unixValues[0]).toLocaleString();
      lastSeenLabel=new Date(unixValues[unixValues.length-1]).toLocaleString();
    }
  }
  $('#ipDetailMeta').textContent='Events: '+N(eventRows.length)+' · Ban records: '+N(banRows.length)+' · First seen: '+firstSeen+' ago · Last seen: '+lastSeen+' ago';

  var asnCounter={};
  var companyCounter={};
  var countryCounter={};
  eventRows.forEach(function(item){
    var asnRaw=String(item.asn_number||'').trim();
    var asn=asnRaw ? ('AS'+asnRaw.replace(/^AS/i,'')) : '';
    var company=String(item.asn_org||'').trim();
    var country=String(item.country_code||'').trim().toUpperCase();
    if(asn){ asnCounter[asn]=(asnCounter[asn]||0)+1; }
    if(company){ companyCounter[company]=(companyCounter[company]||0)+1; }
    if(country){ countryCounter[country]=(countryCounter[country]||0)+1; }
  });
  function topKey(counter){ var keys=Object.keys(counter||{}); if(!keys.length){ return '-'; } keys.sort(function(a,b){ return (counter[b]||0)-(counter[a]||0); }); return keys[0]; }
  $('#ipIntelAsn').textContent=topKey(asnCounter);
  $('#ipIntelCompany').textContent=topKey(companyCounter);
  $('#ipIntelCountry').textContent=topKey(countryCounter);
  $('#ipIntelFirstSeen').textContent=firstSeenLabel;
  $('#ipIntelLastSeen').textContent=lastSeenLabel;
  $('#ipIntelSource').textContent='Derived from DB query records';
  var confidence='Low';
  if(eventRows.length>=5){
    var topCompany=topKey(companyCounter);
    var topCompanyCount=topCompany==='-'?0:(companyCounter[topCompany]||0);
    var ratio=eventRows.length?topCompanyCount/eventRows.length:0;
    if(ratio>=0.75){ confidence='High'; }
    else if(ratio>=0.45){ confidence='Medium'; }
  }
  $('#ipIntelConfidence').textContent=confidence+' ('+N(eventRows.length)+' records)';

  if(!records.length){
    $('#ipDetailRows').innerHTML='<tr><td colspan="5" class="empty">No historical records for this IP.</td></tr>';
    return;
  }

  $('#ipDetailRows').innerHTML=records.map(function(row){
    var kind=String(row.kind||'event').toUpperCase();
    if(kind==='BAN'){
      var duration=(Number(row.ban_duration||0)>0)?(String(row.ban_duration)+'s'):'Permanent';
      var reason=String(row.reason||'-');
      var status=row.is_active?'Active':'Inactive';
      return '<tr><td>'+ago(row.timestamp)+'</td><td><span class="row-kind ban">BAN</span></td><td>'+E(status)+'</td><td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(reason)+'">'+E(reason)+'</td><td>'+E(duration)+'</td></tr>';
    }
    var plugin=String(row.connection_type||'-').toUpperCase();
    var eventType=String(row.event_type||'').toUpperCase();
    var pluginText=eventType?plugin+' / '+eventType:plugin;
    var eventPort=detectPortFromEvent(row);
    if(eventPort && String(row.connection_type||'').toLowerCase()==='portscan'){
      pluginText += ' · Port '+eventPort;
    }
    var threat=String(row.threat_level||'-').toUpperCase();
    return '<tr><td>'+ago(row.timestamp)+'</td><td><span class="row-kind event">EVENT</span></td><td>'+E(pluginText)+'</td><td>'+E(threat)+'</td><td>'+E(String(row.risk_score||0))+'</td></tr>';
  }).join('');
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
      var port=detectPortFromEvent(r);
      var bits=[r.connection_type||'-', r.event_type||'', port?('port '+port):'', r.player_name||'', r.asn_org||''];
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
function parseBulkCategories(raw){
  var seen={};
  return String(raw||'').split(/[\s,]+/).map(function(item){ return item.trim(); }).filter(Boolean).map(function(item){ return parseInt(item,10); }).filter(function(num){
    if(!Number.isFinite(num) || num<1 || num>24 || seen[num]){ return false; }
    seen[num]=true;
    return true;
  });
}
function closeBulkResultModal(){
  $('#bulkResultModal').hidden=true;
  document.body.style.overflow='';
}
function filterBulkResults(results, filter){
  var mode=String(filter||'all');
  if(mode==='failed'){
    return results.filter(function(item){ return !item.ok; });
  }
  if(mode==='report_skipped'){
    return results.filter(function(item){ return !item.reported; });
  }
  if(mode==='reported_success'){
    return results.filter(function(item){ return !!item.reported; });
  }
  return results;
}
function renderBulkResultModal(){
  var payload=state.bulkResultPayload||{};
  var results=Array.isArray(payload.results)?payload.results:[];
  var total=Number(payload.total||results.length||0);
  var success=Number(payload.success||0);
  var failed=Number(payload.failed||Math.max(total-success,0));
  var banApplied=Number(payload.ban_applied||0);
  var reported=Number(payload.reported||0);
  var action=String(payload.action||'bulk');
  var categories=Array.isArray(payload.categories)?payload.categories:[];
  $('#bulkResultMeta').textContent='Action: '+action+' · Categories: '+(categories.length?categories.join(','):'-');
  $('#bulkResultSummary').innerHTML=''
    +'<div class="intel-item"><span class="k">Total</span><span class="v">'+N(total)+'</span></div>'
    +'<div class="intel-item"><span class="k">Success</span><span class="v" style="color:var(--green)">'+N(success)+'</span></div>'
    +'<div class="intel-item"><span class="k">Failed</span><span class="v" style="color:var(--red)">'+N(failed)+'</span></div>'
    +'<div class="intel-item"><span class="k">Ban Applied</span><span class="v">'+N(banApplied)+'</span></div>'
    +'<div class="intel-item"><span class="k">Reported</span><span class="v">'+N(reported)+'</span></div>';
  var filter=$('#bulkResultFilter') ? $('#bulkResultFilter').value : 'all';
  var visible=filterBulkResults(results, filter);
  $('#bulkResultFilterMeta').textContent='Showing '+N(visible.length)+'/'+N(results.length)+' rows.';
  $('#bulkResultRows').innerHTML=visible.length?visible.map(function(item){
    var ok=!!item.ok;
    var ban=!!item.ban_applied;
    var rep=!!item.reported;
    return '<tr>'
      +'<td class="mono">'+E(String(item.ip||'-'))+'</td>'
      +'<td><span class="row-kind '+(ok?'ok':'fail')+'">'+(ok?'SUCCESS':'FAILED')+'</span></td>'
      +'<td><span class="row-kind '+(ban?'ok':'fail')+'">'+(ban?'YES':'NO')+'</span></td>'
      +'<td><span class="row-kind '+(rep?'ok':'fail')+'">'+(rep?'SUCCESS':'SKIPPED')+'</span></td>'
      +'<td style="max-width:460px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(String(item.message||''))+'">'+E(String(item.message||'-'))+'</td>'
      +'</tr>';
  }).join(''):'<tr><td colspan="5" class="empty">No per-IP results returned.</td></tr>';
}
function openBulkResultModal(payload){
  state.bulkResultPayload=payload||{};
  if($('#bulkResultFilter')){ $('#bulkResultFilter').value='all'; }
  renderBulkResultModal();
  $('#bulkResultModal').hidden=false;
  document.body.style.overflow='hidden';
}
async function runBulkIpAction(){
  var action=String($('#bulkActionType').value||'ban');
  var lines=String($('#bulkIpLines').value||'').trim();
  if(!lines){
    setStatus('err','Missing bulk lines','Add one IP per line before running bulk action.');
    return;
  }
  var reason=String($('#bulkReason').value||'').trim();
  var duration=parseInt($('#bulkDuration').value,10);
  if(!Number.isFinite(duration)||duration<0){ duration=parseInt(getConfigValue('firewall.ipset.default_ban_duration',0),10); }
  if(!Number.isFinite(duration)||duration<0){ duration=0; }
  var categories=parseBulkCategories($('#bulkCategories').value);
  if((action==='report' || action==='report_and_ban') && !categories.length){ categories=[14]; }
  var respectRateLimit=!!($('#bulkRespectRateLimit')&&$('#bulkRespectRateLimit').checked);
  var reportIntervalMs=parseInt(($('#bulkReportIntervalMs')||{value:'2200'}).value,10);
  if(!Number.isFinite(reportIntervalMs) || reportIntervalMs<500){ reportIntervalMs=2200; }
  var payload=await api('/api/admin/bulk-ip-action', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      action:action,
      lines:lines,
      reason:reason,
      duration:duration,
      categories:categories,
      respect_report_rate_limit: respectRateLimit,
      report_interval_ms: reportIntervalMs
    })
  });
  if(!payload){ return; }
  var message='Action: '+String(payload.action||action)+' · Success '+N(payload.success||0)+'/'+N(payload.total||0)+' · Ban '+N(payload.ban_applied||0)+' · Report '+N(payload.reported||0);
  if((payload.categories||[]).length){ message += ' · Categories: '+(payload.categories||[]).join(','); }
  var failedRows=(payload.results||[]).filter(function(item){ return !item.ok; }).slice(0,4);
  if(failedRows.length){
    message += ' · Failed: '+failedRows.map(function(item){ return String(item.ip||'?')+' ('+String(item.message||'skipped')+')'; }).join('; ');
  }
  setStatus((payload.failed||0)>0?'err':'ok','Bulk action completed', message);
  openBulkResultModal(payload);
  await refresh();
}
function renderTopPortscannedPorts(){
  var allPorts=Array.isArray(state.topPorts)?state.topPorts:[];
  var limit=state.topPortsExpanded?allPorts.length:8;
  var visible=allPorts.slice(0,limit);
  $('#topPortsList').innerHTML = visible.length ? visible.map(function(p){ var hp=p.is_honeypot?'<span class="tag t-yellow" style="margin-left:8px">HONEYPOT</span>':''; return '<div class="list-item"><strong class="mono">Port '+E(String(p.port||'-'))+hp+'</strong><div class="sub">Scans: '+N(p.scan_count||0)+' · Last seen: '+ago(p.last_seen)+'</div></div>'; }).join('') : '<div class="empty">No portscan history yet.</div>';
  var btn=$('#topPortsToggleBtn');
  if(!btn){ return; }
  if(allPorts.length<=8){
    btn.hidden=true;
    return;
  }
  btn.hidden=false;
  btn.textContent=state.topPortsExpanded?'Show Less':'Show More';
}
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
function renderBlocklistAdmin(){ var bl=state.blocklist; if(!bl||!bl.enabled){ $('#meshList').innerHTML='<div class="empty">Blocklist protection is disabled.</div>'; return; } var items=[]; if(bl.first_setup){ var fsLoaded=Number(bl.first_setup.ips_loaded||0); var activeLoaded=Number(bl.active&&bl.active.total_ips_loaded||0); var loadedLabel=fsLoaded>0?N(fsLoaded):(activeLoaded>0?('0 (initial pass) · active list '+N(activeLoaded)):'0'); items.push('<div class="list-item"><strong>First Setup ('+E(bl.first_setup.mode)+')</strong><div class="sub">Status: '+(bl.first_setup.completed?'Completed':'Active — '+E(bl.first_setup.remaining||'unknown')+' remaining')+' · IPs loaded: '+loadedLabel+'</div></div>'); } if(bl.active){ items.push('<div class="list-item"><strong>Active Blocklist</strong><div class="sub">Total IPs loaded: '+N(bl.active.total_ips_loaded||0)+' · Last fetch: '+ago(bl.active.last_fetch_at)+' · Last count: '+N(bl.active.last_fetch_count||0)+'</div></div>'); } if(bl.last_error){ items.push('<div class="list-item"><strong>Last Error</strong><div class="sub">'+E(bl.last_error)+'</div></div>'); } $('#meshList').innerHTML=items.join('')||'<div class="empty">Blocklist enabled, awaiting first fetch.</div>'; }
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
  renderAllConfigControls();
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
  try{
    Object.assign(changes, collectAllConfigControlChanges());
  }catch(error){
    setStatus('err','Invalid config input', error && error.message ? error.message : 'Please check your config inputs.');
    return false;
  }
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
  if((stats.active_bans||0)>0&&state.firewall.length===0){ items.push({title:'Database bans do not match firewall entries', body:'This can be expected in simulation mode. In live mode, check firewall permissions or service startup ordering.'}); }
  if(highRiskEvents>=10){ items.push({title:'High-risk event volume is elevated', body:'Review recent events and confirm whitelist coverage before tightening thresholds further.'}); }
  if(state.blocklist&&state.blocklist.last_error){ items.push({title:'Blocklist fetch encountered an error', body:'Check the configured URLs and network connectivity. Error: '+(state.blocklist.last_error||'unknown')}); }
  if(!items.length){ items.push({title:'No immediate operator action suggested', body:'The current snapshot looks stable. Continue monitoring the live event stream.'}); }
  $('#adviceList').innerHTML=items.map(function(item){ return '<div class="advice-item"><strong>'+E(item.title)+'</strong><div class="sub">'+E(item.body)+'</div></div>'; }).join('');
}
function syncPluginFilter(){ var select=$('#eventPluginFilter'); var current=select.value; var values=Array.from(new Set(state.events.map(function(e){ return e.connection_type||'unknown'; }))).sort(); select.innerHTML='<option value="">All Plugins</option>'+values.map(function(v){ return '<option value="'+E(v)+'">'+E(v.toUpperCase())+'</option>'; }).join(''); select.value=values.indexOf(current)!==-1?current:''; }
function syncCountryFilter(){ var select=$('#eventCountryFilter'); var current=select.value; var values=Array.from(new Set(state.events.map(function(e){ return String(e.country_code||'').toUpperCase(); }).filter(function(v){ return v && v!=='ZZ'; }))).sort(); select.innerHTML='<option value="">All Countries</option>'+values.map(function(v){ return '<option value="'+E(v)+'">'+E(v)+'</option>'; }).join(''); select.value=values.indexOf(current)!==-1?current:''; }
async function refresh(){
  var adminPortsHours=parseInt(($('#adminAtTimeRange')||{value:'24'}).value,10)||0;
  state.adminIncludeHoneypot=!!($('#adminIncludeHoneypot')&&$('#adminIncludeHoneypot').checked);
  var portsQuery='/api/top-portscanned-ports?limit=12'+(adminPortsHours>0?'&hours='+adminPortsHours:'')+(state.adminIncludeHoneypot?'':'&include_honeypot=0');
  var results = await Promise.all([api('/api/health'),api('/api/stats'),api('/api/events?limit=120'),api('/api/bans'),api('/api/firewall-bans?limit=1000'),api(portsQuery),api('/api/blocklist')]);
  if(results.some(function(item){ return item===null; })){ return; }
  state.health=results[0]||null; state.stats=results[1]||null; state.events=results[2]&&results[2].events?results[2].events:[]; state.bans=results[3]&&results[3].bans?results[3].bans:[]; state.firewall=results[4]&&results[4].items?results[4].items:[]; state.topPorts=results[5]&&results[5].ports?results[5].ports:[]; state.blocklist=results[6]||null;
  syncPluginFilter(); syncCountryFilter(); renderSummary(); renderEvents(); renderBans(); renderFirewall(); renderTopPortscannedPorts(); renderBlocklistAdmin(); renderAdvice();
}
async function performAction(path, body, successTitle, successMessage){ var payload = await api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{})}); if(!payload){ return false; } setStatus('ok', successTitle, successMessage(payload)); await refresh(); return true; }
async function logout(message){ clearInterval(timer); clearTimeout(idleTimer); await fetch('/api/logout', {method:'POST'}).catch(function(){}); if(message){ sessionStorage.setItem('wardenips_logout_message', message); } window.location.href='/login?next=/admin'; }
function bindActivity(){ ['mousemove','mousedown','keydown','scroll','touchstart','click'].forEach(function(name){ document.addEventListener(name, function(){ debounce('activity', handleUserActivity, 150); }, {passive:true}); }); resetIdleTimer(); }
function bind(){
  ['globalSearch','eventPluginFilter','eventThreatFilter','eventCountryFilter','eventBanStateFilter','banSort','ipFamilyFilter','manualIp','manualWhitelist','manualBanIp','manualBanDuration','manualBanReason','cfgPortscanIgnoredPortsEntry','bulkReason','bulkCategories'].forEach(function(id){ $('#'+id).addEventListener('input', function(){ debounce(id, function(){ renderEvents(); renderBans(); renderFirewall(); }, 220); }); $('#'+id).addEventListener('change', function(){ debounce(id+'-change', function(){ renderEvents(); renderBans(); renderFirewall(); }, 120); }); });
  $('#themeToggle').addEventListener('click', function(){ applyTheme(state.theme==='dark' ? 'light' : 'dark'); });
  $('#dismissUpdateNoticeBtn').addEventListener('click', function(){ var info=state.updateInfo; var key=getDismissKey(info); if(key){ try{ localStorage.setItem(key,'1'); }catch(error){} } $('#updateNotice').hidden=true; });
  $('#openConfigBtn').addEventListener('click', function(){ handleUserActivity(); openConfigModal(); });
  $('#refreshWhitelistBtn').addEventListener('click', async function(){ handleUserActivity(); var ok=await loadWhitelist(); if(ok){ setStatus('ok','Whitelist refreshed','Current whitelist entries were loaded.'); } });
  $('#configSectionSearch').addEventListener('input', function(){ debounce('config-search', filterConfigSections, 120); });
  $('#closeConfigBtn').addEventListener('click', function(){ closeConfigModal(); });
  $('#closeIpDetailBtn').addEventListener('click', function(){ closeIpDetailModal(); });
  $('#closeBulkResultBtn').addEventListener('click', function(){ closeBulkResultModal(); });
  $('#bulkResultFilter').addEventListener('change', function(){ renderBulkResultModal(); });
  $('#ipDetailToggleBanBtn').addEventListener('click', async function(){ await runIpDetailToggleBan(); });
  $('#ipDetailReportBanBtn').addEventListener('click', async function(){ await runIpDetailReportAndBan(); });
  $('#configModal').addEventListener('click', function(ev){ if(ev.target===this){ closeConfigModal(); } });
  $('#ipDetailModal').addEventListener('click', function(ev){ if(ev.target===this){ closeIpDetailModal(); } });
  $('#bulkResultModal').addEventListener('click', function(ev){ if(ev.target===this){ closeBulkResultModal(); } });
  document.addEventListener('keydown', function(ev){ if(ev.key==='Escape' && !$('#configModal').hidden){ closeConfigModal(); } if(ev.key==='Escape' && !$('#ipDetailModal').hidden){ closeIpDetailModal(); } if(ev.key==='Escape' && !$('#bulkResultModal').hidden){ closeBulkResultModal(); } });
  $('#refreshNow').addEventListener('click', function(){ handleUserActivity(); refresh(); });
  $('#logoutBtn').addEventListener('click', function(){ logout('Logged out successfully.'); });
  $('#refreshRate').addEventListener('change', function(){ if(timer){ clearInterval(timer); } timer = setInterval(refresh, parseInt(this.value,10)||1000); });
  $('#topPortsToggleBtn').addEventListener('click', function(){ state.topPortsExpanded=!state.topPortsExpanded; renderTopPortscannedPorts(); });
    $('#adminAtTimeRange').addEventListener('change', function(){ handleUserActivity(); refresh(); });
  $('#adminIncludeHoneypot').addEventListener('change', function(){ handleUserActivity(); refresh(); });
  $('#queryRunBtn').addEventListener('click', async function(){ handleUserActivity(); await runRecordQuery(); });
  $('#queryValue').addEventListener('keydown', async function(ev){ if(ev.key==='Enter'){ ev.preventDefault(); handleUserActivity(); await runRecordQuery(); } });
  $('#bulkActionBtn').addEventListener('click', async function(){ handleUserActivity(); await runBulkIpAction(); });
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
  $('#addWhitelistBtn').addEventListener('click', async function(){ var value=$('#manualWhitelist').value.trim(); if(!value){ setStatus('err','Missing input','Enter an IP or CIDR before adding to whitelist.'); return; } handleUserActivity(); var ok=await performAction('/api/admin/whitelist/add', {value:value}, 'Whitelist updated', function(payload){ return payload.message || ('Added '+value+' to whitelist.'); }); if(ok){ await loadWhitelist(); } });
  $('#removeWhitelistBtn').addEventListener('click', async function(){ var value=$('#manualWhitelist').value.trim(); if(!value){ setStatus('err','Missing input','Enter an IP or CIDR before removing from whitelist.'); return; } handleUserActivity(); var ok=await performAction('/api/admin/whitelist/remove', {value:value}, 'Whitelist updated', function(payload){ return payload.message || ('Removed '+value+' from whitelist.'); }); if(ok){ await loadWhitelist(); } $('#manualWhitelist').value=''; });
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
  $('#eventsRows').addEventListener('click', async function(ev){ var button=ev.target.closest('.ip-link-btn'); if(!button){ return; } var ip=String(button.getAttribute('data-ip')||'').trim(); if(!ip){ return; } handleUserActivity(); await openIpDetailModal(ip); });
  $('#banRows').addEventListener('click', async function(ev){ var button = ev.target.closest('.ban-action'); if(!button){ return; } var sourceIp = button.getAttribute('data-ip'); if(!sourceIp || !confirm('Deactivate this database ban record?')){ return; } handleUserActivity(); await performAction('/api/admin/deactivate-ban', {source_ip:sourceIp}, 'Ban record updated', function(payload){ return 'Deactivated '+N(payload.updated||0)+' matching records.'; }); });
  $('#firewallRows').addEventListener('click', async function(ev){ var button = ev.target.closest('.fw-action'); if(!button){ return; } var ip = button.getAttribute('data-ip'); if(!ip || !confirm('Remove this IP from the firewall set?')){ return; } handleUserActivity(); await performAction('/api/admin/unban-ip', {ip:ip}, 'Firewall IP removed', function(payload){ return payload.message || ('Removed '+ip+' from the firewall.'); }); });
}
var flashMessage = sessionStorage.getItem('wardenips_logout_message'); if(flashMessage){ setStatus('ok','Session notice', flashMessage); sessionStorage.removeItem('wardenips_logout_message'); }
initTheme(); bind(); bindActivity(); loadConfig(); loadWhitelist(); loadAuthSettings(); loadUpdateStatus(); refresh(); timer=setInterval(refresh, parseInt($('#refreshRate').value,10)||1000);
bindAllSettingsGroupToggles();
})();
</script>
</body>
</html>"""
