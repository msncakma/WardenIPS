"""Auth and session handlers extracted from DashboardAPI monolith."""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timezone

from aiohttp import web

from wardenips.core.auth import verify_password, verify_totp_code


async def handle_login_page(api, request: web.Request) -> web.Response:
    if api._bootstrap_token_is_valid():
        raise web.HTTPFound("/setup")
    next_path = api._normalize_next_path(
        request.query.get("next", "/dashboard"),
        "/dashboard",
    )
    if api._is_session_authenticated(request):
        raise web.HTTPFound(next_path)
    auth_ready = await api._admin_auth_available()
    html = api.LOGIN_HTML.replace("__NEXT_PATH__", json.dumps(next_path))
    html = html.replace("__AUTH_READY__", "true" if auth_ready else "false")
    html = html.replace(
        "__PUBLIC_DASHBOARD_ENABLED__",
        "true" if api._public_dashboard_enabled else "false",
    )
    html = html.replace(
        "__SETUP_MESSAGE__",
        json.dumps(
            "No admin user exists yet. Complete the first-boot setup flow and create an admin account."
        ),
    )
    html = api._render_ui_template(html)
    return web.Response(text=html, content_type="text/html")


async def handle_setup_page(api, request: web.Request) -> web.Response:
    if not api._bootstrap_token_is_valid():
        raise web.HTTPFound("/login")
    html = api.SETUP_HTML.replace("__SETUP_EXPIRY__", json.dumps(api._bootstrap_token_expires_at or "24 hours"))
    html = api._render_ui_template(html)
    return web.Response(text=html, content_type="text/html")


async def handle_login(api, request: web.Request) -> web.Response:
    if api._bootstrap_token_is_valid():
        return web.json_response(
            {"error": "setup_required", "message": "Initial setup must be completed before login.", "redirect_to": "/setup"},
            status=403,
        )
    client_ip = api._client_ip(request)
    if api._consume_rate_limit(
        api._login_attempts,
        client_ip,
        api._login_rate_limit_per_minute,
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
    next_path = api._normalize_next_path(
        str(payload.get("next", "/dashboard")).strip() or "/dashboard",
        "/dashboard",
    )
    if not await api._admin_auth_available():
        return api._json_auth_error()
    user = await api._db.get_admin_user_by_username(username)
    if user:
        locked_until_raw = str(user.get("locked_until", "") or "").strip()
        if locked_until_raw:
            try:
                locked_until = datetime.fromisoformat(locked_until_raw.replace("Z", "+00:00"))
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=timezone.utc)
                if locked_until > datetime.now(timezone.utc):
                    await api._log_audit(
                        request,
                        "auth.login_failed",
                        actor_username=username or None,
                        details={"reason": "account_locked", "locked_until": locked_until.isoformat()},
                    )
                    return web.json_response(
                        {"error": "account_locked", "message": "Account is temporarily locked due to repeated failures."},
                        status=423,
                    )
            except Exception:
                pass

    if not user or not verify_password(str(user.get("password_hash", "")), password):
        if user:
            try:
                failed_count = int(user.get("failed_login_count", 0) or 0) + 1
            except Exception:
                failed_count = 1
            lock_seconds = 300 if failed_count >= 5 else 0
            await api._db.record_admin_failed_login(username, lock_seconds=lock_seconds)
        await api._log_audit(request, "auth.login_failed", actor_username=username or None, details={"reason": "invalid_credentials"})
        return web.json_response(
            {"error": "invalid_credentials", "message": "Invalid username or password."},
            status=401,
        )

    if int(user.get("totp_enabled", 0)):
        pending_token = secrets.token_urlsafe(24)
        api._pending_logins[pending_token] = {
            "username": user["username"],
            "next_path": next_path,
            "expires_at": time.time() + 300,
        }
        return web.json_response({"ok": True, "requires_totp": True, "pending_token": pending_token})

    response = web.json_response({"ok": True, "redirect_to": next_path})
    api._issue_session(response, request, username=user["username"])
    await api._db.record_admin_login(user["username"], client_ip)
    await api._log_audit(request, "auth.login_success", actor_username=user["username"], details={"method": "password_only"})
    return response


async def handle_login_totp(api, request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    pending_token = str(payload.get("pending_token", "")).strip()
    code = str(payload.get("totp_code", "")).strip()
    pending = api._pending_logins.get(pending_token)
    if not pending or float(pending.get("expires_at", 0)) <= time.time():
        api._pending_logins.pop(pending_token, None)
        return web.json_response({"error": "pending_auth_expired", "message": "The login challenge expired. Start again."}, status=401)
    username = str(pending.get("username", ""))
    user = await api._db.get_admin_user_by_username(username)
    if not user or not verify_totp_code(str(user.get("totp_secret", "")), code):
        await api._log_audit(request, "auth.totp_failed", actor_username=username, details={"reason": "invalid_totp"})
        return web.json_response({"error": "invalid_totp", "message": "Invalid TOTP code."}, status=401)

    api._pending_logins.pop(pending_token, None)
    response = web.json_response({"ok": True, "redirect_to": pending.get("next_path") or "/admin"})
    api._issue_session(response, request, username=username)
    await api._db.record_admin_login(username, api._client_ip(request))
    await api._log_audit(request, "auth.login_success", actor_username=username, details={"method": "password_totp"})
    return response


async def handle_logout(api, request: web.Request) -> web.Response:
    actor = api._get_session_actor(request)
    if request.method == "GET":
        response = web.HTTPFound("/login")
    else:
        response = web.json_response({"ok": True, "redirect_to": "/login"})
    api._clear_session(request, response)
    if actor:
        await api._log_audit(request, "auth.logout", actor_username=actor)
    return response


async def handle_session_activity(api, request: web.Request) -> web.Response:
    if not api._is_session_authenticated(request):
        return api._json_auth_error()
    token = api._get_session_token(request)
    if api._consume_rate_limit(
        api._activity_touches,
        token,
        limit=1,
        window_seconds=api._activity_touch_interval_seconds,
    ):
        return web.json_response(
            {"ok": True, "ttl_seconds": max(int(api._sessions.get(token, 0) - time.time()), 0)}
        )
    api._touch_session(request)
    return web.json_response(
        {"ok": True, "ttl_seconds": max(int(api._sessions.get(token, 0) - time.time()), 0)}
    )
