"""Setup and invite registration handlers extracted from DashboardAPI monolith."""

from __future__ import annotations

import json
import ipaddress
import secrets
import time

from aiohttp import web

from wardenips.core.auth import (
    check_password_policy,
    generate_totp_secret,
    hash_password,
    verify_bootstrap_token,
    verify_totp_code,
    build_totp_uri,
    build_totp_qr_data_url,
)


async def handle_setup_begin(api, request: web.Request) -> web.Response:
    if not api._bootstrap_token_is_valid():
        return web.json_response({"error": "setup_unavailable", "message": "First-boot setup is not available anymore."}, status=403)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    bootstrap_token = str(payload.get("bootstrap_token", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    password_confirm = str(payload.get("password_confirm", ""))
    if not verify_bootstrap_token(api._bootstrap_token_hash, bootstrap_token):
        await api._log_audit(request, "setup.begin_failed", actor_username=username or None, details={"reason": "invalid_bootstrap"})
        return web.json_response({"error": "invalid_bootstrap", "message": "Invalid bootstrap token."}, status=401)
    if not username or username.lower() == "admin":
        return web.json_response({"error": "invalid_username", "message": "Choose a non-default admin username."}, status=400)
    if password != password_confirm:
        return web.json_response({"error": "password_mismatch", "message": "Passwords do not match."}, status=400)
    is_valid, policy_message = check_password_policy(password)
    if not is_valid:
        return web.json_response({"error": "weak_password", "message": policy_message}, status=400)
    if await api._db.has_admin_users():
        return web.json_response({"error": "setup_completed", "message": "An admin user already exists."}, status=409)

    pending_token = secrets.token_urlsafe(24)
    totp_secret = generate_totp_secret()
    totp_uri = build_totp_uri(username, totp_secret)
    api._pending_setups[pending_token] = {
        "username": username,
        "password_hash": hash_password(password),
        "totp_secret": totp_secret,
        "expires_at": time.time() + 900,
    }
    await api._log_audit(request, "setup.begin_success", actor_username=username, details={"totp": True})
    return web.json_response({
        "ok": True,
        "pending_setup_token": pending_token,
        "totp_secret": totp_secret,
        "totp_uri": totp_uri,
        "totp_qr_data_url": build_totp_qr_data_url(totp_uri),
    })


async def handle_invite_register(api, request: web.Request) -> web.Response:
    if api._bootstrap_token_is_valid():
        return web.json_response({"error": "setup_required", "message": "Complete bootstrap setup first."}, status=403)
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    invite_token = str(payload.get("invite_token", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    password_confirm = str(payload.get("password_confirm", ""))
    display_name = str(payload.get("display_name", "")).strip()
    totp_enabled = bool(payload.get("totp_enabled", True))

    if not invite_token or not username:
        return web.json_response({"error": "invalid_request", "message": "invite_token and username are required."}, status=400)
    if password != password_confirm:
        return web.json_response({"error": "password_mismatch", "message": "Passwords do not match."}, status=400)
    valid, message = check_password_policy(password)
    if not valid:
        return web.json_response({"error": "weak_password", "message": message}, status=400)
    if await api._db.get_admin_user_by_username(username):
        return web.json_response({"error": "username_exists", "message": "Username already exists."}, status=409)

    invite = await api._db.get_active_invite_by_hash(api._hash_invite_token(invite_token))
    if not invite:
        return web.json_response({"error": "invalid_invite", "message": "Invite token is invalid or expired."}, status=401)

    created_by = str(invite.get("created_by") or "")
    user_id = await api._db.create_admin_user(
        username=username,
        password_hash=hash_password(password),
        totp_secret=generate_totp_secret(),
        totp_enabled=totp_enabled,
        is_owner=False,
        display_name=display_name or username,
        created_by=created_by,
    )
    try:
        role_codes = json.loads(str(invite.get("role_codes_json") or "[]"))
    except Exception:
        role_codes = []
    try:
        permission_nodes = json.loads(str(invite.get("permission_nodes_json") or "[]"))
    except Exception:
        permission_nodes = []
    for role in role_codes if isinstance(role_codes, list) else []:
        await api._db.assign_role_to_user(username, str(role or "").strip().lower())
    for node in permission_nodes if isinstance(permission_nodes, list) else []:
        await api._db.upsert_user_permission(username, str(node or "").strip(), effect=1)

    await api._db.consume_invite_token(int(invite.get("id") or 0))
    response = web.json_response({"ok": True, "redirect_to": "/portal", "message": "Registration completed."})
    api._issue_session(response, request, username=username)
    await api._db.record_admin_login(username, api._client_ip(request))
    await api._log_audit(request, "auth.invite_register", actor_username=username, details={"invite_id": invite.get("id"), "created_by": created_by, "user_id": user_id})
    return response


async def handle_setup_complete(api, request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    pending_token = str(payload.get("pending_setup_token", "")).strip()
    totp_code = str(payload.get("totp_code", "")).strip()
    pending = api._pending_setups.get(pending_token)
    if not pending or float(pending.get("expires_at", 0)) <= time.time():
        api._pending_setups.pop(pending_token, None)
        return web.json_response({"error": "setup_expired", "message": "Setup session expired. Start again."}, status=401)
    if not verify_totp_code(str(pending.get("totp_secret", "")), totp_code):
        await api._log_audit(request, "setup.complete_failed", actor_username=str(pending.get("username", "")), details={"reason": "invalid_totp"})
        return web.json_response({"error": "invalid_totp", "message": "Invalid TOTP code."}, status=401)
    if await api._db.has_admin_users():
        api._pending_setups.pop(pending_token, None)
        return web.json_response({"error": "setup_completed", "message": "An admin user already exists."}, status=409)

    username = str(pending.get("username", ""))
    try:
        await api._db.create_admin_user(
            username=username,
            password_hash=str(pending.get("password_hash", "")),
            totp_secret=str(pending.get("totp_secret", "")),
            totp_enabled=True,
            is_owner=True,
            display_name=username,
            created_by="bootstrap_setup",
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
    api._pending_setups.pop(pending_token, None)
    # Apply first-install defaults
    try:
        private_nets = payload.get("whitelist_private_networks") or []
        if private_nets and isinstance(private_nets, list):
            existing_ips = list(api._config.get("whitelist.ips", []) or [])
            existing_cidrs = list(api._config.get("whitelist.cidr_ranges", []) or [])
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
            await api._config.patch_values({"whitelist.ips": existing_ips, "whitelist.cidr_ranges": existing_cidrs})
            if api._whitelist:
                await api._whitelist.reload(api._config)
        # Ensure monitor mode is active for fresh installs
        await api._config.patch_values({"firewall.simulation_mode": True})
        api._firewall.apply_simulation_config(True)
    except Exception:
        pass
    await api._clear_bootstrap_config()
    response = web.json_response({"ok": True, "redirect_to": "/admin", "message": "Initial admin setup completed."})
    api._issue_session(response, request, username=username)
    await api._db.record_admin_login(username, api._client_ip(request))
    await api._log_audit(request, "setup.complete_success", actor_username=username, details={"totp": True})
    return response
