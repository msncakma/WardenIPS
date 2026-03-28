"""Admin security handlers extracted from DashboardAPI monolith."""

from __future__ import annotations

import ipaddress
from aiohttp import web


async def handle_admin_get_whitelist(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    return web.json_response(
        {
            "ok": True,
            "ips": list(api._config.get("whitelist.ips", []) or []),
            "cidr_ranges": list(api._config.get("whitelist.cidr_ranges", []) or []),
        }
    )


async def handle_admin_add_whitelist(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    raw_value = str(payload.get("value", "")).strip()
    try:
        normalized, entry_type = api._normalize_whitelist_entry(raw_value)
    except Exception:
        return web.json_response(
            {
                "error": "invalid_entry",
                "message": "Provide a valid IPv4/IPv6 address or CIDR range.",
            },
            status=400,
        )

    # Use WhitelistService if available (modern path), else legacy config patching
    if api._whitelist_service:
        tag = payload.get("tag", "manual")
        reason = payload.get("reason", "Added via admin panel")
        try:
            result = await api._whitelist_service.add_whitelist(normalized, reason=reason, tag=tag)
            if result:
                await api._log_audit(
                    request,
                    "admin.whitelist_add",
                    actor_username=actor,
                    details={"entry": normalized, "entry_type": entry_type, "tag": tag},
                )
                return web.json_response(
                    {
                        "ok": True,
                        "message": f"Added {normalized} to whitelist.",
                        "entry": normalized,
                        "entry_type": entry_type,
                    }
                )
        except Exception:
            pass  # Fall through to legacy path on error

    # Legacy path: Direct config patching
    ip_values = list(api._config.get("whitelist.ips", []) or [])
    cidr_values = list(api._config.get("whitelist.cidr_ranges", []) or [])

    if entry_type == "ip":
        if normalized in ip_values:
            return web.json_response(
                {
                    "ok": True,
                    "message": f"{normalized} is already in whitelist.",
                    "entry": normalized,
                    "entry_type": entry_type,
                }
            )
        ip_values.append(normalized)
    else:
        if normalized in cidr_values:
            return web.json_response(
                {
                    "ok": True,
                    "message": f"{normalized} is already in whitelist.",
                    "entry": normalized,
                    "entry_type": entry_type,
                }
            )
        cidr_values.append(normalized)

    await api._config.patch_values(
        {
            "whitelist.ips": ip_values,
            "whitelist.cidr_ranges": cidr_values,
        }
    )
    if api._whitelist:
        await api._whitelist.reload(api._config)

    await api._log_audit(
        request,
        "admin.whitelist_add",
        actor_username=actor,
        details={"entry": normalized, "entry_type": entry_type},
    )
    return web.json_response(
        {
            "ok": True,
            "message": f"Added {normalized} to whitelist.",
            "entry": normalized,
            "entry_type": entry_type,
        }
    )


async def handle_admin_remove_whitelist(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    raw_value = str(payload.get("value", "")).strip()
    try:
        normalized, entry_type = api._normalize_whitelist_entry(raw_value)
    except Exception:
        return web.json_response(
            {
                "error": "invalid_entry",
                "message": "Provide a valid IPv4/IPv6 address or CIDR range.",
            },
            status=400,
        )

    # Use WhitelistService if available (modern path), else legacy config patching
    if api._whitelist_service:
        try:
            result = await api._whitelist_service.remove_whitelist_by_value(normalized)
            if result:
                await api._log_audit(
                    request,
                    "admin.whitelist_remove",
                    actor_username=actor,
                    details={"entry": normalized, "entry_type": entry_type},
                )
                return web.json_response(
                    {
                        "ok": True,
                        "message": f"Removed {normalized} from whitelist.",
                        "entry": normalized,
                        "entry_type": entry_type,
                    }
                )
        except Exception:
            pass  # Fall through to legacy path on error

    # Legacy path: Direct config patching
    ip_values = list(api._config.get("whitelist.ips", []) or [])
    cidr_values = list(api._config.get("whitelist.cidr_ranges", []) or [])
    changed = False

    if entry_type == "ip" and normalized in ip_values:
        ip_values = [item for item in ip_values if str(item).strip() != normalized]
        changed = True
    if entry_type == "cidr" and normalized in cidr_values:
        cidr_values = [item for item in cidr_values if str(item).strip() != normalized]
        changed = True

    if not changed:
        return web.json_response(
            {
                "ok": True,
                "message": f"{normalized} was not present in whitelist.",
                "entry": normalized,
                "entry_type": entry_type,
            }
        )

    await api._config.patch_values(
        {
            "whitelist.ips": ip_values,
            "whitelist.cidr_ranges": cidr_values,
        }
    )
    if api._whitelist:
        await api._whitelist.reload(api._config)

    await api._log_audit(
        request,
        "admin.whitelist_remove",
        actor_username=actor,
        details={"entry": normalized, "entry_type": entry_type},
    )
    return web.json_response(
        {
            "ok": True,
            "message": f"Removed {normalized} from whitelist.",
            "entry": normalized,
            "entry_type": entry_type,
        }
    )


async def handle_admin_unban_ip(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    payload = await request.json()
    ip_value = str(payload.get("ip", "")).strip()
    if not ip_value:
        return web.json_response(
            {"error": "invalid_ip", "message": "IP address is required."},
            status=400,
        )
    # Use BanService if available (modern path), else legacy direct firewall access
    if api._ban_service:
        firewall_result = await api._ban_service.unban_ip(ip_value, actor)
        deactivated = 1 if firewall_result else 0
    else:
        # Legacy: Direct firewall access
        firewall_result = await api._firewall.unban_ip(ip_value)
        deactivated = await api._db.deactivate_ban_by_ip(ip_value)
    await api._log_audit(
        request,
        "admin.unban_ip",
        actor_username=actor,
        details={
            "ip": ip_value,
            "firewall_result": firewall_result,
            "deactivated_records": deactivated,
        },
    )
    return web.json_response(
        {
            "ok": firewall_result,
            "message": f"Removed {ip_value} from firewall bans.",
            "deactivated_records": deactivated,
        }
    )


async def handle_admin_ban_ip(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    ip_value = str(payload.get("ip", "")).strip()
    if not ip_value:
        return web.json_response(
            {"error": "invalid_ip", "message": "IP address is required."},
            status=400,
        )
    try:
        ipaddress.ip_address(ip_value)
    except Exception:
        return web.json_response(
            {"error": "invalid_ip", "message": "Provide a valid IPv4 or IPv6 address."},
            status=400,
        )

    duration_value = payload.get("duration", api._config.get("firewall.ipset.default_ban_duration", 0))
    try:
        duration = max(int(duration_value), 0)
    except Exception:
        duration = max(int(api._config.get("firewall.ipset.default_ban_duration", 0)), 0)

    reason = str(payload.get("reason", "")).strip() or "[ADMIN] Manual ban from dashboard"
    risk_score_value = payload.get("risk_score", 100)
    try:
        risk_score = min(max(int(risk_score_value), 0), 100)
    except Exception:
        risk_score = 100

    # Use BanService if available (modern path), else legacy direct firewall access
    if api._ban_service:
        banned = await api._ban_service.ban_ip(ip_value, duration_seconds=duration, reason=reason, actor=actor)
    else:
        # Legacy: Direct firewall access
        banned = await api._firewall.ban_ip(ip_value, duration=duration, reason=reason)
    if not banned:
        return web.json_response(
            {
                "ok": False,
                "message": f"Ban request for {ip_value} was skipped (already banned, whitelisted, or blocked by safety checks).",
            },
            status=409,
        )

    if not api._ban_service:  # Only log if legacy (service logs internally)
        await api._db.log_ban(ip_value, reason, risk_score, duration)
        await api._notifier.notify_ban(
            ip=ip_value,
            reason=reason,
            risk=risk_score,
            duration=duration,
            plugin="admin",
        )
    await api._log_audit(
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
