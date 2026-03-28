"""Admin config, firewall, and operational handlers extracted from DashboardAPI monolith."""

from __future__ import annotations

from aiohttp import web
from wardenips.core.updater import UpdateChecker
from wardenips import __version__


async def handle_admin_deactivate_ban(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    source_ip = str(payload.get("source_ip", "")).strip()
    if not source_ip:
        return web.json_response(
            {"error": "invalid_ip", "message": "Source IP is required."},
            status=400,
        )
    updated = await api._db.deactivate_ban_by_ip(source_ip)
    await api._log_audit(request, "admin.deactivate_ban", actor_username=actor, details={"source_ip": source_ip, "updated": updated})
    return web.json_response({"ok": True, "updated": updated})


async def handle_admin_deactivate_all_bans(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    updated = await api._db.deactivate_all_bans()
    await api._log_audit(request, "admin.deactivate_all_bans", actor_username=actor, details={"updated": updated})
    return web.json_response({"ok": True, "updated": updated})


async def handle_admin_flush_firewall(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    flushed = await api._firewall.flush()
    updated = await api._db.deactivate_all_bans()
    await api._log_audit(request, "admin.flush_firewall", actor_username=actor, details={"flushed": flushed, "deactivated_records": updated})
    return web.json_response({"ok": flushed, "deactivated_records": updated})


async def handle_admin_clear_events(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    deleted = await api._db.clear_events()
    await api._log_audit(request, "admin.clear_events", actor_username=actor, details={"deleted": deleted})
    return web.json_response({"ok": True, "deleted": deleted})


async def handle_admin_clear_ban_history(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    deleted = await api._db.clear_ban_history()
    await api._log_audit(request, "admin.clear_ban_history", actor_username=actor, details={"deleted": deleted})
    return web.json_response({"ok": True, "deleted": deleted})


async def handle_admin_test_notification(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    if not api._notifier:
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
        result = await api._notifier.send_test_notification(channel)
    except ValueError as exc:
        return web.json_response({"error": "invalid_channel", "message": str(exc)}, status=400)
    except RuntimeError as exc:
        return web.json_response({"error": "notification_unavailable", "message": str(exc)}, status=503)
    summary = ", ".join(f"{name}: {status}" for name, status in result["results"].items())
    await api._log_audit(request, "admin.test_notification", actor_username=actor, details={"channel": channel, "results": result.get("results", {})})
    return web.json_response({"ok": True, "message": f"Test notification dispatched ({summary}).", **result})


async def handle_admin_update_status(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "panel.view")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    checker = UpdateChecker(current_version=__version__)
    return web.json_response(await checker.get_status())


async def handle_admin_get_config(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    
    # Use ConfigService if available, otherwise fall back to direct config access
    if api._config_service:
        config_data = await api._config_service.get_config()
        yaml_text = await api._config.get_yaml_text()
    else:
        config_data = api._config.raw
        yaml_text = await api._config.get_yaml_text()
    
    return web.json_response(
        {
            "ok": True,
            "config": config_data,
            "yaml": yaml_text,
            "message": "Some runtime changes apply immediately in the dashboard, while service-level changes may require a restart.",
        }
    )


async def handle_admin_save_config(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    yaml_text = str(payload.get("yaml", "")).strip()
    if not yaml_text:
        return web.json_response({"error": "invalid_config", "message": "YAML content is required."}, status=400)
    try:
        await api._config.save_yaml_text(yaml_text)
    except Exception as exc:
        return web.json_response({"error": "config_write_failed", "message": str(exc)}, status=500)
    api._initialize_config()
    desired_simulation, effective_simulation = api._sync_firewall_simulation_mode()
    await api._log_audit(request, "admin.save_config", actor_username=actor, details={"mode": "yaml", "bytes": len(yaml_text)})
    current_yaml = await api._config.get_yaml_text()
    message = "Configuration saved. Restart WardenIPS if you changed firewall, plugin, or notification wiring."
    if (not desired_simulation) and effective_simulation:
        message = (
            "Configuration saved. Simulation mode remains active because firewall tools/permissions are not currently available at runtime."
        )
    return web.json_response(
        {
            "ok": True,
            "message": message,
            "config": api._config.raw,
            "yaml": current_yaml,
        }
    )


async def handle_admin_patch_config(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    changes = payload.get("changes") or {}
    if not isinstance(changes, dict) or not changes:
        return web.json_response({"error": "invalid_changes", "message": "At least one config change is required."}, status=400)
    
    # Use ConfigService if available for validation, otherwise fall back to direct access
    if api._config_service:
        try:
            normalized_changes = {str(key): value for key, value in changes.items()}
            await api._config_service.patch_config(normalized_changes)
        except Exception as exc:
            return web.json_response({"error": "config_write_failed", "message": str(exc)}, status=500)
    else:
        try:
            normalized_changes = {str(key): value for key, value in changes.items()}
            await api._config.patch_values(normalized_changes)
        except Exception as exc:
            return web.json_response({"error": "config_write_failed", "message": str(exc)}, status=500)
    
    api._initialize_config()
    desired_simulation, effective_simulation = api._sync_firewall_simulation_mode()
    await api._log_audit(request, "admin.patch_config", actor_username=actor, details={"changes": sorted(str(key) for key in changes.keys())})
    current_yaml = await api._config.get_yaml_text()
    message = "Configuration updated."
    if (not desired_simulation) and effective_simulation:
        message = (
            "Configuration updated. Simulation mode remains active because firewall tools/permissions are not currently available at runtime."
        )
    return web.json_response(
        {
            "ok": True,
            "message": message,
            "config": api._config.raw,
            "yaml": current_yaml,
        }
    )


async def handle_admin_get_portal_links(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    return web.json_response(
        {
            "ok": True,
            "enabled": bool(api._portal_enabled),
            "count": len(api._portal_links),
            "links": list(api._portal_links),
        }
    )


async def handle_admin_set_portal_links(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    raw_links = payload.get("links", [])
    if not isinstance(raw_links, list):
        return web.json_response({"error": "invalid_links", "message": "links must be a JSON array."}, status=400)

    normalized_links: list[dict[str, str]] = []
    for item in raw_links[:40]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        url = str(item.get("url", "")).strip()
        description = str(item.get("description", "")).strip()
        permission = str(item.get("permission", "")).strip()
        if not title or not url:
            continue
        normalized_links.append(
            {
                "title": title[:120],
                "url": url[:500],
                "description": description[:260],
                "permission": permission[:120],
            }
        )

    api._portal_links = normalized_links
    await api._log_audit(request, "admin.set_portal_links", actor_username=actor, details={"count": len(normalized_links)})
    return web.json_response(
        {
            "ok": True,
            "count": len(normalized_links),
            "links": normalized_links,
        }
    )
