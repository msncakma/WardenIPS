"""Operational and hot-reload handlers extracted from DashboardAPI monolith."""

from __future__ import annotations

from aiohttp import web


async def handle_admin_reload_config(api, request: web.Request) -> web.Response:
    """Trigger config hot-reload without full restart."""
    permission_error = await api._require_permission(request, "admin.config.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    components = payload.get("components", [])
    if isinstance(components, str):
        components = [components]
    if not isinstance(components, list):
        components = []
    
    components = [str(c).strip().lower() for c in components if c]
    if not components:
        # Default: reload all
        components = ["config", "whitelist", "firewall", "plugins", "notifications"]
    
    valid_components = {"config", "whitelist", "firewall", "plugins", "notifications"}
    invalid = [c for c in components if c not in valid_components]
    if invalid:
        return web.json_response(
            {
                "error": "invalid_components",
                "message": f"Invalid component names: {invalid}. Valid: {valid_components}",
            },
            status=400,
        )
    
    results = {}
    
    # Reload config
    if "config" in components:
        try:
            await api._config.reload()
            results["config"] = "ok"
        except Exception as e:
            results["config"] = f"error: {str(e)}"
    
    # Reload whitelist
    if "whitelist" in components:
        try:
            if api._whitelist:
                await api._whitelist.reload(api._config)
            results["whitelist"] = "ok"
        except Exception as e:
            results["whitelist"] = f"error: {str(e)}"
    
    # Reload firewall state
    if "firewall" in components:
        try:
            if api._firewall:
                await api._firewall.sync()
            results["firewall"] = "ok"
        except Exception as e:
            results["firewall"] = f"error: {str(e)}"
    
    # Reload plugins
    if "plugins" in components:
        try:
            if api._plugin_mgr:
                await api._plugin_mgr.reload_all_configs()
            results["plugins"] = "ok"
        except Exception as e:
            results["plugins"] = f"error: {str(e)}"
    
    # Reload notifications
    if "notifications" in components:
        try:
            if api._notifier:
                await api._notifier.reload_config(api._config)
            results["notifications"] = "ok"
        except Exception as e:
            results["notifications"] = f"error: {str(e)}"
    
    await api._log_audit(
        request,
        "admin.config_reload",
        actor_username=actor,
        details={"components": components, "results": results},
    )
    
    return web.json_response(
        {
            "ok": all(str(v).startswith("ok") for v in results.values()),
            "components": results,
            "message": "Configuration reload completed.",
        }
    )


async def handle_admin_plugins_status(api, request: web.Request) -> web.Response:
    """Get status of all plugins."""
    permission_error = await api._require_permission(request, "admin.operational.read")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    
    plugins = []
    if api._plugin_mgr:
        for plugin in api._plugin_mgr._plugins:
            plugin_info = {
                "name": plugin.__class__.__name__,
                "enabled": getattr(plugin, "enabled", True),
                "config_path": getattr(plugin, "config_path", None),
            }
            if hasattr(plugin, "get_stats"):
                try:
                    stats = await plugin.get_stats() if hasattr(plugin.get_stats, "__await__") else plugin.get_stats()
                    plugin_info["stats"] = stats
                except Exception:
                    pass
            plugins.append(plugin_info)
    
    return web.json_response({"ok": True, "plugins": plugins, "count": len(plugins)})


async def handle_admin_firewall_status(api, request: web.Request) -> web.Response:
    """Get current firewall state."""
    permission_error = await api._require_permission(request, "admin.operational.read")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    
    status = {
        "simulation_mode": api._config.get("firewall.simulation_mode", False),
        "ipset_backend": api._config.get("firewall.ipset.backend", "unknown"),
    }
    
    if api._firewall:
        try:
            active_ips = await api._firewall.get_active_ban_count()
            status["active_bans"] = active_ips
        except Exception:
            status["active_bans"] = "unknown"
    
    return web.json_response({"ok": True, "firewall": status})


async def handle_admin_database_stats(api, request: web.Request) -> web.Response:
    """Get database statistics and health."""
    permission_error = await api._require_permission(request, "admin.operational.read")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    
    stats = {}
    
    if api._db:
        try:
            total_events = await api._db.count_events()
            stats["total_events"] = total_events
        except Exception:
            stats["total_events"] = "unknown"
        
        try:
            total_bans = await api._db.count_ban_records()
            stats["total_ban_records"] = total_bans
        except Exception:
            stats["total_ban_records"] = "unknown"
        
        try:
            db_size = await api._db.get_database_size_mb()
            stats["database_size_mb"] = db_size
        except Exception:
            stats["database_size_mb"] = "unknown"
    
    return web.json_response({"ok": True, "database": stats})


async def handle_admin_database_optimize(api, request: web.Request) -> web.Response:
    """Optimize database (VACUUM + ANALYZE)."""
    permission_error = await api._require_permission(request, "admin.operational.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    dry_run = bool(payload.get("dry_run", False))
    
    result = {"dry_run": dry_run}
    
    if not dry_run and api._db:
        try:
            before_size = await api._db.get_database_size_mb()
            result["size_before_mb"] = before_size
            
            await api._db.optimize()
            
            after_size = await api._db.get_database_size_mb()
            result["size_after_mb"] = after_size
            result["freed_mb"] = max(0, before_size - after_size)
            result["status"] = "completed"
        except Exception as e:
            result["status"] = f"error: {str(e)}"
    else:
        result["status"] = "dry_run"
    
    await api._log_audit(
        request,
        "admin.database_optimize",
        actor_username=actor,
        details=result,
    )
    
    return web.json_response({"ok": result.get("status") == "completed", **result})


async def handle_admin_firewall_sync(api, request: web.Request) -> web.Response:
    """Synchronize firewall with database state."""
    permission_error = await api._require_permission(request, "admin.operational.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    dry_run = bool(payload.get("dry_run", False))
    
    result = {"dry_run": dry_run, "added": 0, "removed": 0, "errors": []}
    
    if not dry_run and api._firewall:
        try:
            # Get all bans from DB
            db_bans = await api._db.list_bans() if api._db else []
            db_ban_ips = {str(b.get("ip", "")).strip() for b in db_bans if b}
            
            # Get active firewall IPs
            fw_ips = await api._firewall.get_active_bans() if hasattr(api._firewall, "get_active_bans") else set()
            
            # Add missing bans
            missing = db_ban_ips - fw_ips
            for ip in missing:
                try:
                    await api._firewall.ban_ip(ip, reason="Firewall sync")
                    result["added"] += 1
                except Exception as e:
                    result["errors"].append(f"Failed to add {ip}: {str(e)}")
            
            # Remove extra bans
            extra = fw_ips - db_ban_ips
            for ip in extra:
                try:
                    await api._firewall.unban_ip(ip)
                    result["removed"] += 1
                except Exception as e:
                    result["errors"].append(f"Failed to remove {ip}: {str(e)}")
            
            result["status"] = "completed"
        except Exception as e:
            result["status"] = f"error: {str(e)}"
            result["errors"].append(str(e))
    else:
        result["status"] = "dry_run"
    
    await api._log_audit(
        request,
        "admin.firewall_sync",
        actor_username=actor,
        details=result,
    )
    
    return web.json_response(
        {"ok": result.get("status") == "completed", **result}
    )


async def handle_admin_system_health(api, request: web.Request) -> web.Response:
    """Get overall system health report."""
    permission_error = await api._require_permission(request, "admin.operational.read")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    
    health = {
        "uptime_seconds": time.time() - api._start_time if api._start_time else 0,
        "components": {
            "database": "ok" if api._db else "missing",
            "firewall": "ok" if api._firewall else "missing",
            "notifier": "ok" if api._notifier else "missing",
            "plugins": "ok" if api._plugin_mgr else "missing",
        },
    }
    
    # Version info
    try:
        from wardenips import __version__
        health["version"] = __version__
    except Exception:
        health["version"] = "unknown"
    
    return web.json_response({"ok": True, "health": health})


# Import time at end of file
import time
