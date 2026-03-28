"""Operational management routes - firewall, plugins, database operations."""

from datetime import datetime, timezone
from aiohttp import web


def setup_operational_routes(app: web.Application, deps: dict):
    """Register operational management routes.
    
    Args:
        app: aiohttp Application
        deps: Dependencies dict
    """
    app["firewall_service"] = deps.get("firewall_service")
    app["plugin_service"] = deps.get("plugin_service")
    app["plugins"] = deps.get("plugins") or deps.get("plugin_manager")
    app["db"] = deps.get("db")
    
    # Firewall operations
    app.router.add_get("/api/v2/admin/firewall/status", handle_firewall_status)
    app.router.add_post("/api/v2/admin/firewall/sync", handle_firewall_sync)
    
    # Plugin operations
    app.router.add_get("/api/v2/admin/plugins", handle_list_plugins)
    app.router.add_get("/api/v2/admin/plugins/{name}", handle_get_plugin)
    app.router.add_post("/api/v2/admin/plugins/{name}/reload", handle_reload_plugin)
    
    # Database operations
    app.router.add_get("/api/v2/admin/database/stats", handle_database_stats)
    app.router.add_post("/api/v2/admin/database/optimize", handle_database_optimize)


async def handle_firewall_status(request: web.Request) -> web.Response:
    """GET /api/admin/firewall/status — Get live firewall state."""
    try:
        firewall = request.app.get("firewall")
        
        if not firewall:
            return web.json_response(
                {"error": "Firewall not available"},
                status=503
            )
        
        status = await firewall.get_status()
        
        return web.json_response({
            "firewall": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_firewall_sync(request: web.Request) -> web.Response:
    """POST /api/admin/firewall/sync — Reconcile firewall rules with database."""
    try:
        data = await request.json()
        dry_run = data.get("dry_run", False)
        
        firewall = request.app.get("firewall")
        
        if not firewall:
            return web.json_response(
                {"error": "Firewall not available"},
                status=503
            )
        
        # Call firewall reconciliation method
        result = await firewall.reconcile(dry_run=dry_run)
        
        return web.json_response({
            "reconciliation": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except ValueError:
        return web.json_response(
            {"error": "invalid JSON in request body"},
            status=400
        )
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_list_plugins(request: web.Request) -> web.Response:
    """GET /api/admin/plugins — List plugins and their status."""
    try:
        plugins_manager = request.app.get("plugins")

        plugins = []
        if plugins_manager and hasattr(plugins_manager, "plugins"):
            for plugin in plugins_manager.plugins:
                stats = getattr(plugin, "stats", {}) or {}
                plugins.append(
                    {
                        "name": getattr(plugin, "name", "unknown"),
                        "enabled": bool(getattr(plugin, "is_enabled", False)),
                        "log_file": getattr(plugin, "log_file_path", ""),
                        "stats": stats,
                    }
                )
        
        return web.json_response({
            "plugins": plugins,
            "total": len(plugins),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_get_plugin(request: web.Request) -> web.Response:
    """GET /api/admin/plugins/{name} — Get plugin details and status."""
    name = request.match_info.get("name")
    
    try:
        plugins_manager = request.app.get("plugins")
        if not plugins_manager or not hasattr(plugins_manager, "get_plugin"):
            return web.json_response({"error": "plugin manager not available"}, status=503)

        plugin_obj = plugins_manager.get_plugin(name)
        if not plugin_obj:
            return web.json_response({"error": "plugin not found"}, status=404)

        plugin = {
            "name": getattr(plugin_obj, "name", name),
            "enabled": bool(getattr(plugin_obj, "is_enabled", False)),
            "log_file": getattr(plugin_obj, "log_file_path", ""),
            "stats": getattr(plugin_obj, "stats", {}) or {},
        }
        
        return web.json_response(plugin)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_reload_plugin(request: web.Request) -> web.Response:
    """POST /api/admin/plugins/{name}/reload — Reload plugin configuration."""
    name = request.match_info.get("name")
    
    try:
        plugins_manager = request.app.get("plugins")
        if not plugins_manager or not hasattr(plugins_manager, "get_plugin"):
            return web.json_response({"error": "plugin manager not available"}, status=503)

        plugin_obj = plugins_manager.get_plugin(name)
        if not plugin_obj:
            return web.json_response({"error": "plugin not found"}, status=404)

        if hasattr(plugin_obj, "on_stop"):
            await plugin_obj.on_stop()
        if hasattr(plugin_obj, "on_start"):
            await plugin_obj.on_start()
        
        return web.json_response({
            "status": "reloaded",
            "plugin": name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_database_stats(request: web.Request) -> web.Response:
    """GET /api/admin/database/stats — Get extended database statistics."""
    try:
        db = request.app.get("db")
        
        if not db:
            return web.json_response(
                {"error": "Database not available"},
                status=503
            )
        
        stats = await db.get_stats()
        
        return web.json_response({
            "stats": stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_database_optimize(request: web.Request) -> web.Response:
    """POST /api/admin/database/optimize — Run VACUUM and ANALYZE."""
    try:
        db = request.app.get("db")
        
        if not db:
            return web.json_response(
                {"error": "Database not available"},
                status=503
            )
        
        # Call database optimization method
        success = await db.optimize()
        
        if not success:
            return web.json_response(
                {"error": "database optimization failed"},
                status=500
            )
        
        result = {
            "status": "completed",
            "operation": "VACUUM + ANALYZE",
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        return web.json_response(result)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
