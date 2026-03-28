"""Configuration management routes - get/set/reload operations."""

from datetime import datetime, timezone
from aiohttp import web


def setup_config_routes(app: web.Application, deps: dict):
    """Register config management routes.
    
    Args:
        app: aiohttp Application
        deps: Dependencies dict with config_service
    """
    app["config_service"] = deps.get("config_service")
    
    # Register routes
    app.router.add_get("/api/v2/admin/config", handle_get_config)
    app.router.add_patch("/api/v2/admin/config", handle_patch_config)
    app.router.add_post("/api/v2/admin/config/reload", handle_reload_config)
    app.router.add_post("/api/v2/admin/config/validate", handle_validate_config)


async def handle_get_config(request: web.Request) -> web.Response:
    """GET /api/admin/config — Get current configuration (with secrets masked)."""
    try:
        config_service = request.app.get("config_service")
        
        if not config_service:
            return web.json_response(
                {"error": "Config service not available"},
                status=503
            )
        
        key = request.rel_url.query.get("key")
        config_data = await config_service.get_config(key=key)
        
        return web.json_response({
            "config": config_data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_patch_config(request: web.Request) -> web.Response:
    """PATCH /api/admin/config — Update configuration and save to disk."""
    try:
        data = await request.json()
        
        config_service = request.app.get("config_service")
        
        if not config_service:
            return web.json_response(
                {"error": "Config service not available"},
                status=503
            )
        
        # Validation happens in service layer
        result = await config_service.patch_config(data)
        
        return web.json_response({
            "status": "updated",
            "changes": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_reload_config(request: web.Request) -> web.Response:
    """POST /api/admin/config/reload — Reload config without restart (hot-reload)."""
    try:
        data = await request.json()
        components = data.get("components", None)  # e.g., ["whitelist", "firewall"]
        
        config_service = request.app.get("config_service")
        
        if not config_service:
            return web.json_response(
                {"error": "Config service not available"},
                status=503
            )
        
        result = await config_service.reload_config(components=components)
        
        return web.json_response(result)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_validate_config(request: web.Request) -> web.Response:
    """POST /api/admin/config/validate — Validate config without applying."""
    try:
        data = await request.json()
        
        config_service = request.app.get("config_service")
        
        if not config_service:
            return web.json_response(
                {"error": "Config service not available"},
                status=503
            )
        
        is_valid, errors = await config_service.validate_config(data)
        
        response = {
            "valid": is_valid,
            "errors": errors,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        status = 200 if is_valid else 400
        return web.json_response(response, status=status)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
