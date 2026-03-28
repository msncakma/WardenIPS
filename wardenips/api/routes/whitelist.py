"""Whitelist management routes - add/remove/list whitelisted IPs."""

from datetime import datetime, timezone
from aiohttp import web


def setup_whitelist_routes(app: web.Application, deps: dict):
    """Register whitelist management routes.
    
    Args:
        app: aiohttp Application
        deps: Dependencies dict with whitelist_service
    """
    app["whitelist_service"] = deps.get("whitelist_service")
    
    # Register routes
    app.router.add_get("/api/v2/admin/whitelist", handle_list_whitelist)
    app.router.add_post("/api/v2/admin/whitelist/add", handle_add_whitelist)
    app.router.add_delete("/api/v2/admin/whitelist/{entry_id}", handle_remove_whitelist)
    app.router.add_patch("/api/v2/admin/whitelist/{entry_id}", handle_update_whitelist)


async def handle_list_whitelist(request: web.Request) -> web.Response:
    """GET /api/admin/whitelist — List all whitelisted entries."""
    try:
        whitelist_service = request.app.get("whitelist_service")
        
        if not whitelist_service:
            return web.json_response(
                {"error": "Whitelist service not available"},
                status=503
            )
        
        entries = await whitelist_service.list_whitelist()
        
        return web.json_response({
            "whitelist": entries,
            "total": len(entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_add_whitelist(request: web.Request) -> web.Response:
    """POST /api/admin/whitelist/add — Add IP/CIDR to whitelist."""
    try:
        data = await request.json()
        ip_or_cidr = data.get("ip")
        reason = data.get("reason", "")
        tag = data.get("tag", "")
        
        if not ip_or_cidr:
            return web.json_response(
                {"error": "ip field required"},
                status=400
            )
        
        whitelist_service = request.app.get("whitelist_service")
        
        if not whitelist_service:
            return web.json_response(
                {"error": "Whitelist service not available"},
                status=503
            )
        
        result = await whitelist_service.add_whitelist(
            ip_or_cidr=ip_or_cidr,
            reason=reason,
            tag=tag,
        )
        
        return web.json_response(result, status=201)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_remove_whitelist(request: web.Request) -> web.Response:
    """DELETE /api/admin/whitelist/{entry_id} — Remove from whitelist."""
    entry_id = request.match_info.get("entry_id")
    
    try:
        whitelist_service = request.app.get("whitelist_service")
        
        if not whitelist_service:
            return web.json_response(
                {"error": "Whitelist service not available"},
                status=503
            )
        
        result = await whitelist_service.remove_whitelist(entry_id)
        
        return web.json_response(result)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_update_whitelist(request: web.Request) -> web.Response:
    """PATCH /api/admin/whitelist/{entry_id} — Update whitelist entry."""
    entry_id = request.match_info.get("entry_id")
    
    try:
        data = await request.json()
        reason = data.get("reason")
        tag = data.get("tag")
        
        whitelist_service = request.app.get("whitelist_service")
        
        if not whitelist_service:
            return web.json_response(
                {"error": "Whitelist service not available"},
                status=503
            )
        
        result = await whitelist_service.update_whitelist(
            entry_id=entry_id,
            reason=reason,
            tag=tag,
        )
        
        return web.json_response(result)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
