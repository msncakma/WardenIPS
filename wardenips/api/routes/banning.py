"""Ban management routes - ban/unban/list operations."""

from datetime import datetime, timezone
from aiohttp import web


def setup_banning_routes(app: web.Application, deps: dict):
    """Register banning management routes.
    
    Args:
        app: aiohttp Application
        deps: Dependencies dict with ban_service
    """
    app["ban_service"] = deps.get("ban_service")
    app["firewall"] = deps.get("firewall")
    
    # Register routes
    app.router.add_post("/api/v2/admin/ban-ip", handle_ban_ip)
    app.router.add_delete("/api/v2/admin/ban/{ip}", handle_unban_ip)
    app.router.add_get("/api/v2/admin/bans", handle_list_bans)
    app.router.add_post("/api/v2/admin/bulk-ban", handle_bulk_ban)
    app.router.add_post("/api/v2/admin/firewall/reconcile", handle_firewall_reconcile)


async def handle_ban_ip(request: web.Request) -> web.Response:
    """POST /api/admin/ban-ip — Ban an IP address."""
    try:
        data = await request.json()
        ip = data.get("ip")
        duration = int(data.get("duration", 0))
        reason = data.get("reason", "")
        
        if not ip:
            return web.json_response(
                {"error": "ip field required"},
                status=400
            )
        
        ban_service = request.app.get("ban_service")
        
        if not ban_service:
            return web.json_response(
                {"error": "Ban service not available"},
                status=503
            )
        
        result = await ban_service.ban_ip(
            ip=ip,
            duration_seconds=duration,
            reason=reason,
            actor="api",
        )
        
        status_code = 201 if result.get("status") == "ok" else 400
        return web.json_response(result, status=status_code)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_unban_ip(request: web.Request) -> web.Response:
    """DELETE /api/admin/ban/{ip} — Unban an IP address."""
    ip = request.match_info.get("ip")
    
    try:
        ban_service = request.app.get("ban_service")
        
        if not ban_service:
            return web.json_response(
                {"error": "Ban service not available"},
                status=503
            )
        
        result = await ban_service.unban_ip(ip=ip, actor="api")
        
        return web.json_response(result)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_list_bans(request: web.Request) -> web.Response:
    """GET /api/admin/bans — List active bans."""
    try:
        limit = int(request.rel_url.query.get("limit", 100))
        
        ban_service = request.app.get("ban_service")
        
        if not ban_service:
            return web.json_response(
                {"error": "Ban service not available"},
                status=503
            )
        
        bans = await ban_service.get_active_bans(limit=limit)
        
        return web.json_response({
            "bans": bans,
            "total": len(bans),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_bulk_ban(request: web.Request) -> web.Response:
    """POST /api/admin/bulk-ban — Ban multiple IPs at once."""
    try:
        data = await request.json()
        ips = data.get("ips", [])
        duration = int(data.get("duration", 0))
        reason = data.get("reason", "")
        
        if not ips:
            return web.json_response(
                {"error": "ips array required"},
                status=400
            )
        
        ban_service = request.app.get("ban_service")
        
        if not ban_service:
            return web.json_response(
                {"error": "Ban service not available"},
                status=503
            )
        
        result = await ban_service.bulk_ban(
            ips=ips,
            duration_seconds=duration,
            reason=reason,
            actor="api",
        )
        
        return web.json_response(result, status=207)  # Multi-Status
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_firewall_reconcile(request: web.Request) -> web.Response:
    """POST /api/admin/firewall/reconcile — Sync database with kernel firewall."""
    try:
        data = await request.json()
        dry_run = data.get("dry_run", False)

        firewall = request.app.get("firewall")
        if not firewall:
            return web.json_response(
                {"error": "Firewall not available"},
                status=503,
            )

        result = await firewall.reconcile(dry_run=bool(dry_run))

        return web.json_response({
            "status": "reconciled",
            "dry_run": bool(dry_run),
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    except ValueError:
        return web.json_response({"error": "invalid JSON in request body"}, status=400)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
