"""Public API endpoints - read-only, no authentication required."""

from datetime import datetime, timedelta, timezone
from aiohttp import web


def setup_public_routes(app: web.Application, deps: dict):
    """Register public API routes.
    
    Args:
        app: aiohttp Application
        deps: Dependencies dict with db, firewall, config, etc.
    """
    # Store dependencies in app for access in handlers
    app["db"] = deps.get("db")
    app["firewall"] = deps.get("firewall")
    app["config"] = deps.get("config")
    
    # Register routes
    app.router.add_get("/api/v2/health", handle_health)
    app.router.add_get("/api/v2/stats", handle_stats)
    app.router.add_get("/api/v2/events", handle_events)
    app.router.add_get("/api/v2/bans", handle_bans)
    app.router.add_get("/api/v2/firewall", handle_firewall_status)
    app.router.add_get("/api/v2/top-attackers", handle_top_attackers)
    app.router.add_get("/api/v2/events-timeline", handle_events_timeline)
    app.router.add_get("/api/v2/asn-stats", handle_asn_stats)
    app.router.add_get("/api/v2/threat-distribution", handle_threat_distribution)
    app.router.add_get("/api/v2/plugin-stats", handle_plugin_stats)


async def handle_health(request: web.Request) -> web.Response:
    """GET /api/health — Health check and uptime."""
    app = request.app
    db = app.get("db")
    
    # Calculate uptime
    uptime_seconds = 0  # Would be set from main.py start_time
    uptime_hours = uptime_seconds // 3600
    
    response = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": uptime_seconds,
        "uptime_formatted": f"{uptime_hours}h" if uptime_hours > 0 else "< 1h",
    }
    
    # Add database health if available
    if db:
        try:
            stats = await db.get_stats()
            response["database"] = "ok"
            response["stats"] = stats
        except Exception as e:
            response["database"] = f"error: {e}"
    
    return web.json_response(response)


async def handle_stats(request: web.Request) -> web.Response:
    """GET /api/stats — Database statistics."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        stats = await db.get_stats()
        return web.json_response(stats)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_events(request: web.Request) -> web.Response:
    """GET /api/events — Recent events (paginated)."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        limit = int(request.rel_url.query.get("limit", 100))
        offset = int(request.rel_url.query.get("offset", 0))
        
        events = await db.get_events(limit=limit, offset=offset)
        total = await db.get_event_count()
        
        return web.json_response({
            "events": events,
            "total": total,
            "limit": limit,
            "offset": offset,
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_bans(request: web.Request) -> web.Response:
    """GET /api/bans — Active ban list."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        limit = int(request.rel_url.query.get("limit", 100))
        bans = await db.get_active_bans(limit=limit)
        
        return web.json_response({
            "bans": bans,
            "total": len(bans),
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_firewall_status(request: web.Request) -> web.Response:
    """GET /api/firewall — Firewall operational status."""
    app = request.app
    firewall = app.get("firewall")
    
    if not firewall:
        return web.json_response({"error": "Firewall not available"}, status=503)
    
    try:
        status = await firewall.get_status()
        return web.json_response({
            "firewall": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_top_attackers(request: web.Request) -> web.Response:
    """GET /api/top-attackers — Top source IPs by event count."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        limit = int(request.rel_url.query.get("limit", 10))
        
        # Query top attackers
        query = """
            SELECT source_ip, COUNT(*) as count 
            FROM connection_events 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT ?
        """
        attackers = await db._execute(query, (limit,))
        attackers = [
            {"ip": row[0], "event_count": row[1]} 
            for row in (attackers or [])
        ]
        
        return web.json_response({"attackers": attackers})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_events_timeline(request: web.Request) -> web.Response:
    """GET /api/events-timeline — Events grouped by hour."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        timeline = await db.get_events_timeline(hours=24)
        return web.json_response({"timeline": timeline})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_asn_stats(request: web.Request) -> web.Response:
    """GET /api/asn-stats — Events grouped by ASN organization."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        stats = await db.get_asn_stats(limit=20)
        return web.json_response({"asn_stats": stats})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_threat_distribution(request: web.Request) -> web.Response:
    """GET /api/threat-distribution — Events grouped by threat level."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        distribution = await db.get_threat_distribution()
        return web.json_response({"distribution": distribution})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_plugin_stats(request: web.Request) -> web.Response:
    """GET /api/plugin-stats — Events grouped by plugin/connection type."""
    app = request.app
    db = app.get("db")
    
    if not db:
        return web.json_response({"error": "Database not available"}, status=503)
    
    try:
        stats = await db.get_plugin_stats()
        return web.json_response({"plugin_stats": stats})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
