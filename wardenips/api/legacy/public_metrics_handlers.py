"""Public metric handlers extracted from DashboardAPI.

These functions keep legacy behavior while reducing `dashboard.py` size.
"""

from __future__ import annotations

import json
from aiohttp import web


async def handle_firewall(api, request: web.Request) -> web.Response:
    if not api._check_auth(request):
        return api._json_auth_error()
    count = await api._firewall.get_banned_count()
    return web.json_response(
        {
            "simulation_mode": api._firewall.simulation_mode,
            "active_bans": count,
            "firewall": repr(api._firewall),
        }
    )


async def handle_firewall_bans(api, request: web.Request) -> web.Response:
    if not api._check_auth(request):
        return api._json_auth_error()
    limit = min(int(request.query.get("limit", "500")), 2000)
    try:
        items = await api._firewall.list_banned_ips(limit=limit)
        return web.json_response({"items": items, "count": len(items)})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_top_attackers(api, request: web.Request) -> web.Response:
    if not api._check_public_dashboard_access(request):
        return api._json_auth_error()
    limit = min(int(request.query.get("limit", "10")), 50)
    try:
        async with api._db._lock:
            async with api._db._db.execute(
                """
                SELECT source_ip,
                     COUNT(*) as ban_count,
                     MAX(risk_score) as max_risk,
                     MAX(banned_at) as last_ban
                FROM ban_history
                GROUP BY source_ip
                ORDER BY ban_count DESC
                LIMIT ?
                """,
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                columns = [d[0] for d in cursor.description]
                attackers = [dict(zip(columns, row)) for row in rows]
        return web.json_response({"attackers": attackers})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_events_timeline(api, request: web.Request) -> web.Response:
    if not api._check_public_dashboard_access(request):
        return api._json_auth_error()
    hours = min(int(request.query.get("hours", "24")), 168)
    try:
        timestamp_expr = "COALESCE(strftime('%s', timestamp), CASE WHEN timestamp GLOB '[0-9]*' THEN CAST(timestamp AS INTEGER) ELSE 0 END)"
        async with api._db._lock:
            async with api._db._db.execute(
                f"""
                SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                     COUNT(*) as count
                FROM connection_events
                WHERE {timestamp_expr} >= strftime('%s', 'now', ? || ' hours')
                GROUP BY hour
                ORDER BY hour ASC
                """,
                (f"-{hours}",),
            ) as cursor:
                rows = await cursor.fetchall()
                timeline = [{"hour": r[0], "count": r[1]} for r in rows]
        return web.json_response({"timeline": timeline})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_asn_stats(api, request: web.Request) -> web.Response:
    if not api._check_public_dashboard_access(request):
        return api._json_auth_error()
    hours = max(int(request.query.get("hours", "0")), 0)
    try:
        timestamp_expr = "COALESCE(strftime('%s', timestamp), CASE WHEN timestamp GLOB '[0-9]*' THEN CAST(timestamp AS INTEGER) ELSE 0 END)"
        time_clause = f"AND {timestamp_expr} >= strftime('%s', 'now', ? || ' hours')" if hours > 0 else ""
        time_params: list = [f"-{hours}"] if hours > 0 else []
        async with api._db._lock:
            async with api._db._db.execute(
                f"""
                SELECT COALESCE(asn_org, 'Unknown') as org,
                     COUNT(*) as count,
                     SUM(CASE WHEN is_suspicious_asn=1 THEN 1 ELSE 0 END) as suspicious_count
                FROM connection_events
                WHERE asn_org IS NOT NULL
                {time_clause}
                GROUP BY asn_org
                ORDER BY count DESC
                LIMIT 20
                """,
                tuple(time_params),
            ) as cursor:
                rows = await cursor.fetchall()
                orgs = [{"org": r[0], "count": r[1], "suspicious": r[2]} for r in rows]

        async with api._db._lock:
            async with api._db._db.execute(
                f"""
                SELECT source_ip, details
                FROM connection_events
                WHERE 1=1
                {time_clause}
                ORDER BY id DESC
                LIMIT 5000
                """,
                tuple(time_params),
            ) as cursor:
                rows = await cursor.fetchall()

                counts: dict[str, int] = {}
                for source_ip, details_value in rows:
                    details_obj = {}
                    if isinstance(details_value, str) and details_value:
                        try:
                            details_obj = json.loads(details_value)
                        except Exception:
                            details_obj = {}
                    elif isinstance(details_value, dict):
                        details_obj = details_value

                    code = api._resolve_country_code(details_obj, source_ip) or "ZZ"
                    counts[code] = counts.get(code, 0) + 1

                countries = [
                    {"country": country, "count": count}
                    for country, count in sorted(
                        counts.items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:30]
                ]

        return web.json_response({"asn_orgs": orgs, "countries": countries})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_geo_heatmap(api, request: web.Request) -> web.Response:
    if not api._check_public_dashboard_access(request):
        return api._json_auth_error()
    hours = min(int(request.query.get("hours", "24")), 168)
    try:
        async with api._db._lock:
            async with api._db._db.execute(
                """
                SELECT source_ip, details
                FROM connection_events
                WHERE COALESCE(strftime('%s', timestamp), 0) >= strftime('%s', 'now', ? || ' hours')
                ORDER BY id DESC
                LIMIT 5000
                """,
                (f"-{hours}",),
            ) as cursor:
                rows = await cursor.fetchall()

                counts: dict[str, int] = {}
                for source_ip, details_value in rows:
                    details_obj = {}
                    if isinstance(details_value, str) and details_value:
                        try:
                            details_obj = json.loads(details_value)
                        except Exception:
                            details_obj = {}
                    elif isinstance(details_value, dict):
                        details_obj = details_value

                    code = api._resolve_country_code(details_obj, source_ip)
                    if not code or code == "ZZ":
                        continue
                    counts[code] = counts.get(code, 0) + 1

                points = [
                    {"country": country, "count": count}
                    for country, count in sorted(
                        counts.items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:150]
                ]
        return web.json_response({"points": points, "hours": hours})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_threat_distribution(api, request: web.Request) -> web.Response:
    if not api._check_public_dashboard_access(request):
        return api._json_auth_error()
    try:
        async with api._db._lock:
            async with api._db._db.execute(
                """
                SELECT threat_level, COUNT(*) as count
                FROM connection_events
                GROUP BY threat_level
                ORDER BY count DESC
                """
            ) as cursor:
                rows = await cursor.fetchall()
                distribution = [{"level": r[0], "count": r[1]} for r in rows]
        return web.json_response({"distribution": distribution})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_plugin_stats(api, request: web.Request) -> web.Response:
    if not api._check_public_dashboard_access(request):
        return api._json_auth_error()
    try:
        async with api._db._lock:
            async with api._db._db.execute(
                """
                SELECT connection_type, COUNT(*) as count
                FROM connection_events
                GROUP BY connection_type
                ORDER BY count DESC
                """
            ) as cursor:
                rows = await cursor.fetchall()
                plugins = [{"plugin": r[0], "count": r[1]} for r in rows]
        return web.json_response({"plugins": plugins})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)
