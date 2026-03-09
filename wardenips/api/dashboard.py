"""
WardenIPS - Web Dashboard REST API
====================================

A lightweight async REST API built on aiohttp for real-time monitoring
of WardenIPS internals: stats, banned IPs (hashed), recent events,
and system health.

Endpoints:
  GET  /api/health              — Health check / uptime
  GET  /api/stats               — Database statistics
  GET  /api/bans                — Active ban list (hashed IPs)
  GET  /api/firewall-bans       — Active firewall IPs (plaintext operational view)
  GET  /api/events?limit=N      — Recent events
  GET  /api/firewall            — Firewall status
  GET  /api/top-attackers       — Top attacking IP hashes
  GET  /api/events-timeline     — Events grouped by hour
  GET  /api/country-stats       — Events grouped by country
  GET  /api/threat-distribution — Events grouped by threat level
  GET  /api/plugin-stats        — Events grouped by plugin/connection type
  GET  /                        — Full SPA dashboard
  GET  /v2                      — Advanced admin dashboard

The API is completely optional and controlled by the 'dashboard' section
in config.yaml.  When disabled, no port is opened.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Optional

from wardenips.core.logger import get_logger

logger = get_logger(__name__)

try:
    from aiohttp import web
    _AIOHTTP_WEB_AVAILABLE = True
except ImportError:
    _AIOHTTP_WEB_AVAILABLE = False


class DashboardAPI:
    """
    Async REST API server for WardenIPS monitoring.

    Usage:
        api = DashboardAPI(config, db, firewall, start_time)
        await api.start()
        ...
        await api.stop()
    """

    def __init__(
        self,
        config,
        db,
        firewall,
        start_time: float,
        threat_intel=None,
    ) -> None:
        self._config = config
        self._db = db
        self._firewall = firewall
        self._start_time = start_time
        self._threat_intel = threat_intel
        self._enabled: bool = False
        self._host: str = "127.0.0.1"
        self._port: int = 7680
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._api_key: str = ""
        self._initialize_config()

    def _initialize_config(self) -> None:
        dash = self._config.get_section("dashboard") if self._config.get("dashboard", None) else {}
        if not dash:
            return
        self._enabled = dash.get("enabled", False)
        self._host = dash.get("host", "127.0.0.1")
        self._port = dash.get("port", 7680)
        self._api_key = dash.get("api_key", "")

    @property
    def enabled(self) -> bool:
        return self._enabled and _AIOHTTP_WEB_AVAILABLE

    def _check_auth(self, request: web.Request) -> bool:
        """Verify API key if configured."""
        if not self._api_key:
            return True
        auth = request.headers.get("Authorization", "")
        return auth == f"Bearer {self._api_key}"

    async def start(self) -> None:
        if not self.enabled:
            return

        self._app = web.Application()
        self._app.router.add_get("/", self._handle_dashboard)
        self._app.router.add_get("/v2", self._handle_dashboard_v2)
        self._app.router.add_get("/api/health", self._handle_health)
        self._app.router.add_get("/api/stats", self._handle_stats)
        self._app.router.add_get("/api/bans", self._handle_bans)
        self._app.router.add_get("/api/firewall-bans", self._handle_firewall_bans)
        self._app.router.add_get("/api/events", self._handle_events)
        self._app.router.add_get("/api/firewall", self._handle_firewall)
        self._app.router.add_get("/api/top-attackers", self._handle_top_attackers)
        self._app.router.add_get("/api/events-timeline", self._handle_events_timeline)
        self._app.router.add_get("/api/country-stats", self._handle_country_stats)
        self._app.router.add_get("/api/threat-distribution", self._handle_threat_distribution)
        self._app.router.add_get("/api/plugin-stats", self._handle_plugin_stats)
        self._app.router.add_get("/api/threat-intel", self._handle_threat_intel)

        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()
        logger.info(
            "Dashboard API started on http://%s:%d",
            self._host, self._port,
        )

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            logger.info("Dashboard API stopped.")

    # ── Core Handlers ──

    async def _handle_health(self, request: web.Request) -> web.Response:
        uptime = int(time.monotonic() - self._start_time)
        m, s = divmod(uptime, 60)
        h, m = divmod(m, 60)
        return web.json_response({
            "status": "ok",
            "uptime": f"{h:02d}:{m:02d}:{s:02d}",
            "uptime_seconds": uptime,
        })

    async def _handle_stats(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        stats = await self._db.get_stats()
        banned_count = await self._firewall.get_banned_count()
        stats["firewall_active_bans"] = banned_count
        stats["simulation_mode"] = self._firewall.simulation_mode
        return web.json_response(stats)

    async def _handle_bans(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            async with self._db._lock:
                async with self._db._db.execute(
                    """
                    SELECT ip_hash, reason, risk_score, ban_duration,
                           banned_at, expires_at, is_active
                    FROM ban_history
                    WHERE is_active = 1
                    ORDER BY banned_at DESC
                    LIMIT 100
                    """
                ) as cursor:
                    rows = await cursor.fetchall()
                    columns = [d[0] for d in cursor.description]
                    bans = [dict(zip(columns, row)) for row in rows]
            return web.json_response({"bans": bans, "count": len(bans)})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_events(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        limit = min(int(request.query.get("limit", "50")), 200)
        try:
            async with self._db._lock:
                async with self._db._db.execute(
                    """
                    SELECT id, timestamp, ip_hash, player_name,
                           connection_type, asn_number, asn_org,
                           country_code, is_datacenter, risk_score,
                           threat_level, details
                    FROM connection_events
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ) as cursor:
                    rows = await cursor.fetchall()
                    columns = [d[0] for d in cursor.description]
                    events = [dict(zip(columns, row)) for row in rows]
            return web.json_response({"events": events, "count": len(events)})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_firewall(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        count = await self._firewall.get_banned_count()
        return web.json_response({
            "simulation_mode": self._firewall.simulation_mode,
            "active_bans": count,
            "firewall": repr(self._firewall),
        })

    async def _handle_firewall_bans(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        limit = min(int(request.query.get("limit", "500")), 2000)
        try:
            items = await self._firewall.list_banned_ips(limit=limit)
            return web.json_response({"items": items, "count": len(items)})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    # ── Analytics Handlers ──

    async def _handle_top_attackers(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        limit = min(int(request.query.get("limit", "10")), 50)
        try:
            async with self._db._lock:
                async with self._db._db.execute(
                    """
                    SELECT ip_hash,
                           COUNT(*) as ban_count,
                           MAX(risk_score) as max_risk,
                           MAX(banned_at) as last_ban
                    FROM ban_history
                    GROUP BY ip_hash
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

    async def _handle_events_timeline(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        hours = min(int(request.query.get("hours", "24")), 168)
        try:
            async with self._db._lock:
                async with self._db._db.execute(
                    """
                    SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                           COUNT(*) as count
                    FROM connection_events
                    WHERE timestamp >= datetime('now', ? || ' hours')
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

    async def _handle_country_stats(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            async with self._db._lock:
                async with self._db._db.execute(
                    """
                    SELECT COALESCE(country_code, 'Unknown') as country,
                           COUNT(*) as count
                    FROM connection_events
                    WHERE country_code IS NOT NULL
                    GROUP BY country_code
                    ORDER BY count DESC
                    LIMIT 20
                    """
                ) as cursor:
                    rows = await cursor.fetchall()
                    countries = [{"country": r[0], "count": r[1]} for r in rows]
            return web.json_response({"countries": countries})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_threat_distribution(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            async with self._db._lock:
                async with self._db._db.execute(
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

    async def _handle_plugin_stats(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            async with self._db._lock:
                async with self._db._db.execute(
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

    async def _handle_threat_intel(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        if not self._threat_intel:
            return web.json_response({
                "enabled": False,
                "mode": "disabled",
                "description": "Threat intelligence sync is not configured.",
                "peers": [],
            })
        try:
            return web.json_response(await self._threat_intel.get_status())
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    # ── Dashboard SPA ──

    async def _handle_dashboard(self, request: web.Request) -> web.Response:
        return web.Response(text=DASHBOARD_HTML, content_type="text/html")

    async def _handle_dashboard_v2(self, request: web.Request) -> web.Response:
      return web.Response(text=DASHBOARD_V2_HTML, content_type="text/html")


# ══════════════════════════════════════════════════════════════════════
#  Full SPA Dashboard — Dark theme, auto-refresh, CSS-only charts
# ══════════════════════════════════════════════════════════════════════

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WardenIPS Dashboard</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0e17;--card:#111827;--card-h:#1a2332;
  --bdr:#1e293b;--bdr-g:#3b82f620;
  --txt:#e2e8f0;--dim:#64748b;--dim2:#475569;
  --accent:#3b82f6;--accent-g:#3b82f640;
  --red:#ef4444;--red-d:#dc262620;
  --warn:#f59e0b;--warn-d:#f59e0b20;
  --grn:#10b981;--grn-d:#10b98120;
  --pur:#8b5cf6;--pur-d:#8b5cf620;
  --cyan:#06b6d4;--cyan-d:#06b6d420;
  --r:12px;--rs:8px;
}
html{font-size:15px;scroll-behavior:smooth}
body{font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 20% 50%,#3b82f608 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,#8b5cf608 0%,transparent 50%),radial-gradient(ellipse at 50% 80%,#06b6d405 0%,transparent 50%);pointer-events:none;z-index:0}
.sh{max-width:1440px;margin:0 auto;padding:1.5rem;position:relative;z-index:1}
header{display:flex;align-items:center;justify-content:space-between;padding:1rem 0 2rem;flex-wrap:wrap;gap:1rem}
.logo{display:flex;align-items:center;gap:.75rem}
.logo svg{width:36px;height:36px;filter:drop-shadow(0 0 8px var(--accent-g))}
.logo h1{font-size:1.5rem;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.meta{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.bdg{display:inline-flex;align-items:center;gap:.4rem;padding:.35rem .75rem;border-radius:20px;font-size:.75rem;font-weight:600;letter-spacing:.03em}
.bdg-live{background:var(--grn-d);color:var(--grn);animation:pls 2s infinite}
.bdg-sim{background:var(--warn-d);color:var(--warn)}
@keyframes pls{0%,100%{opacity:1}50%{opacity:.6}}
.dot{width:6px;height:6px;border-radius:50%;background:var(--grn);display:inline-block;margin-right:4px}

/* Stats */
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1rem;margin-bottom:2rem}
.sc{background:var(--card);border:1px solid var(--bdr);border-radius:var(--r);padding:1.25rem 1.5rem;transition:all .25s ease;position:relative;overflow:hidden}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent);border-radius:var(--r) var(--r) 0 0;opacity:.6;transition:opacity .3s}
.sc:hover{transform:translateY(-2px);border-color:var(--accent);box-shadow:0 8px 32px var(--accent-g)}
.sc:hover::before{opacity:1}
.sc.dng::before{background:var(--red)}.sc.wrn::before{background:var(--warn)}.sc.suc::before{background:var(--grn)}.sc.prp::before{background:var(--pur)}
.sc .lb{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:.5rem;display:flex;align-items:center;gap:.4rem}
.sc .lb svg{width:14px;height:14px;opacity:.7}
.sc .vl{font-size:2rem;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.vl.bl{color:var(--accent)}.vl.rd{color:var(--red)}.vl.gn{color:var(--grn)}.vl.yl{color:var(--warn)}.vl.pp{color:var(--pur)}
.sc .sb{font-size:.7rem;color:var(--dim2);margin-top:.35rem}

/* Panels */
.pn{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem}
@media(max-width:900px){.pn{grid-template-columns:1fr}}
.pl{background:var(--card);border:1px solid var(--bdr);border-radius:var(--r);overflow:hidden;transition:all .25s ease}
.pl:hover{border-color:var(--bdr-g)}
.ph{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.25rem;border-bottom:1px solid var(--bdr)}
.ph h2{font-size:.95rem;font-weight:600;display:flex;align-items:center;gap:.5rem}
.ph h2 svg{width:18px;height:18px;color:var(--accent)}
.pill{font-size:.65rem;padding:.2rem .55rem;background:var(--accent);color:#fff;border-radius:10px;font-weight:700}
.pb{padding:1.25rem;max-height:420px;overflow-y:auto}
.pb::-webkit-scrollbar{width:4px}
.pb::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:4px}
.fw{grid-column:1/-1}

/* Bar Chart */
.cb{display:flex;flex-direction:column;gap:.5rem}
.br{display:flex;align-items:center;gap:.75rem}
.bl2{min-width:90px;font-size:.75rem;color:var(--dim);text-align:right;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bt{flex:1;height:26px;background:#1e293b;border-radius:6px;overflow:hidden;position:relative}
.bf{height:100%;border-radius:6px;transition:width .8s cubic-bezier(.25,.46,.45,.94);display:flex;align-items:center;padding:0 .6rem;font-size:.7rem;font-weight:600;color:#fff;white-space:nowrap;min-width:fit-content}
.bf.c0{background:linear-gradient(90deg,#3b82f6,#60a5fa)}
.bf.c1{background:linear-gradient(90deg,#ef4444,#f87171)}
.bf.c2{background:linear-gradient(90deg,#10b981,#34d399)}
.bf.c3{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.bf.c4{background:linear-gradient(90deg,#8b5cf6,#a78bfa)}
.bf.c5{background:linear-gradient(90deg,#06b6d4,#22d3ee)}

/* Timeline */
.tc{display:flex;align-items:flex-end;gap:3px;height:160px;padding-top:1rem}
.tb{flex:1;min-width:4px;background:linear-gradient(to top,var(--accent),var(--cyan));border-radius:3px 3px 0 0;transition:height .6s cubic-bezier(.25,.46,.45,.94);position:relative;cursor:pointer}
.tb:hover{opacity:.8}
.tb:hover::after{content:attr(data-t);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#1e293b;color:var(--txt);font-size:.65rem;padding:.3rem .5rem;border-radius:4px;white-space:nowrap;z-index:10;box-shadow:0 4px 24px #00000040}
.tl{display:flex;gap:3px;margin-top:.4rem}
.tl span{flex:1;font-size:.55rem;color:var(--dim2);text-align:center;overflow:hidden;text-overflow:ellipsis}

/* Table */
.t{width:100%;border-collapse:separate;border-spacing:0}
.t th{text-align:left;font-size:.65rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);padding:.6rem .75rem;border-bottom:1px solid var(--bdr);position:sticky;top:0;background:var(--card);z-index:2}
.t td{padding:.55rem .75rem;font-size:.8rem;border-bottom:1px solid #1e293b10;vertical-align:middle}
.t tr:hover td{background:var(--card-h)}
.h{font-family:'Fira Code','Cascadia Code',monospace;font-size:.7rem;color:var(--dim);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rb{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;font-weight:700;min-width:38px;text-align:center}
.rh{background:var(--red-d);color:var(--red)}.rm{background:var(--warn-d);color:var(--warn)}.rl{background:var(--grn-d);color:var(--grn)}
.tg{display:inline-block;padding:.1rem .45rem;border-radius:4px;font-size:.65rem;font-weight:600;text-transform:uppercase}
.tg-H,.tg-C{background:var(--red-d);color:var(--red)}
.tg-M{background:var(--warn-d);color:var(--warn)}
.tg-L{background:var(--grn-d);color:var(--grn)}
.tg-N{background:#1e293b;color:var(--dim2)}
.pt{display:inline-block;padding:.1rem .45rem;border-radius:4px;font-size:.65rem;font-weight:600;background:var(--cyan-d);color:var(--cyan)}
.em{padding:2rem;text-align:center;color:var(--dim2);font-size:.85rem}
.em svg{width:40px;height:40px;margin-bottom:.75rem;opacity:.3}
.mesh-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem;margin-bottom:1rem}
.mesh-stat{padding:.9rem;border:1px solid var(--bdr);border-radius:10px;background:#0f172a}
.mesh-stat .k{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:.35rem}
.mesh-stat .v{font-size:1.1rem;font-weight:700}
.mesh-topology{display:grid;place-items:center;min-height:220px;margin:1rem 0 1.2rem;border:1px solid var(--bdr);border-radius:14px;background:radial-gradient(circle at center,#13233d 0%,#0f172a 42%,#0b1220 100%);overflow:hidden;position:relative}
.mesh-topology::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at center,#3b82f61c 0%,transparent 52%);pointer-events:none}
.mesh-canvas{position:relative;width:min(100%,520px);height:200px}
.mesh-node{position:absolute;display:flex;align-items:center;justify-content:center;border-radius:999px;border:1px solid var(--bdr);font-size:.72rem;font-weight:700;letter-spacing:.01em;box-shadow:0 10px 28px #00000035}
.mesh-node.local{left:50%;top:50%;transform:translate(-50%,-50%);width:112px;height:112px;background:linear-gradient(135deg,#2563eb,#0f766e);color:#eff6ff;border-color:#60a5fa}
.mesh-node.peer{width:78px;height:78px;background:#111827;color:var(--txt)}
.mesh-node.peer.ok{border-color:#34d399;background:linear-gradient(135deg,#0f172a,#0b2b22)}
.mesh-node.peer.bad{border-color:#f87171;background:linear-gradient(135deg,#0f172a,#311313)}
.mesh-line{position:absolute;height:2px;transform-origin:left center;background:linear-gradient(90deg,#60a5fa55,#22d3ee20)}
.mesh-node small{display:block;font-size:.62rem;color:#cbd5e1;font-weight:600;opacity:.85}
.peer-list{display:grid;gap:.65rem}
.peer-card{padding:.85rem 1rem;border:1px solid var(--bdr);border-radius:10px;background:#0f172a}
.peer-head{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:.45rem}
.peer-url{font-size:.8rem;font-weight:700;color:var(--txt);word-break:break-all}
.peer-meta{font-size:.72rem;color:var(--dim);display:flex;gap:.85rem;flex-wrap:wrap}
.st{display:inline-flex;align-items:center;gap:.35rem;padding:.2rem .5rem;border-radius:999px;font-size:.68rem;font-weight:700}
.st.ok{background:var(--grn-d);color:var(--grn)}
.st.bad{background:var(--red-d);color:var(--red)}
.desc{font-size:.78rem;line-height:1.5;color:var(--dim);margin-bottom:.9rem}
footer{text-align:center;padding:2rem 0 1rem;color:var(--dim2);font-size:.75rem}
footer a{color:var(--accent);text-decoration:none}
footer a:hover{text-decoration:underline}
.kofi-fab{position:fixed;right:18px;bottom:18px;z-index:20;display:inline-flex;align-items:center;gap:.45rem;padding:.55rem .9rem;border-radius:999px;background:linear-gradient(135deg,#1f2937,#111827);border:1px solid #334155;color:#e2e8f0;text-decoration:none;font-size:.78rem;font-weight:700;box-shadow:0 10px 30px #00000055;transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease;backdrop-filter:blur(4px)}
.kofi-fab .heart{font-size:.9rem;line-height:1;color:#fb7185}
.kofi-fab .sub{font-size:.68rem;color:var(--dim);font-weight:600}
.kofi-fab:hover{transform:translateY(-2px);border-color:#38bdf8;box-shadow:0 14px 34px #00000070;text-decoration:none}
@keyframes kofiPulse{0%,100%{box-shadow:0 10px 30px #00000055}50%{box-shadow:0 12px 34px #0ea5e93a}}
.kofi-fab{animation:kofiPulse 3.4s ease-in-out infinite}
@keyframes fi{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.ai{animation:fi .4s cubic-bezier(.4,0,.2,1) both}
.d1{animation-delay:.05s}.d2{animation-delay:.1s}.d3{animation-delay:.15s}.d4{animation-delay:.2s}.d5{animation-delay:.25s}.d6{animation-delay:.3s}
@media(max-width:900px){.mesh-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:640px){.sg{grid-template-columns:repeat(2,1fr)}.sc .vl{font-size:1.5rem}.logo h1{font-size:1.2rem}.sh{padding:1rem}.kofi-fab{right:12px;bottom:12px;padding:.5rem .75rem}.kofi-fab .sub{display:none}.mesh-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="sh">
  <header>
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--accent)"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <h1>WardenIPS</h1>
    </div>
    <div class="meta">
      <span class="bdg bdg-live" id="sb"><span class="dot"></span>LIVE</span>
      <span style="font-size:.8rem;color:var(--dim)" id="ut">--:--:--</span>
    </div>
  </header>

  <div class="sg">
    <div class="sc ai d1"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Uptime</div><div class="vl bl" id="su">--:--:--</div></div>
    <div class="sc ai d2"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Total Events</div><div class="vl bl" id="se">0</div></div>
    <div class="sc dng ai d3"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>Total Bans</div><div class="vl rd" id="stb">0</div></div>
    <div class="sc wrn ai d4"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Active Bans</div><div class="vl yl" id="sab">0</div></div>
    <div class="sc suc ai d5"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Firewall</div><div class="vl gn" id="sfw">0</div></div>
    <div class="sc prp ai d6"><div class="lb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>Mode</div><div class="vl pp" id="sm">--</div></div>
  </div>

  <div class="pn">
    <div class="pl fw ai d2">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></svg>Events Timeline (24h)</h2></div>
      <div class="pb" style="overflow:visible"><div class="tc" id="tlc"></div><div class="tl" id="tll"></div></div>
    </div>
    <div class="pl ai d3">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Threat Levels</h2></div>
      <div class="pb"><div class="cb" id="thc"></div></div>
    </div>
    <div class="pl ai d4">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>Top Countries</h2></div>
      <div class="pb"><div class="cb" id="coc"></div></div>
    </div>
    <div class="pl ai d3">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="M20 8v6m3-3h-6"/></svg>Top Attackers</h2><span class="pill" id="ac">0</span></div>
      <div class="pb"><div class="cb" id="atc"></div></div>
    </div>
    <div class="pl ai d4">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/></svg>Plugins</h2></div>
      <div class="pb"><div class="cb" id="plc"></div></div>
    </div>
  </div>

  <div class="pn">
    <div class="pl fw ai d2">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 7 7 17"/><path d="M7 7h10v10"/><path d="M5 5h4"/><path d="M15 19h4"/></svg>Threat Mesh</h2><span class="pill" id="tic">0</span></div>
      <div class="pb">
        <div class="desc" id="tid">Threat intelligence is disabled.</div>
        <div class="mesh-grid">
          <div class="mesh-stat"><div class="k">Mode</div><div class="v" id="tim">Disabled</div></div>
          <div class="mesh-stat"><div class="k">Peers</div><div class="v" id="tip">0</div></div>
          <div class="mesh-stat"><div class="k">Hashes Shared</div><div class="v" id="tis">0</div></div>
          <div class="mesh-stat"><div class="k">Hashes Received</div><div class="v" id="tir">0</div></div>
        </div>
        <div class="mesh-topology"><div class="mesh-canvas" id="tmc"></div></div>
        <div class="peer-list" id="til"></div>
      </div>
    </div>
    <div class="pl fw ai d2">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>Active Bans</h2><span class="pill" id="bc">0</span></div>
      <div class="pb" style="max-height:350px">
        <table class="t" id="bnt"><thead><tr><th>IP Hash</th><th>Risk</th><th>Reason</th><th>Duration</th><th>Banned At</th><th>Expires</th></tr></thead><tbody id="bnb"></tbody></table>
        <div class="em" id="bne" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg><div>No active bans — all clear!</div></div>
      </div>
    </div>
    <div class="pl fw ai d3">
      <div class="ph"><h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Recent Events</h2><span class="pill" id="ec">0</span></div>
      <div class="pb" style="max-height:400px">
        <table class="t" id="evt"><thead><tr><th>Time</th><th>IP Hash</th><th>Plugin</th><th>User</th><th>Country</th><th>Risk</th><th>Threat</th><th>ASN</th></tr></thead><tbody id="evb"></tbody></table>
        <div class="em" id="eve" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><div>No events recorded yet</div></div>
      </div>
    </div>
  </div>

  <footer>WardenIPS &mdash; Autonomous Intrusion Prevention &middot; <a href="https://github.com" target="_blank" rel="noopener">GitHub</a></footer>
</div>

<a class="kofi-fab" href="https://ko-fi.com/msncakma" target="_blank" rel="noopener" title="Support WardenIPS on Ko-fi">
  <span class="heart">♥</span>
  <span>Support the project <span class="sub">on Ko-fi</span></span>
</a>

<script>
(function(){
'use strict';
var R=1000;
function $(s){return document.querySelector(s)}
function N(n){return(n||0).toLocaleString()}
function E(s){var d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
function T(iso){
  if(!iso)return'-';
  var d=new Date(iso+'Z'),n=new Date(),df=Math.floor((n-d)/1000);
  if(df<60)return df+'s ago';if(df<3600)return Math.floor(df/60)+'m ago';
  if(df<86400)return Math.floor(df/3600)+'h ago';return Math.floor(df/86400)+'d ago';
}
function D(s){
  if(!s||s<=0)return'Permanent';
  if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';
  return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
}
function TG(iso){return iso?T(iso):'-'}
function RC(r){return r>=70?'rh':r>=40?'rm':'rl'}
function CF(c){
  if(!c||c.length!==2)return'';
  return String.fromCodePoint(...[...c.toUpperCase()].map(x=>x.charCodeAt(0)+127397));
}
var CC=['c0','c1','c2','c3','c4','c5'];
async function A(p){try{var r=await fetch(p);if(!r.ok)return null;return await r.json()}catch(e){return null}}

function bars(id,items,lk,vk,ci){
  var el=$('#'+id);
  if(!items||!items.length){el.innerHTML='<div class="em" style="padding:1rem 0"><div>No data</div></div>';return}
  var mx=Math.max(...items.map(function(i){return i[vk]}),1);
  el.innerHTML=items.map(function(it,idx){
    var pct=Math.max((it[vk]/mx)*100,3);
    var c=CC[((ci||0)+idx)%6];
    var lb=it[lk]||'Unknown';
    var em=lk==='country'?CF(lb)+' ':'';
    return '<div class="br"><span class="bl2">'+em+E(lb)+'</span><div class="bt"><div class="bf '+c+'" style="width:'+pct+'%">'+N(it[vk])+'</div></div></div>';
  }).join('');
}

function renderThreatIntel(ti){
  $('#tic').textContent = ti&&ti.peers ? ti.peers.length : 0;
  $('#tim').textContent = ti&&ti.enabled ? (ti.mode||'Enabled') : 'Disabled';
  $('#tip').textContent = N(ti&&ti.peers ? ti.peers.length : 0);
  $('#tis').textContent = N(ti&&ti.shared_total ? ti.shared_total : 0);
  $('#tir').textContent = N(ti&&ti.received_total ? ti.received_total : 0);
  $('#tid').textContent = ti&&ti.description ? ti.description : 'Threat intelligence is disabled.';
  var list = $('#til');
  var canvas = $('#tmc');
  if(!ti||!ti.enabled||!ti.peers||!ti.peers.length){
    list.innerHTML = '<div class="em" style="padding:1rem 0"><div>No peers configured</div></div>';
    canvas.innerHTML = '<div class="mesh-node local">This Node<small>No peers</small></div>';
    return;
  }
  var peers = ti.peers.slice(0, 6);
  var centerX = 260;
  var centerY = 100;
  var radius = peers.length > 1 ? 78 : 0;
  var html = '<div class="mesh-node local" style="left:'+centerX+'px;top:'+centerY+'px">This Node<small>'+E(ti.mode||'mesh')+'</small></div>';
  peers.forEach(function(peer, idx){
    var angle = peers.length === 1 ? 0 : ((Math.PI * 2) / peers.length) * idx - Math.PI / 2;
    var x = centerX + Math.cos(angle) * radius;
    var y = centerY + Math.sin(angle) * radius;
    var dx = x - centerX;
    var dy = y - centerY;
    var len = Math.sqrt((dx * dx) + (dy * dy));
    var deg = Math.atan2(dy, dx) * (180 / Math.PI);
    var cls = peer.reachable ? 'ok' : 'bad';
    html += '<div class="mesh-line" style="left:'+centerX+'px;top:'+centerY+'px;width:'+len+'px;transform:rotate('+deg+'deg)"></div>';
    html += '<div class="mesh-node peer '+cls+'" style="left:'+x+'px;top:'+y+'px;transform:translate(-50%,-50%)" title="'+E(peer.peer||'peer')+'">Peer '+(idx+1)+'<small>'+(peer.reachable?'online':'offline')+'</small></div>';
  });
  canvas.innerHTML = html;
  list.innerHTML = ti.peers.map(function(peer){
    var ok = !!peer.reachable;
    return '<div class="peer-card">'
      + '<div class="peer-head"><div class="peer-url">'+E(peer.peer||'unknown')+'</div><span class="st '+(ok?'ok':'bad')+'">'+(ok?'Reachable':'Offline')+'</span></div>'
      + '<div class="peer-meta">'
      + '<span>Last success: '+TG(peer.last_success_at)+'</span>'
      + '<span>Last attempt: '+TG(peer.last_attempt_at)+'</span>'
      + '<span>New hashes: '+N(peer.last_received_count||0)+'</span>'
      + '<span>Total received: '+N(peer.total_received||0)+'</span>'
      + (peer.last_error?'<span>Error: '+E(peer.last_error)+'</span>':'')
      + '</div></div>';
  }).join('');
}

async function refresh(){
  var h=await A('/api/health');
  var s=await A('/api/stats');
  var bn=await A('/api/bans');
  var ev=await A('/api/events?limit=50');
  var tl=await A('/api/events-timeline?hours=24');
  var co=await A('/api/country-stats');
  var th=await A('/api/threat-distribution');
  var pg=await A('/api/plugin-stats');
  var at=await A('/api/top-attackers?limit=10');
  var ti=await A('/api/threat-intel');

  // Health
  if(h){$('#su').textContent=h.uptime||'--:--:--';$('#ut').textContent='Uptime: '+(h.uptime||'--:--:--')}

  // Stats
  if(s){
    $('#se').textContent=N(s.total_events);
    $('#stb').textContent=N(s.total_bans);
    $('#sab').textContent=N(s.active_bans);
    $('#sfw').textContent=N(s.firewall_active_bans);
    var sim=s.simulation_mode;
    $('#sm').textContent=sim?'SIM':'LIVE';
    $('#sm').className='vl '+(sim?'yl':'gn');
    var bd=$('#sb');
    if(sim){bd.className='bdg bdg-sim';bd.innerHTML='SIMULATION'}
    else{bd.className='bdg bdg-live';bd.innerHTML='<span class="dot"></span>LIVE'}
  }

  // Bans Table
  var btb=$('#bnb'),be=$('#bne'),bp=$('#bc');
  if(!bn||!bn.bans||!bn.bans.length){btb.innerHTML='';be.style.display='block';bp.textContent='0'}
  else{be.style.display='none';bp.textContent=bn.count;
    btb.innerHTML=bn.bans.map(function(b){
      return '<tr><td class="h" title="'+E(b.ip_hash)+'">'+E((b.ip_hash||'').substring(0,16))+'&hellip;</td><td><span class="rb '+RC(b.risk_score)+'">'+b.risk_score+'</span></td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(b.reason)+'">'+E(b.reason)+'</td><td>'+D(b.ban_duration)+'</td><td>'+T(b.banned_at)+'</td><td>'+(b.expires_at?T(b.expires_at):'Never')+'</td></tr>';
    }).join('')}

  // Events Table
  var etb=$('#evb'),ee=$('#eve'),ep=$('#ec');
  if(!ev||!ev.events||!ev.events.length){etb.innerHTML='';ee.style.display='block';ep.textContent='0'}
  else{ee.style.display='none';ep.textContent=ev.count;
    etb.innerHTML=ev.events.map(function(e){
      var fl=CF(e.country_code);
      var pl=(e.connection_type||'unknown').toUpperCase();
      var tc=e.threat_level;
      var tcl=tc==='HIGH'||tc==='CRITICAL'?'tg-H':tc==='MEDIUM'?'tg-M':tc==='LOW'?'tg-L':'tg-N';
      return '<tr><td style="white-space:nowrap;font-size:.75rem">'+T(e.timestamp)+'</td><td class="h" title="'+E(e.ip_hash)+'">'+E((e.ip_hash||'').substring(0,14))+'&hellip;</td><td><span class="pt">'+E(pl)+'</span></td><td>'+E(e.player_name||'-')+'</td><td>'+(fl?'<span style="font-size:1.1rem;margin-right:.3rem">'+fl+'</span>':'')+E(e.country_code||'-')+'</td><td><span class="rb '+RC(e.risk_score)+'">'+e.risk_score+'</span></td><td><span class="tg '+tcl+'">'+E(tc)+'</span></td><td style="font-size:.75rem;color:var(--dim);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+E(e.asn_org)+'">'+E(e.asn_org||'-')+'</td></tr>';
    }).join('')}

  // Timeline
  var tc2=$('#tlc'),tl2=$('#tll');
  if(!tl||!tl.timeline||!tl.timeline.length){tc2.innerHTML='<div class="em" style="width:100%;padding:2rem 0"><div>No timeline data</div></div>';tl2.innerHTML=''}
  else{
    var mx=Math.max(...tl.timeline.map(function(t){return t.count}),1);
    tc2.innerHTML=tl.timeline.map(function(t){
      var pct=Math.max((t.count/mx)*100,2);
      var hr=t.hour?(t.hour.split(' ')[1]||t.hour):'';
      return '<div class="tb" style="height:'+pct+'%" data-t="'+hr+': '+t.count+' events"></div>';
    }).join('');
    tl2.innerHTML=tl.timeline.map(function(t,i){
      var hr=t.hour?(t.hour.split(' ')[1]||''):'';
      var show=i%Math.max(1,Math.floor(tl.timeline.length/12))===0;
      return '<span>'+(show?hr:'')+'</span>';
    }).join('')}

  // Threat Distribution
  if(th&&th.distribution){
    var cm={HIGH:1,CRITICAL:1,MEDIUM:3,LOW:2,NONE:5};
    var el=$('#thc');
    var tmx=Math.max(...th.distribution.map(function(d){return d.count}),1);
    el.innerHTML=th.distribution.map(function(d){
      var pct=Math.max((d.count/tmx)*100,3);
      return '<div class="br"><span class="bl2">'+E(d.level)+'</span><div class="bt"><div class="bf '+CC[cm[d.level]||0]+'" style="width:'+pct+'%">'+N(d.count)+'</div></div></div>';
    }).join('')}
  else bars('thc',[],'level','count',0);

  // Country
  bars('coc',co?co.countries:null,'country','count',2);

  // Plugins
  bars('plc',pg?pg.plugins:null,'plugin','count',3);

  // Attackers
  var ap=$('#ac');
  if(at&&at.attackers){ap.textContent=at.attackers.length;
    var ait=at.attackers.map(function(a){return{label:(a.ip_hash||'').substring(0,16)+'…',count:a.ban_count}});
    bars('atc',ait,'label','count',1)}
  else{ap.textContent='0';bars('atc',[],'label','count',1)}

  renderThreatIntel(ti);
}

refresh();
setInterval(refresh,R);
})();
</script>
</body>
</html>"""


DASHBOARD_V2_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WardenIPS Dashboard V2</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#08111f;--bg2:#0d1728;--panel:#111c30;--panel2:#0f1a2c;--b:#22304a;
  --txt:#e7edf7;--muted:#8da0bd;--blue:#4f8cff;--cyan:#19c2d8;--green:#13c38b;--yellow:#f4b740;--red:#f15b6c;
}
body{font-family:Inter,Segoe UI,system-ui,sans-serif;background:radial-gradient(circle at top,#12203a 0%,#08111f 45%,#070d18 100%);color:var(--txt);min-height:100vh}
.app{max-width:1560px;margin:0 auto;padding:24px}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.brand h1{font-size:1.8rem;font-weight:800;letter-spacing:-.03em}
.brand p{font-size:.88rem;color:var(--muted);margin-top:4px}
.actions{display:flex;gap:10px;flex-wrap:wrap}
.ctrl,.btn{background:var(--panel);border:1px solid var(--b);color:var(--txt);border-radius:10px;padding:10px 12px;font-size:.88rem}
.btn{cursor:pointer;font-weight:700}.btn.primary{background:linear-gradient(135deg,var(--blue),#375ff5);border-color:#4f8cff}
.hero{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:18px}
.hero-card,.side-card,.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--b);border-radius:16px;padding:16px}
.hero-card h2,.card h2,.side-card h2{font-size:.96rem;font-weight:800;margin-bottom:10px}
.hero-meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.metric{padding:14px;border:1px solid var(--b);border-radius:12px;background:#0b1527}
.metric .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px}
.metric .v{font-size:1.6rem;font-weight:800}
.layout{display:grid;grid-template-columns:1.3fr 1fr;gap:16px}
.stack{display:grid;gap:16px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.search{flex:1;min-width:220px}
.table-wrap{max-height:420px;overflow:auto;border:1px solid var(--b);border-radius:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #1b2940;font-size:.84rem;vertical-align:middle}
th{position:sticky;top:0;background:#0b1527;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
tr:hover td{background:#0f1d32}
.mono{font-family:Cascadia Code,Fira Code,monospace;font-size:.76rem}
.tag{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:999px;font-size:.72rem;font-weight:800}
.t-red{background:#3b131b;color:#ff97a4}.t-green{background:#0e2d25;color:#79efc6}.t-yellow{background:#392b0d;color:#ffd27f}.t-blue{background:#102543;color:#8eb8ff}
.split{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.list{display:grid;gap:10px}
.list-item{padding:12px;border:1px solid var(--b);border-radius:12px;background:#0b1527}
.list-item strong{display:block;margin-bottom:6px}
.sub{font-size:.78rem;color:var(--muted);line-height:1.5}
.empty{padding:24px;text-align:center;color:var(--muted)}
.small{font-size:.76rem;color:var(--muted)}
.linkbar{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}.linkbar a{color:#9fc5ff;text-decoration:none;font-size:.82rem}
@media(max-width:1100px){.hero,.layout,.split{grid-template-columns:1fr}.hero-meta{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:680px){.app{padding:14px}.hero-meta{grid-template-columns:1fr}.actions{width:100%}.ctrl,.btn{width:100%}}
</style>
</head>
<body>
<div class="app">
  <div class="top">
    <div class="brand">
      <h1>WardenIPS Admin Console</h1>
      <p>Interactive operational view for bans, firewall state, events, and peer intelligence.</p>
      <div class="linkbar">
        <a href="/">Open Dashboard v1</a>
        <a href="https://ko-fi.com/msncakma" target="_blank" rel="noopener">Support on Ko-fi</a>
      </div>
    </div>
    <div class="actions">
      <input id="globalSearch" class="ctrl search" placeholder="Filter events, hashes, plugins, countries, IPs...">
      <select id="refreshRate" class="ctrl">
        <option value="1000">Refresh 1s</option>
        <option value="3000">Refresh 3s</option>
        <option value="5000">Refresh 5s</option>
      </select>
      <button id="refreshNow" class="btn primary">Refresh Now</button>
    </div>
  </div>

  <div class="hero">
    <div class="hero-card">
      <h2>Operational Summary</h2>
      <div class="hero-meta">
        <div class="metric"><div class="k">Total Events</div><div class="v" id="mEvents">0</div></div>
        <div class="metric"><div class="k">Active DB Bans</div><div class="v" id="mDbBans">0</div></div>
        <div class="metric"><div class="k">Firewall IPs</div><div class="v" id="mFwBans">0</div></div>
        <div class="metric"><div class="k">Threat Mesh Peers</div><div class="v" id="mPeers">0</div></div>
      </div>
    </div>
    <div class="side-card">
      <h2>Runtime</h2>
      <div class="list">
        <div class="list-item"><strong id="runtimeMode">Mode: --</strong><span class="sub" id="runtimeUptime">Uptime: --</span></div>
        <div class="list-item"><strong>Privacy Model</strong><span class="sub">Database events and ban history store hashed IP identifiers. Raw IPs are shown only for currently active firewall entries.</span></div>
      </div>
    </div>
  </div>

  <div class="layout">
    <div class="stack">
      <div class="card">
        <h2>Recent Security Events</h2>
        <div class="toolbar">
          <select id="eventPluginFilter" class="ctrl">
            <option value="">All Plugins</option>
          </select>
          <select id="eventThreatFilter" class="ctrl">
            <option value="">All Threats</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="NONE">None</option>
          </select>
          <select id="eventSort" class="ctrl">
            <option value="time">Sort: Newest</option>
            <option value="risk">Sort: Highest Risk</option>
          </select>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Hash</th><th>Plugin</th><th>Country</th><th>Risk</th><th>Threat</th><th>ASN</th></tr></thead>
            <tbody id="eventsRows"></tbody>
          </table>
        </div>
      </div>

      <div class="split">
        <div class="card">
          <h2>Active Database Bans</h2>
          <div class="toolbar">
            <select id="banSort" class="ctrl">
              <option value="recent">Sort: Recent</option>
              <option value="risk">Sort: Highest Risk</option>
            </select>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Hash</th><th>Risk</th><th>Reason</th><th>Expires</th></tr></thead>
              <tbody id="banRows"></tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <h2>Active Firewall IPs</h2>
          <div class="toolbar">
            <select id="ipFamilyFilter" class="ctrl">
              <option value="">All Families</option>
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
            </select>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>IP Address</th><th>Family</th></tr></thead>
              <tbody id="firewallRows"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div class="stack">
      <div class="card">
        <h2>Threat Mesh</h2>
        <div class="list" id="meshList"></div>
      </div>
      <div class="card">
        <h2>Top Attackers</h2>
        <div class="list" id="attackerList"></div>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
'use strict';
var timer = null;
var state = {events:[], bans:[], firewall:[], attackers:[], mesh:null, stats:null, health:null};
function $(s){return document.querySelector(s)}
function N(n){return (n||0).toLocaleString()}
function E(s){var d=document.createElement('div'); d.textContent=s||''; return d.innerHTML}
function ago(iso){ if(!iso) return '-'; var d=new Date(iso+'Z'), n=new Date(), df=Math.floor((n-d)/1000); if(df<60)return df+'s'; if(df<3600)return Math.floor(df/60)+'m'; if(df<86400)return Math.floor(df/3600)+'h'; return Math.floor(df/86400)+'d'; }
function tagRisk(r){ return r>=70?'t-red':r>=40?'t-yellow':'t-green'; }
function tagThreat(t){ return t==='CRITICAL'||t==='HIGH'?'t-red':t==='MEDIUM'?'t-yellow':t==='LOW'?'t-green':'t-blue'; }
async function api(p){ try{ var r=await fetch(p); if(!r.ok)return null; return await r.json(); }catch(e){ return null; } }
function filterText(){ return ($('#globalSearch').value||'').trim().toLowerCase(); }

function renderSummary(){
  $('#mEvents').textContent = N(state.stats&&state.stats.total_events);
  $('#mDbBans').textContent = N(state.stats&&state.stats.active_bans);
  $('#mFwBans').textContent = N(state.firewall.length);
  $('#mPeers').textContent = N(state.mesh&&state.mesh.peers ? state.mesh.peers.length : 0);
  $('#runtimeMode').textContent = 'Mode: '+((state.stats&&state.stats.simulation_mode)?'Simulation':'Live');
  $('#runtimeUptime').textContent = 'Uptime: '+((state.health&&state.health.uptime)||'--');
}

function renderEvents(){
  var rows = state.events.slice();
  var q = filterText();
  var plugin = $('#eventPluginFilter').value;
  var threat = $('#eventThreatFilter').value;
  var sort = $('#eventSort').value;
  rows = rows.filter(function(e){
    var blob = [e.ip_hash,e.connection_type,e.country_code,e.threat_level,e.asn_org,e.player_name].join(' ').toLowerCase();
    return (!q || blob.indexOf(q)!==-1) && (!plugin || e.connection_type===plugin) && (!threat || e.threat_level===threat);
  });
  rows.sort(function(a,b){
    if(sort==='risk') return (b.risk_score||0)-(a.risk_score||0);
    return String(b.timestamp||'').localeCompare(String(a.timestamp||''));
  });
  $('#eventsRows').innerHTML = rows.length ? rows.map(function(e){ return '<tr>'
    + '<td>'+ago(e.timestamp)+'</td>'
    + '<td class="mono" title="'+E(e.ip_hash)+'">'+E((e.ip_hash||'').slice(0,16))+'…</td>'
    + '<td>'+E((e.connection_type||'unknown').toUpperCase())+'</td>'
    + '<td>'+E(e.country_code||'-')+'</td>'
    + '<td><span class="tag '+tagRisk(e.risk_score||0)+'">'+E(String(e.risk_score||0))+'</span></td>'
    + '<td><span class="tag '+tagThreat(e.threat_level||'NONE')+'">'+E(e.threat_level||'NONE')+'</span></td>'
    + '<td>'+E(e.asn_org||'-')+'</td>'
    + '</tr>'; }).join('') : '<tr><td colspan="7" class="empty">No events match the current filters.</td></tr>';
}

function renderBans(){
  var rows = state.bans.slice();
  var q = filterText();
  var sort = $('#banSort').value;
  rows = rows.filter(function(b){ return !q || [b.ip_hash,b.reason].join(' ').toLowerCase().indexOf(q)!==-1; });
  rows.sort(function(a,b){
    if(sort==='risk') return (b.risk_score||0)-(a.risk_score||0);
    return String(b.banned_at||'').localeCompare(String(a.banned_at||''));
  });
  $('#banRows').innerHTML = rows.length ? rows.map(function(b){ return '<tr>'
    + '<td class="mono" title="'+E(b.ip_hash)+'">'+E((b.ip_hash||'').slice(0,16))+'…</td>'
    + '<td><span class="tag '+tagRisk(b.risk_score||0)+'">'+E(String(b.risk_score||0))+'</span></td>'
    + '<td>'+E(b.reason||'-')+'</td>'
    + '<td>'+E(b.expires_at?ago(b.expires_at)+' left':'Never')+'</td>'
    + '</tr>'; }).join('') : '<tr><td colspan="4" class="empty">No active bans match the current filters.</td></tr>';
}

function renderFirewall(){
  var rows = state.firewall.slice();
  var q = filterText();
  var family = $('#ipFamilyFilter').value;
  rows = rows.filter(function(item){ return (!q || [item.ip,item.family].join(' ').toLowerCase().indexOf(q)!==-1) && (!family || item.family===family); });
  $('#firewallRows').innerHTML = rows.length ? rows.map(function(item){ return '<tr><td class="mono">'+E(item.ip)+'</td><td>'+E(item.family)+'</td></tr>'; }).join('') : '<tr><td colspan="2" class="empty">No firewall IPs match the current filters.</td></tr>';
}

function renderAttackers(){
  $('#attackerList').innerHTML = state.attackers.length ? state.attackers.map(function(a){
    return '<div class="list-item"><strong class="mono">'+E((a.ip_hash||'').slice(0,20))+'…</strong><div class="sub">Bans: '+N(a.ban_count)+' · Max risk: '+N(a.max_risk||0)+' · Last: '+ago(a.last_ban)+'</div></div>';
  }).join('') : '<div class="empty">No attacker history yet.</div>';
}

function renderMesh(){
  var mesh = state.mesh;
  if(!mesh || !mesh.enabled){ $('#meshList').innerHTML = '<div class="empty">Threat mesh is disabled.</div>'; return; }
  $('#meshList').innerHTML = (mesh.peers&&mesh.peers.length ? mesh.peers : []).map(function(peer){
    return '<div class="list-item"><strong>'+E(peer.peer||'peer')+'</strong><div class="sub">Status: '+(peer.reachable?'online':'offline')+' · New hashes: '+N(peer.last_received_count||0)+' · Total received: '+N(peer.total_received||0)+' · Last success: '+ago(peer.last_success_at)+'</div></div>';
  }).join('') || '<div class="empty">Threat mesh enabled, but no peers configured.</div>';
}

function syncPluginFilter(){
  var select = $('#eventPluginFilter');
  var current = select.value;
  var values = Array.from(new Set(state.events.map(function(e){ return e.connection_type||'unknown'; }))).sort();
  select.innerHTML = '<option value="">All Plugins</option>' + values.map(function(v){ return '<option value="'+E(v)+'">'+E(v.toUpperCase())+'</option>'; }).join('');
  select.value = values.indexOf(current)!==-1 ? current : '';
}

  async function refresh(){
    var results = await Promise.all([
      api('/api/health'),
      api('/api/stats'),
      api('/api/events?limit=120'),
      api('/api/bans'),
      api('/api/firewall-bans?limit=1000'),
      api('/api/top-attackers?limit=12'),
      api('/api/threat-intel')
    ]);
    state.health = results[0]||null;
    state.stats = results[1]||null;
    state.events = results[2]&&results[2].events ? results[2].events : [];
    state.bans = results[3]&&results[3].bans ? results[3].bans : [];
    state.firewall = results[4]&&results[4].items ? results[4].items : [];
    state.attackers = results[5]&&results[5].attackers ? results[5].attackers : [];
    state.mesh = results[6]||null;
    syncPluginFilter();
    renderSummary(); renderEvents(); renderBans(); renderFirewall(); renderAttackers(); renderMesh();
  }

  function bind(){
    ['globalSearch','eventPluginFilter','eventThreatFilter','eventSort','banSort','ipFamilyFilter'].forEach(function(id){ $( '#'+id ).addEventListener('input', function(){ renderEvents(); renderBans(); renderFirewall(); }); $( '#'+id ).addEventListener('change', function(){ renderEvents(); renderBans(); renderFirewall(); }); });
    $('#refreshNow').addEventListener('click', refresh);
    $('#refreshRate').addEventListener('change', function(){ if(timer) clearInterval(timer); timer = setInterval(refresh, parseInt(this.value,10)||1000); });
  }

  bind();
  refresh();
  timer = setInterval(refresh, parseInt($('#refreshRate').value,10)||1000);
})();
</script>
</body>
</html>"""
