"""Admin bulk and reconciliation handlers extracted from DashboardAPI monolith."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import datetime

from aiohttp import web


async def handle_admin_report_ips(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.report.execute")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    ips = payload.get("ips", [])
    if not isinstance(ips, list) or not ips:
        return web.json_response({"error": "invalid_ips", "message": "ips must be a non-empty list."}, status=400)

    try:
        categories = [int(c) for c in (payload.get("categories") or [18])]
    except Exception:
        categories = [18]
    comment = str(payload.get("comment", "Automatic report from WardenIPS") or "Automatic report from WardenIPS")

    results = []
    for raw_ip in ips:
        ip = str(raw_ip or "").strip()
        if not api._is_valid_ip(ip):
            results.append({"ip": ip, "ok": False, "error": "invalid_ip"})
            continue

        success = False
        detail = ""
        if api._abuseipdb is not None:
            try:
                success, detail = await asyncio.to_thread(api._abuseipdb.report_ip, ip, categories, comment)
            except Exception as exc:
                success, detail = False, str(exc)
        else:
            detail = "AbuseIPDB client not configured"

        results.append({"ip": ip, "ok": bool(success), "detail": detail})

    await api._log_audit(
        request,
        "admin.report_ips",
        actor_username=actor,
        details={
            "count": len(results),
            "success": sum(1 for item in results if item.get("ok")),
            "categories": categories,
        },
    )

    return web.json_response(
        {
            "ok": True,
            "count": len(results),
            "success": sum(1 for item in results if item.get("ok")),
            "results": results,
        }
    )


async def handle_admin_bulk_action(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.bulk.execute")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    action = str(payload.get("action", "") or "").strip().lower()
    ips = payload.get("ips", [])
    reason = str(payload.get("reason", "Bulk admin action") or "Bulk admin action")
    duration = payload.get("duration")

    if action not in {"ban", "unban", "whitelist_add", "whitelist_remove"}:
        return web.json_response({"error": "invalid_action", "message": "Unsupported action."}, status=400)
    if not isinstance(ips, list) or not ips:
        return web.json_response({"error": "invalid_ips", "message": "ips must be a non-empty list."}, status=400)

    processed = []
    for raw_ip in ips:
        ip = str(raw_ip or "").strip()
        if not api._is_valid_ip(ip):
            processed.append({"ip": ip, "ok": False, "error": "invalid_ip"})
            continue

        try:
            if action == "ban":
                try:
                    dur = int(duration) if duration is not None else 0
                except Exception:
                    dur = 0
                
                # Use BanService if available, otherwise fall back to direct firewall access
                if api._ban_service:
                    result = await api._ban_service.ban_ip(
                        ip=ip,
                        duration_seconds=dur,
                        reason=reason,
                        actor=actor or "admin_bulk",
                    )
                    if result.get("status") == "ok":
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": result.get("reason", "ban_failed")})
                else:
                    # Fallback: legacy direct access
                    if api._firewall and api._firewall.is_whitelisted(ip):
                        processed.append({"ip": ip, "ok": False, "error": "ip_whitelisted", "message": "IP is whitelisted."})
                        continue
                    if api._firewall and await api._firewall.ban_ip(ip, reason=reason, duration=dur):
                        await api._db.log_ban_action(ip, reason=reason, risk_score=100, duration=dur)
                        await api._notify_ban_event(
                            ip,
                            {
                                "source": "admin_bulk",
                                "reason": reason,
                                "risk_score": 100,
                                "duration": dur,
                            },
                        )
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": "ban_failed"})

            elif action == "unban":
                # Use BanService if available, otherwise fall back to direct firewall access
                if api._ban_service:
                    result = await api._ban_service.unban_ip(
                        ip=ip,
                        actor=actor or "admin_bulk",
                    )
                    if result.get("status") == "ok":
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": result.get("reason", "unban_failed")})
                else:
                    # Fallback: legacy direct access
                    if api._firewall and await api._firewall.unban_ip(ip):
                        if api._notifier:
                            await api._notifier.send_unban_notification(ip, "manual", {"source": "admin_bulk", "reason": reason})
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": "unban_failed"})

            elif action == "whitelist_add":
                # Use WhitelistService if available, otherwise fall back to firewall access
                if api._whitelist_service:
                    result = await api._whitelist_service.add_whitelist(
                        ip_or_cidr=ip,
                        reason=reason or "Bulk admin whitelist add",
                        tag="admin_bulk",
                    )
                    if result.get("status") == "ok":
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": result.get("reason", "whitelist_add_failed")})
                else:
                    # Fallback: legacy direct access
                    success = False
                    if api._firewall and hasattr(api._firewall, "add_to_whitelist"):
                        success = bool(await api._firewall.add_to_whitelist(ip))
                    if success:
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": "whitelist_add_failed"})

            elif action == "whitelist_remove":
                # Use WhitelistService if available, otherwise fall back to firewall access
                if api._whitelist_service:
                    result = await api._whitelist_service.remove_whitelist(
                        entry_id=ip,  # Using IP as entry_id for lookup
                    )
                    if result.get("status") == "ok":
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": result.get("reason", "whitelist_remove_failed")})
                else:
                    # Fallback: legacy direct access
                    success = False
                    if api._firewall and hasattr(api._firewall, "remove_from_whitelist"):
                        success = bool(await api._firewall.remove_from_whitelist(ip))
                    if success:
                        processed.append({"ip": ip, "ok": True})
                    else:
                        processed.append({"ip": ip, "ok": False, "error": "whitelist_remove_failed"})

        except Exception as exc:
            processed.append({"ip": ip, "ok": False, "error": str(exc)})

    await api._log_audit(
        request,
        "admin.bulk_action",
        actor_username=actor,
        details={
            "action": action,
            "count": len(ips),
            "success": sum(1 for item in processed if item.get("ok")),
        },
    )

    return web.json_response(
        {
            "ok": True,
            "action": action,
            "count": len(processed),
            "success": sum(1 for item in processed if item.get("ok")),
            "results": processed,
        }
    )


async def handle_admin_reconcile_firewall(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.firewall.reconcile")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)

    if not api._firewall:
        return web.json_response({"error": "firewall_unavailable", "message": "Firewall manager is not available."}, status=503)

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    source = str(payload.get("source", "db") or "db").strip().lower()
    if source not in {"db", "runtime", "all", "active_only"}:
        source = "db"

    db_records = []
    if source in {"db", "all", "active_only"}:
        if source == "active_only":
            db_records = await api._db.get_ban_history(limit=2000, active_only=True)
        else:
            db_records = await api._db.get_ban_history(limit=5000, active_only=False)

    db_ips = []
    now = datetime.now()
    for rec in db_records:
        ip = str(rec.get("source_ip", "") or "").strip()
        if not ip or not api._is_valid_ip(ip):
            continue
        if source in {"active_only", "all"}:
            if rec.get("is_active", True):
                expires_raw = rec.get("expires_at")
                if expires_raw:
                    try:
                        exp = datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
                        if exp.tzinfo is not None:
                            exp = exp.astimezone().replace(tzinfo=None)
                        if exp < now:
                            continue
                    except Exception:
                        pass
            else:
                continue
        db_ips.append(ip)

    runtime_ips = set(api._firewall.get_banned_ips())
    db_ip_set = set(db_ips)

    missing_in_firewall = sorted(list(db_ip_set - runtime_ips))
    extra_in_firewall = sorted(list(runtime_ips - db_ip_set))

    reapplied = []
    for ip in missing_in_firewall:
        if await api._firewall.ban_ip(ip, reason="Reconciled from DB", duration=None):
            reapplied.append(ip)

    removed_runtime = []
    for ip in extra_in_firewall:
        if await api._firewall.unban_ip(ip):
            removed_runtime.append(ip)

    await api._log_audit(
        request,
        "admin.reconcile_firewall",
        actor_username=actor,
        details={
            "source": source,
            "db_count": len(db_ip_set),
            "runtime_count": len(runtime_ips),
            "reapplied": len(reapplied),
            "removed_runtime": len(removed_runtime),
        },
    )

    return web.json_response(
        {
            "ok": True,
            "source": source,
            "db_count": len(db_ip_set),
            "runtime_count": len(runtime_ips),
            "missing_in_firewall": missing_in_firewall,
            "extra_in_firewall": extra_in_firewall,
            "reapplied": reapplied,
            "removed_runtime": removed_runtime,
        }
    )


async def handle_admin_deactivate_expired(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.firewall.reconcile")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)

    now = datetime.now()
    changed = []
    records = await api._db.get_ban_history(limit=5000, active_only=True)
    for rec in records:
        ip = str(rec.get("source_ip", "") or "").strip()
        expires_raw = rec.get("expires_at")
        if not ip or not expires_raw:
            continue
        try:
            exp = datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
            if exp.tzinfo is not None:
                exp = exp.astimezone().replace(tzinfo=None)
        except Exception:
            continue

        if exp >= now:
            continue

        await api._db.deactivate_ban_by_ip(ip)
        if api._firewall:
            await api._firewall.unban_ip(ip)
        changed.append(ip)

    await api._log_audit(
        request,
        "admin.deactivate_expired",
        actor_username=actor,
        details={"count": len(changed)},
    )
    return web.json_response({"ok": True, "count": len(changed), "ips": changed})


async def handle_admin_enforce_db_bans(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.firewall.reconcile")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)

    if not api._firewall:
        return web.json_response({"error": "firewall_unavailable", "message": "Firewall manager is not available."}, status=503)

    now = datetime.now()
    records = await api._db.get_ban_history(limit=5000, active_only=True)
    desired = []
    for rec in records:
        ip = str(rec.get("source_ip", "") or "").strip()
        if not ip or not api._is_valid_ip(ip):
            continue
        expires_raw = rec.get("expires_at")
        if expires_raw:
            try:
                exp = datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
                if exp.tzinfo is not None:
                    exp = exp.astimezone().replace(tzinfo=None)
                if exp < now:
                    continue
            except Exception:
                pass
        desired.append(ip)

    desired_set = set(desired)
    runtime_set = set(api._firewall.get_banned_ips())

    to_add = sorted(list(desired_set - runtime_set))
    to_remove = sorted(list(runtime_set - desired_set))

    added = []
    for ip in to_add:
        if await api._firewall.ban_ip(ip, reason="Enforced from DB", duration=None):
            added.append(ip)

    removed = []
    for ip in to_remove:
        if await api._firewall.unban_ip(ip):
            removed.append(ip)

    await api._log_audit(
        request,
        "admin.enforce_db_bans",
        actor_username=actor,
        details={"added": len(added), "removed": len(removed)},
    )

    return web.json_response(
        {
            "ok": True,
            "desired_count": len(desired_set),
            "runtime_count": len(runtime_set),
            "added": added,
            "removed": removed,
        }
    )


async def handle_admin_report_and_ban(api, request: web.Request) -> web.Response:
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
        return web.json_response({"error": "invalid_ip", "message": "IP address is required."}, status=400)
    try:
        ipaddress.ip_address(ip_value)
    except Exception:
        return web.json_response({"error": "invalid_ip", "message": "Provide a valid IPv4 or IPv6 address."}, status=400)

    duration_value = payload.get("duration", api._config.get("firewall.ipset.default_ban_duration", 0))
    try:
        duration = max(int(duration_value), 0)
    except Exception:
        duration = max(int(api._config.get("firewall.ipset.default_ban_duration", 0)), 0)

    reason = str(payload.get("reason", "")).strip() or "[ADMIN] Report+Ban from dashboard"
    risk_score_value = payload.get("risk_score", 100)
    try:
        risk_score = min(max(int(risk_score_value), 0), 100)
    except Exception:
        risk_score = 100

    raw_categories = payload.get("categories", [14])
    categories: list[int] = []
    if isinstance(raw_categories, list):
        for item in raw_categories:
            try:
                value = int(item)
            except Exception:
                continue
            if 1 <= value <= 24 and value not in categories:
                categories.append(value)
    if not categories:
        categories = [14]

    ban_applied = await api._firewall.ban_ip(ip_value, duration=duration, reason=reason)
    if ban_applied:
        await api._db.log_ban(ip_value, reason, risk_score, duration)
        await api._notifier.notify_ban(
            ip=ip_value,
            reason=reason,
            risk=risk_score,
            duration=duration,
            plugin="admin",
        )

    reported = False
    if api._abuse_reporter:
        try:
            reported = await api._abuse_reporter.report_ip(
                ip=ip_value,
                categories=categories,
                comment=f"{reason} | Trigger: admin report+ban",
            )
        except Exception:
            reported = False

    await api._log_audit(
        request,
        "admin.report_and_ban",
        actor_username=actor,
        details={
            "ip": ip_value,
            "duration": duration,
            "risk_score": risk_score,
            "categories": categories,
            "ban_applied": ban_applied,
            "reported": reported,
        },
    )

    if not ban_applied and not reported:
        return web.json_response(
            {
                "ok": False,
                "message": f"No action taken for {ip_value} (already banned, whitelisted, or reporter unavailable).",
                "ban_applied": False,
                "reported": False,
            },
            status=409,
        )

    result_parts: list[str] = []
    result_parts.append("ban applied" if ban_applied else "ban skipped")
    result_parts.append("reported" if reported else "report skipped")
    return web.json_response(
        {
            "ok": True,
            "message": f"{ip_value}: " + ", ".join(result_parts) + ".",
            "ban_applied": ban_applied,
            "reported": reported,
        }
    )


async def handle_admin_bulk_ip_action(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    action = str(payload.get("action", "ban") or "ban").strip().lower()
    if action not in {"ban", "report", "report_and_ban"}:
        return web.json_response(
            {
                "error": "invalid_action",
                "message": "action must be one of: ban, report, report_and_ban.",
            },
            status=400,
        )

    lines_text = str(payload.get("lines", "") or "")
    if not lines_text.strip():
        return web.json_response(
            {"error": "invalid_lines", "message": "Provide at least one IP in lines."},
            status=400,
        )

    try:
        duration = max(int(payload.get("duration", api._config.get("firewall.ipset.default_ban_duration", 0))), 0)
    except Exception:
        duration = max(int(api._config.get("firewall.ipset.default_ban_duration", 0)), 0)

    reason_base = str(payload.get("reason", "") or "").strip()
    if not reason_base:
        reason_base = "[ADMIN] Bulk action from dashboard"

    risk_score_value = payload.get("risk_score", 100)
    try:
        risk_score = min(max(int(risk_score_value), 0), 100)
    except Exception:
        risk_score = 100

    raw_categories = payload.get("categories", [14])
    categories: list[int] = []
    if isinstance(raw_categories, list):
        for item in raw_categories:
            try:
                value = int(item)
            except Exception:
                continue
            if 1 <= value <= 24 and value not in categories:
                categories.append(value)
    if not categories:
        categories = [14]

    raw_respect = payload.get("respect_report_rate_limit", True)
    if isinstance(raw_respect, bool):
        respect_report_rate_limit = raw_respect
    elif isinstance(raw_respect, (int, float)):
        respect_report_rate_limit = bool(int(raw_respect))
    elif isinstance(raw_respect, str):
        respect_report_rate_limit = raw_respect.strip().lower() in {"1", "true", "yes", "on"}
    else:
        respect_report_rate_limit = True

    try:
        report_interval_ms = int(payload.get("report_interval_ms", 2200))
    except Exception:
        report_interval_ms = 2200
    report_interval_ms = min(max(report_interval_ms, 500), 15000)
    report_interval_seconds = report_interval_ms / 1000.0
    last_report_at = 0.0

    entries: list[tuple[str, str]] = []
    for raw_line in lines_text.splitlines():
        line = str(raw_line or "").strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            ip_part, note_part = line.split("|", 1)
            ip_value = ip_part.strip()
            per_line_note = note_part.strip()
        else:
            ip_value = line
            per_line_note = ""
        if not ip_value:
            continue
        entries.append((ip_value, per_line_note))

    if not entries:
        return web.json_response(
            {"error": "invalid_lines", "message": "No valid IP lines were found."},
            status=400,
        )

    results: list[dict[str, object]] = []
    for ip_value, per_line_note in entries:
        item = {
            "ip": ip_value,
            "ban_applied": False,
            "reported": False,
            "ok": False,
            "message": "",
        }
        try:
            ipaddress.ip_address(ip_value)
        except Exception:
            item["message"] = "Invalid IP format."
            results.append(item)
            continue

        final_reason = reason_base
        if per_line_note:
            final_reason = f"{reason_base} | {per_line_note}"

        ban_applied = False
        if action in {"ban", "report_and_ban"}:
            ban_applied = await api._firewall.ban_ip(ip_value, duration=duration, reason=final_reason)
            if ban_applied:
                await api._db.log_ban(ip_value, final_reason, risk_score, duration)
                await api._notifier.notify_ban(
                    ip=ip_value,
                    reason=final_reason,
                    risk=risk_score,
                    duration=duration,
                    plugin="admin",
                )

        reported = False
        if action in {"report", "report_and_ban"} and api._abuse_reporter:
            if respect_report_rate_limit and last_report_at > 0:
                elapsed = time.monotonic() - last_report_at
                wait_seconds = report_interval_seconds - elapsed
                if wait_seconds > 0:
                    await asyncio.sleep(wait_seconds)
            try:
                reported = await api._abuse_reporter.report_ip(
                    ip=ip_value,
                    categories=categories,
                    comment=f"{final_reason} | Trigger: admin bulk {action}",
                )
                last_report_at = time.monotonic()
            except Exception:
                reported = False
                last_report_at = time.monotonic()

            if not reported and respect_report_rate_limit:
                await asyncio.sleep(report_interval_seconds)
                try:
                    reported = await api._abuse_reporter.report_ip(
                        ip=ip_value,
                        categories=categories,
                        comment=f"{final_reason} | Trigger: admin bulk {action} (retry)",
                    )
                    last_report_at = time.monotonic()
                except Exception:
                    reported = False
                    last_report_at = time.monotonic()

        item["ban_applied"] = ban_applied
        item["reported"] = reported
        if action == "ban":
            item["ok"] = bool(ban_applied)
            item["message"] = "ban applied" if ban_applied else "ban skipped"
        elif action == "report":
            item["ok"] = bool(reported)
            item["message"] = "reported" if reported else "report skipped (rate-limit/provider/no-reporter)"
        else:
            item["ok"] = bool(ban_applied or reported)
            parts = ["ban applied" if ban_applied else "ban skipped", "reported" if reported else "report skipped (rate-limit/provider/no-reporter)"]
            item["message"] = ", ".join(parts)
        results.append(item)

    success_count = sum(1 for item in results if item.get("ok"))
    fail_count = len(results) - success_count
    reported_count = sum(1 for item in results if item.get("reported"))
    ban_count = sum(1 for item in results if item.get("ban_applied"))

    await api._log_audit(
        request,
        "admin.bulk_ip_action",
        actor_username=actor,
        details={
            "action": action,
            "total": len(results),
            "success": success_count,
            "failed": fail_count,
            "reported": reported_count,
            "ban_applied": ban_count,
            "categories": categories,
        },
    )

    return web.json_response(
        {
            "ok": True,
            "action": action,
            "total": len(results),
            "success": success_count,
            "failed": fail_count,
            "reported": reported_count,
            "ban_applied": ban_count,
            "categories": categories,
            "respect_report_rate_limit": respect_report_rate_limit,
            "report_interval_ms": report_interval_ms,
            "message": f"Bulk action completed: {success_count}/{len(results)} successful.",
            "results": results,
        }
    )


async def handle_admin_enforce_simulated_bans(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)

    if not api._firewall.simulation_mode:
        return web.json_response(
            {
                "error": "simulation_not_enabled",
                "message": "Simulation mode is not enabled. This action is only available while simulation mode is active.",
            },
            status=400,
        )

    now_unix = int(time.time())
    candidates: list[dict[str, object]] = []
    expired_ips: set[str] = set()

    async with api._db._lock:
        async with api._db._db.execute(
            """
        SELECT source_ip, reason, ban_duration, expires_at
        FROM ban_history
        WHERE is_active = 1
        ORDER BY banned_at DESC
        LIMIT 5000
        """
        ) as cursor:
            rows = await cursor.fetchall()

    seen_ips: set[str] = set()
    for source_ip, reason, ban_duration, expires_at in rows:
        ip_value = str(source_ip or "").strip()
        if not ip_value or ip_value in seen_ips:
            continue
        seen_ips.add(ip_value)

        duration = int(ban_duration or 0)
        expires_unix = api._parse_timestamp_unix(expires_at)
        if expires_unix is not None:
            remaining = expires_unix - now_unix
            if remaining <= 0:
                expired_ips.add(ip_value)
                continue
            duration = remaining

        candidates.append(
            {
                "ip": ip_value,
                "duration": duration,
                "reason": str(reason or "simulation replay"),
            }
        )

    deactivated_expired = 0
    for ip_value in expired_ips:
        deactivated_expired += await api._db.deactivate_ban_by_ip(ip_value)

    result = await api._firewall.enforce_db_bans(candidates)
    await api._log_audit(
        request,
        "admin.enforce_simulated_bans",
        actor_username=actor,
        details={
            "requested": result.get("requested", 0),
            "applied": result.get("applied", 0),
            "failed": result.get("failed", 0),
            "skipped": result.get("skipped", 0),
            "expired_deactivated": deactivated_expired,
        },
    )
    return web.json_response(
        {
            "ok": True,
            "requested": result.get("requested", 0),
            "applied": result.get("applied", 0),
            "failed": result.get("failed", 0),
            "skipped": result.get("skipped", 0),
            "expired_deactivated": deactivated_expired,
        }
    )


async def handle_admin_reconcile_bans(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.config.edit")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)

    now_unix = int(time.time())
    desired: dict[str, dict[str, object]] = {}
    expired_ips: set[str] = set()
    skipped_invalid = 0
    db_total_bans = 0

    async with api._db._lock:
        async with api._db._db.execute("SELECT COUNT(*) FROM ban_history") as total_cursor:
            total_row = await total_cursor.fetchone()
            db_total_bans = int(total_row[0]) if total_row else 0
        async with api._db._db.execute(
            """
        SELECT source_ip, reason, ban_duration, expires_at
        FROM ban_history
        WHERE is_active = 1
        ORDER BY banned_at DESC
        LIMIT 20000
        """
        ) as cursor:
            rows = await cursor.fetchall()

    for source_ip, reason, ban_duration, expires_at in rows:
        ip_value = str(source_ip or "").strip()
        if not ip_value or ip_value in desired:
            continue
        try:
            ipaddress.ip_address(ip_value)
        except Exception:
            skipped_invalid += 1
            continue

        try:
            duration = max(int(ban_duration or 0), 0)
        except Exception:
            duration = 0

        expires_unix = api._parse_timestamp_unix(expires_at)
        if expires_unix is not None:
            remaining = expires_unix - now_unix
            if remaining <= 0:
                expired_ips.add(ip_value)
                continue
            duration = max(int(remaining), 1)

        desired[ip_value] = {
            "duration": duration,
            "reason": str(reason or "db reconcile"),
        }

    deactivated_expired = 0
    for ip_value in expired_ips:
        deactivated_expired += await api._db.deactivate_ban_by_ip(ip_value)

    candidates = [
        {
            "ip": ip_value,
            "duration": int(meta.get("duration", 0)),
            "reason": str(meta.get("reason", "db reconcile")),
        }
        for ip_value, meta in desired.items()
    ]

    firewall_items = await api._firewall.list_banned_ips(limit=20000)
    firewall_ips = {
        str(item.get("ip") or "").strip()
        for item in firewall_items
        if str(item.get("ip") or "").strip()
    }
    desired_ips = set(desired.keys())

    enforce_result = await api._firewall.enforce_db_bans(candidates)
    re_applied = int(enforce_result.get("applied", 0))
    apply_failed = int(enforce_result.get("failed", 0))
    apply_skipped = int(enforce_result.get("skipped", 0))
    requested = int(enforce_result.get("requested", 0))

    removed_extra = 0
    remove_failed = 0
    firewall_extra_untouched = len(firewall_ips - desired_ips)

    await api._log_audit(
        request,
        "admin.reconcile_bans",
        actor_username=actor,
        details={
            "db_total_bans": db_total_bans,
            "db_active_considered": len(desired_ips),
            "expired_deactivated": deactivated_expired,
            "invalid_rows_skipped": skipped_invalid,
            "firewall_before": len(firewall_ips),
            "requested": requested,
            "reapplied": re_applied,
            "apply_failed": apply_failed,
            "apply_skipped": apply_skipped,
            "removed_extra": removed_extra,
            "remove_failed": remove_failed,
            "firewall_extra_untouched": firewall_extra_untouched,
        },
    )

    return web.json_response(
        {
            "ok": True,
            "db_total_bans": db_total_bans,
            "db_active_considered": len(desired_ips),
            "expired_deactivated": deactivated_expired,
            "invalid_rows_skipped": skipped_invalid,
            "firewall_before": len(firewall_ips),
            "requested": requested,
            "reapplied": re_applied,
            "apply_failed": apply_failed,
            "apply_skipped": apply_skipped,
            "removed_extra": removed_extra,
            "remove_failed": remove_failed,
            "firewall_extra_untouched": firewall_extra_untouched,
        }
    )
