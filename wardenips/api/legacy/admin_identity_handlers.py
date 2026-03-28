"""Admin identity and access handlers extracted from DashboardAPI monolith."""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from aiohttp import web

from wardenips.core.auth import check_password_policy, generate_totp_secret, hash_password


async def handle_admin_list_users(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.users.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    try:
        limit = int(request.query.get("limit", "200") or 200)
    except Exception:
        limit = 200
    rows = await api._db.list_admin_users(limit=limit)
    return web.json_response({"ok": True, "count": len(rows), "items": rows})


async def handle_admin_create_user(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.users.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request) or ""
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    display_name = str(payload.get("display_name", "")).strip()
    roles = payload.get("roles", []) if isinstance(payload.get("roles", []), list) else []
    permissions = payload.get("permissions", []) if isinstance(payload.get("permissions", []), list) else []
    totp_enabled = bool(payload.get("totp_enabled", True))
    is_owner = bool(payload.get("is_owner", False))

    if not username:
        return web.json_response({"error": "invalid_username", "message": "username is required."}, status=400)
    if not password:
        return web.json_response({"error": "invalid_password", "message": "password is required."}, status=400)
    valid, message = check_password_policy(password)
    if not valid:
        return web.json_response({"error": "weak_password", "message": message}, status=400)
    if is_owner and not await api._actor_has_permission(request, "*"):
        return web.json_response({"error": "forbidden", "message": "Only owner can create another owner account."}, status=403)
    if await api._db.get_admin_user_by_username(username):
        return web.json_response({"error": "username_exists", "message": "Username already exists."}, status=409)

    user_id = await api._db.create_admin_user(
        username=username,
        password_hash=hash_password(password),
        totp_secret=generate_totp_secret(),
        totp_enabled=totp_enabled,
        is_owner=is_owner,
        display_name=display_name or username,
        created_by=actor,
    )
    for role in roles:
        await api._db.assign_role_to_user(username, str(role or "").strip().lower())
    for node in permissions:
        await api._db.upsert_user_permission(username, str(node or "").strip(), effect=1)

    await api._log_audit(
        request,
        "admin.users.create",
        actor_username=actor,
        target=username,
        details={"user_id": user_id, "roles": roles, "permissions": permissions, "is_owner": is_owner},
    )
    return web.json_response({"ok": True, "user_id": user_id, "username": username}, status=201)


async def handle_admin_assign_role(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.users.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request) or ""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    username = str(payload.get("username", "")).strip()
    role_code = str(payload.get("role", "")).strip().lower()
    if not username or not role_code:
        return web.json_response({"error": "invalid_request", "message": "username and role are required."}, status=400)
    ok = await api._db.assign_role_to_user(username, role_code)
    if not ok:
        return web.json_response({"error": "assignment_failed", "message": "Could not assign role."}, status=404)
    await api._log_audit(request, "admin.users.assign_role", actor_username=actor, target=username, details={"role": role_code})
    return web.json_response({"ok": True, "username": username, "role": role_code})


async def handle_admin_grant_permission(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.users.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request) or ""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    username = str(payload.get("username", "")).strip()
    node = str(payload.get("permission", "")).strip()
    effect = int(payload.get("effect", 1) or 1)
    if not username or not node:
        return web.json_response({"error": "invalid_request", "message": "username and permission are required."}, status=400)
    ok = await api._db.upsert_user_permission(username, node, effect=effect)
    if not ok:
        return web.json_response({"error": "grant_failed", "message": "Could not update user permission."}, status=404)
    await api._log_audit(request, "admin.users.permission", actor_username=actor, target=username, details={"permission": node, "effect": 1 if effect >= 0 else -1})
    return web.json_response({"ok": True, "username": username, "permission": node, "effect": 1 if effect >= 0 else -1})


async def handle_admin_list_invites(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.invites.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    try:
        limit = int(request.query.get("limit", "100") or 100)
    except Exception:
        limit = 100
    rows = await api._db.list_invite_tokens(limit=limit)
    items = []
    for row in rows:
        token_hash = str(row.get("token_hash") or "")
        try:
            role_codes = json.loads(str(row.get("role_codes_json") or "[]"))
        except Exception:
            role_codes = []
        try:
            permission_nodes = json.loads(str(row.get("permission_nodes_json") or "[]"))
        except Exception:
            permission_nodes = []
        items.append(
            {
                "id": row.get("id"),
                "fingerprint": token_hash[:8] + "..." if token_hash else "",
                "created_by": row.get("created_by"),
                "note": row.get("note"),
                "max_uses": row.get("max_uses"),
                "used_count": row.get("used_count"),
                "expires_at": row.get("expires_at"),
                "is_active": bool(row.get("is_active")),
                "role_codes": role_codes,
                "permission_nodes": permission_nodes,
                "created_at": row.get("created_at"),
            }
        )
    return web.json_response({"ok": True, "count": len(items), "items": items})


async def handle_admin_create_invite(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.invites.manage")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request) or ""
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    note = str(payload.get("note", "")).strip()
    max_uses = max(1, min(int(payload.get("max_uses", 1) or 1), 50))
    expires_in_hours = max(1, min(int(payload.get("expires_in_hours", 24) or 24), 24 * 30))
    roles = [str(item or "").strip().lower() for item in list(payload.get("roles", []) or []) if str(item or "").strip()]
    permissions = [str(item or "").strip() for item in list(payload.get("permissions", []) or []) if str(item or "").strip()]
    raw_token = secrets.token_urlsafe(24)
    token_hash = api._hash_invite_token(raw_token)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)).isoformat()
    invite_id = await api._db.create_invite_token(
        token_hash=token_hash,
        created_by=actor,
        expires_at=expires_at,
        max_uses=max_uses,
        role_codes=roles,
        permission_nodes=permissions,
        note=note,
    )
    await api._log_audit(request, "admin.invites.create", actor_username=actor, target=str(invite_id), details={"max_uses": max_uses, "expires_at": expires_at, "roles": roles, "permissions": permissions})
    return web.json_response({"ok": True, "invite_id": invite_id, "invite_token": raw_token, "expires_at": expires_at, "max_uses": max_uses}, status=201)


async def handle_admin_query_records(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.query.run")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)
    actor = api._get_session_actor(request)
    started_at = time.perf_counter()

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    field = str(payload.get("field", "auto") or "auto").strip().lower()
    value = str(payload.get("value", "") or "").strip()
    page = max(int(payload.get("page", 1) or 1), 1)
    page_size = min(max(int(payload.get("page_size", payload.get("limit", 100)) or 100), 1), 500)
    offset = (page - 1) * page_size
    record_kind = str(payload.get("record_kind", "event") or "event").strip().lower()
    connection_type_filter = str(payload.get("connection_type", "") or "").strip().lower()
    event_type_filter = str(payload.get("event_type", "") or "").strip().lower()
    country_filter = str(payload.get("country", "") or "").strip().upper()
    try:
        min_risk = int(payload.get("min_risk", 0) or 0)
    except Exception:
        min_risk = 0
    try:
        max_risk = int(payload.get("max_risk", 100) or 100)
    except Exception:
        max_risk = 100
    min_risk = min(max(min_risk, 0), 100)
    max_risk = min(max(max_risk, 0), 100)
    if min_risk > max_risk:
        min_risk, max_risk = max_risk, min_risk
    refresh_missing_geo = bool(payload.get("refresh_missing_geo", True))

    if not value:
        return web.json_response({"error": "invalid_query", "message": "Query value is required."}, status=400)

    if field not in {"auto", "ip", "asn", "user"}:
        return web.json_response({"error": "invalid_field", "message": "Field must be one of: auto, ip, asn, user."}, status=400)
    if record_kind not in {"event", "ban", "all"}:
        return web.json_response({"error": "invalid_record_kind", "message": "record_kind must be one of: event, ban, all."}, status=400)

    if field == "auto":
        try:
            import ipaddress

            ipaddress.ip_address(value)
            resolved_field = "ip"
        except Exception:
            normalized = value.upper().strip()
            if normalized.startswith("AS") and normalized[2:].isdigit():
                resolved_field = "asn"
            elif normalized.isdigit():
                resolved_field = "asn"
            else:
                resolved_field = "user"
    else:
        resolved_field = field

    event_where_clauses: list[str] = ["risk_score >= ?", "risk_score <= ?"]
    event_where_params: list[object] = [min_risk, max_risk]

    if resolved_field == "ip":
        event_where_clauses.append("source_ip = ?")
        event_where_params.append(value)
    elif resolved_field == "asn":
        normalized = value.upper().strip()
        asn_number = None
        if normalized.startswith("AS"):
            normalized = normalized[2:]
        if normalized.isdigit():
            asn_number = int(normalized)
        if asn_number is not None:
            event_where_clauses.append("(asn_number = ? OR LOWER(COALESCE(asn_org, '')) LIKE ?)")
            event_where_params.extend([asn_number, f"%{value.lower()}%"])
        else:
            event_where_clauses.append("LOWER(COALESCE(asn_org, '')) LIKE ?")
            event_where_params.append(f"%{value.lower()}%")
    else:
        event_where_clauses.append("LOWER(COALESCE(player_name, '')) LIKE ?")
        event_where_params.append(f"%{value.lower()}%")

    if connection_type_filter:
        event_where_clauses.append("LOWER(COALESCE(connection_type, '')) = ?")
        event_where_params.append(connection_type_filter)
    if event_type_filter:
        event_where_clauses.append("LOWER(COALESCE(details, '')) LIKE ?")
        event_where_params.append(f'%"event_type": "{event_type_filter}%')
    if country_filter and len(country_filter) == 2 and country_filter.isalpha():
        event_where_clauses.append("(UPPER(COALESCE(details, '')) LIKE ? OR UPPER(COALESCE(details, '')) LIKE ?)")
        event_where_params.append(f'%"COUNTRY_CODE":"{country_filter}"%')
        event_where_params.append(f'%"COUNTRY_CODE": "{country_filter}"%')

    event_where_sql = " AND ".join(event_where_clauses) if event_where_clauses else "1=1"

    event_count_query = f"""
      SELECT COUNT(*)
      FROM connection_events
      WHERE {event_where_sql}
    """

    event_data_query = f"""
      SELECT id, timestamp, source_ip, player_name, connection_type,
             asn_number, asn_org, is_suspicious_asn, risk_score, threat_level, details
      FROM connection_events
      WHERE {event_where_sql}
      ORDER BY timestamp DESC
      LIMIT ? OFFSET ?
    """

    records = []
    total_count = 0
    event_rows_raw = []

    if record_kind in {"event", "all"}:
        async with api._db._lock:
            async with api._db._db.execute(event_count_query, tuple(event_where_params)) as count_cursor:
                count_row = await count_cursor.fetchone()
                total_count = int((count_row[0] or 0) if count_row else 0)
            async with api._db._db.execute(
                event_data_query,
                tuple([*event_where_params, page_size, offset]),
            ) as cursor:
                rows = await cursor.fetchall()
                columns = [d[0] for d in cursor.description]
                event_rows_raw = [dict(zip(columns, row)) for row in rows]

        if refresh_missing_geo and event_rows_raw:
            update_payload = []
            for row in event_rows_raw:
                row_id = int(row.get("id") or 0)
                source_ip = str(row.get("source_ip") or "").strip()
                if row_id <= 0:
                    continue

                details_value = row.get("details")
                details_obj = {}
                if isinstance(details_value, str) and details_value:
                    try:
                        parsed = json.loads(details_value)
                        if isinstance(parsed, dict):
                            details_obj = parsed
                    except Exception:
                        details_obj = {}
                elif isinstance(details_value, dict):
                    details_obj = dict(details_value)

                changed = False
                asn_number = row.get("asn_number")
                asn_org = row.get("asn_org")
                is_suspicious = bool(row.get("is_suspicious_asn"))

                if (asn_number is None and not str(asn_org or "").strip()) and api._is_valid_ip(source_ip) and api._asn_lookup:
                    asn_result = api._asn_lookup.lookup(source_ip)
                    if asn_result.asn_number is not None or str(asn_result.asn_org or "").strip():
                        asn_number = asn_result.asn_number
                        asn_org = asn_result.asn_org
                        is_suspicious = bool(asn_result.is_suspicious)
                        changed = True

                country_code = api._resolve_country_code(details_obj, source_ip)
                if country_code and str(details_obj.get("country_code") or "").strip().upper() != country_code:
                    details_obj["country_code"] = country_code
                    changed = True

                if changed:
                    row["asn_number"] = asn_number
                    row["asn_org"] = asn_org
                    row["is_suspicious_asn"] = is_suspicious
                    row["details"] = details_obj
                    update_payload.append(
                        (
                            asn_number,
                            str(asn_org or ""),
                            1 if is_suspicious else 0,
                            json.dumps(details_obj, ensure_ascii=False),
                            row_id,
                        )
                    )

            if update_payload:
                async with api._db._lock:
                    await api._db._db.executemany(
                        """
                        UPDATE connection_events
                        SET asn_number = ?, asn_org = ?, is_suspicious_asn = ?, details = ?
                        WHERE id = ?
                        """,
                        update_payload,
                    )
                    await api._db._db.commit()

        for row in event_rows_raw:
            details_obj = {}
            details_value = row.get("details")
            if isinstance(details_value, str) and details_value:
                try:
                    details_obj = json.loads(details_value)
                except Exception:
                    details_obj = {}
            elif isinstance(details_value, dict):
                details_obj = details_value
            records.append(
                {
                    "kind": "event",
                    "id": row.get("id"),
                    "timestamp": row.get("timestamp"),
                    "source_ip": row.get("source_ip"),
                    "player_name": row.get("player_name"),
                    "connection_type": row.get("connection_type"),
                    "event_type": str(details_obj.get("event_type") or ""),
                    "event_port": api._extract_event_port({"player_name": row.get("player_name")}, details_obj),
                    "country_code": api._resolve_country_code(details_obj, row.get("source_ip")),
                    "asn_number": row.get("asn_number"),
                    "asn_org": row.get("asn_org"),
                    "is_suspicious_asn": bool(row.get("is_suspicious_asn")),
                    "risk_score": row.get("risk_score"),
                    "threat_level": row.get("threat_level"),
                }
            )

    if resolved_field == "ip" and record_kind in {"ban", "all"}:
        async with api._db._lock:
            async with api._db._db.execute(
                """
                SELECT COUNT(*)
                FROM ban_history
                WHERE source_ip = ?
                  AND risk_score >= ?
                  AND risk_score <= ?
                """,
                (value, min_risk, max_risk),
            ) as bcount_cursor:
                bcount_row = await bcount_cursor.fetchone()
                ban_total_count = int((bcount_row[0] or 0) if bcount_row else 0)

            if record_kind == "ban":
                async with api._db._db.execute(
                    """
                    SELECT id, banned_at, source_ip, reason, risk_score, ban_duration, expires_at, is_active
                    FROM ban_history
                    WHERE source_ip = ?
                      AND risk_score >= ?
                      AND risk_score <= ?
                    ORDER BY banned_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (value, min_risk, max_risk, page_size, offset),
                ) as cursor:
                    ban_rows = await cursor.fetchall()
                records = [
                    {
                        "kind": "ban",
                        "id": row[0],
                        "timestamp": row[1],
                        "source_ip": row[2],
                        "reason": row[3],
                        "risk_score": row[4],
                        "ban_duration": row[5],
                        "expires_at": row[6],
                        "is_active": bool(row[7]),
                    }
                    for row in ban_rows
                ]
                total_count = ban_total_count
            else:
                fetch_cap = min(max(page_size * page * 4, page_size * 4), 5000)
                async with api._db._lock:
                    async with api._db._db.execute(
                        """
                        SELECT id, banned_at, source_ip, reason, risk_score, ban_duration, expires_at, is_active
                        FROM ban_history
                        WHERE source_ip = ?
                          AND risk_score >= ?
                          AND risk_score <= ?
                        ORDER BY banned_at DESC
                        LIMIT ?
                        """,
                        (value, min_risk, max_risk, fetch_cap),
                    ) as cursor:
                        ban_rows = await cursor.fetchall()
                ban_records = [
                    {
                        "kind": "ban",
                        "id": row[0],
                        "timestamp": row[1],
                        "source_ip": row[2],
                        "reason": row[3],
                        "risk_score": row[4],
                        "ban_duration": row[5],
                        "expires_at": row[6],
                        "is_active": bool(row[7]),
                    }
                    for row in ban_rows
                ]
                merged = [*records, *ban_records]
                merged.sort(
                    key=lambda item: api._parse_timestamp_unix(item.get("timestamp")) or 0,
                    reverse=True,
                )
                total_count = int(total_count) + int(ban_total_count)
                records = merged[offset : offset + page_size]

    if record_kind == "event":
        records.sort(
            key=lambda item: api._parse_timestamp_unix(item.get("timestamp")) or 0,
            reverse=True,
        )

    await api._log_audit(
        request,
        "admin.query_records",
        actor_username=actor,
        details={
            "field": resolved_field,
            "value": value,
            "record_kind": record_kind,
            "count": len(records),
            "page": page,
            "page_size": page_size,
            "total": total_count,
        },
    )

    try:
        await api._db.log_query_event(
            actor_username=actor,
            endpoint="/api/admin/query-records",
            query_payload={
                "field": resolved_field,
                "value": value,
                "record_kind": record_kind,
                "connection_type": connection_type_filter,
                "event_type": event_type_filter,
                "country": country_filter,
                "min_risk": min_risk,
                "max_risk": max_risk,
                "page": page,
                "page_size": page_size,
            },
            result_count=len(records),
            duration_ms=int((time.perf_counter() - started_at) * 1000),
            ip_address=api._client_ip(request),
            user_agent=request.headers.get("User-Agent", ""),
        )
    except Exception:
        pass

    return web.json_response(
        {
            "ok": True,
            "field": resolved_field,
            "value": value,
            "record_kind": record_kind,
            "page": page,
            "page_size": page_size,
            "offset": offset,
            "total": total_count,
            "has_more": bool(offset + len(records) < int(total_count or 0)),
            "count": len(records),
            "records": records,
        }
    )


async def handle_admin_audit_events(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.audit.view")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)

    try:
        limit = int(request.query.get("limit", "200") or 200)
    except Exception:
        limit = 200
    actor = str(request.query.get("actor", "") or "").strip()
    action = str(request.query.get("action", "") or "").strip()

    rows = await api._db.get_audit_events(limit=limit, actor=actor, action=action)
    for row in rows:
        details_value = row.get("details_json")
        if isinstance(details_value, str) and details_value:
            try:
                row["details"] = json.loads(details_value)
            except Exception:
                row["details"] = details_value
        else:
            row["details"] = details_value
    return web.json_response({"ok": True, "count": len(rows), "items": rows})


async def handle_admin_audit_queries(api, request: web.Request) -> web.Response:
    permission_error = await api._require_permission(request, "admin.audit.view")
    if permission_error is not None:
        return permission_error
    api._touch_session(request)

    try:
        limit = int(request.query.get("limit", "200") or 200)
    except Exception:
        limit = 200
    actor = str(request.query.get("actor", "") or "").strip()
    endpoint = str(request.query.get("endpoint", "") or "").strip()

    rows = await api._db.get_query_logs(limit=limit, actor=actor, endpoint=endpoint)
    for row in rows:
        query_value = row.get("query_json")
        if isinstance(query_value, str) and query_value:
            try:
                row["query"] = json.loads(query_value)
            except Exception:
                row["query"] = query_value
        else:
            row["query"] = query_value
    return web.json_response({"ok": True, "count": len(rows), "items": rows})
