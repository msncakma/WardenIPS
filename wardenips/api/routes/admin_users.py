"""Admin management routes - user, invite, role management."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from aiohttp import web


def setup_admin_user_routes(app: web.Application, deps: dict):
    """Register admin user management routes.
    
    Args:
        app: aiohttp Application
        deps: Dependencies dict
    """
    # Store dependencies
    app["db"] = deps.get("db")
    app["auth_service"] = deps.get("auth_service")
    app["permission_service"] = deps.get("permission_service")
    app["audit_service"] = deps.get("audit_service")
    
    # Register routes
    app.router.add_get("/api/v2/admin/users", handle_list_users)
    app.router.add_post("/api/v2/admin/users", handle_create_user)
    app.router.add_get("/api/v2/admin/users/{user_id}", handle_get_user)
    app.router.add_patch("/api/v2/admin/users/{user_id}", handle_update_user)
    app.router.add_delete("/api/v2/admin/users/{user_id}", handle_delete_user)
    
    # Invites
    app.router.add_get("/api/v2/admin/invites", handle_list_invites)
    app.router.add_post("/api/v2/admin/invites", handle_create_invite)
    app.router.add_post("/api/v2/admin/invites/{invite_id}/accept", handle_accept_invite)
    
    # Roles
    app.router.add_patch("/api/v2/admin/users/{user_id}/roles", handle_assign_roles)
    
    # Audit log
    app.router.add_get("/api/v2/admin/audit-log", handle_get_audit_log)


async def handle_list_users(request: web.Request) -> web.Response:
    """GET /api/admin/users — List all admin users."""
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        limit = int(request.rel_url.query.get("limit", 250))
        users = await db.list_admin_users(limit=limit)
        return web.json_response({"users": users, "total": len(users)})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_create_user(request: web.Request) -> web.Response:
    """POST /api/admin/users — Create new admin user."""
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        auth_service = request.app.get("auth_service")
        data = await request.json()
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        role = str(data.get("role") or "admin").strip().lower()
        display_name = str(data.get("display_name") or username).strip()
        is_owner = bool(data.get("is_owner", False))
        totp_enabled = bool(data.get("totp_enabled", False))
        
        if not username or not password:
            return web.json_response(
                {"error": "username and password required"},
                status=400
            )

        password_hash = (
            auth_service._hash_password(password)
            if auth_service and hasattr(auth_service, "_hash_password")
            else hashlib.sha256(password.encode()).hexdigest()
        )
        totp_secret = secrets.token_hex(16) if totp_enabled else ""
        actor = request.headers.get("X-Actor", "api")

        user_id = await db.create_admin_user(
            username=username,
            password_hash=password_hash,
            totp_secret=totp_secret,
            totp_enabled=totp_enabled,
            is_owner=is_owner,
            display_name=display_name,
            created_by=actor,
        )

        if role and role not in ("admin", "owner"):
            await db.assign_role_to_user(username, role)

        await db.log_audit_event(
            action="user_create",
            actor_username=actor,
            target=username,
            details={"role": role, "is_owner": is_owner},
        )
        
        return web.json_response({
            "status": "created",
            "user": {"id": user_id, "username": username, "role": role, "is_owner": is_owner},
        }, status=201)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_get_user(request: web.Request) -> web.Response:
    """GET /api/admin/users/{user_id} — Get user details."""
    user_id = request.match_info.get("user_id")
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        users = await db.list_admin_users(limit=1000)
        user = next((u for u in users if str(u.get("id")) == str(user_id)), None)
        if not user:
            return web.json_response({"error": "user not found"}, status=404)

        return web.json_response({"user": user})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_update_user(request: web.Request) -> web.Response:
    """PATCH /api/admin/users/{user_id} — Update user details."""
    user_id = request.match_info.get("user_id")
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        data = await request.json()
        users = await db.list_admin_users(limit=1000)
        user = next((u for u in users if str(u.get("id")) == str(user_id)), None)
        if not user:
            return web.json_response({"error": "user not found"}, status=404)

        username = str(user.get("username") or "")
        if not username:
            return web.json_response({"error": "user has invalid username"}, status=500)

        updated_fields = []
        if "role" in data:
            role = str(data.get("role") or "").strip().lower()
            if role:
                await db.assign_role_to_user(username, role)
                updated_fields.append("role")

        if "totp_enabled" in data:
            await db.set_admin_totp_enabled(username, bool(data.get("totp_enabled")))
            updated_fields.append("totp_enabled")

        if not updated_fields:
            return web.json_response(
                {"error": "no supported fields to update (role, totp_enabled)"},
                status=400,
            )

        await db.log_audit_event(
            action="user_update",
            actor_username=request.headers.get("X-Actor", "api"),
            target=username,
            details={"updated_fields": updated_fields},
        )

        return web.json_response({"status": "updated", "user_id": user_id, "updated_fields": updated_fields})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_delete_user(request: web.Request) -> web.Response:
    """DELETE /api/admin/users/{user_id} — Delete user."""
    user_id = request.match_info.get("user_id")
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        safe_id = int(user_id)
        actor = request.headers.get("X-Actor", "api")

        async with db._lock:
            async with db._db.execute(
                """
                UPDATE admin_users
                SET is_active = 0,
                    disabled_reason = ?,
                    updated_at = datetime('now')
                WHERE id = ? AND is_active = 1
                """,
                (f"Deactivated by {actor}", safe_id),
            ) as cursor:
                await db._db.commit()
                if not cursor.rowcount:
                    return web.json_response({"error": "user not found"}, status=404)

        await db.log_audit_event(
            action="user_delete",
            actor_username=actor,
            target=str(safe_id),
            details={"mode": "soft_delete"},
        )

        return web.json_response({"status": "deleted", "user_id": safe_id})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_list_invites(request: web.Request) -> web.Response:
    """GET /api/admin/invites — List pending invites."""
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        limit = int(request.rel_url.query.get("limit", 100))
        invites = await db.list_invite_tokens(limit=limit)
        return web.json_response({"invites": invites, "total": len(invites)})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_create_invite(request: web.Request) -> web.Response:
    """POST /api/admin/invites — Create new user invite."""
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        data = await request.json()
        email = str(data.get("email") or "").strip()
        role = str(data.get("role") or "viewer").strip().lower()
        max_uses = int(data.get("max_uses", 1))
        expires_hours = int(data.get("expires_hours", 24))
        note = str(data.get("note") or "").strip()
        
        if not email:
            return web.json_response({"error": "email required"}, status=400)

        plain_token = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=max(1, expires_hours))).isoformat()

        actor = request.headers.get("X-Actor", "api")
        invite_id = await db.create_invite_token(
            token_hash=token_hash,
            created_by=actor,
            expires_at=expires_at,
            max_uses=max_uses,
            role_codes=[role],
            permission_nodes=[],
            note=note or f"Invite for {email}",
        )
        
        return web.json_response({
            "status": "created",
            "invite": {
                "id": invite_id,
                "email": email,
                "role": role,
                "token": plain_token,
                "expires_at": expires_at,
            },
        }, status=201)
    
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_accept_invite(request: web.Request) -> web.Response:
    """POST /api/admin/invites/{invite_id}/accept — Accept invite."""
    invite_id = request.match_info.get("invite_id")
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        data = await request.json()
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        display_name = str(data.get("display_name") or username).strip()
        
        if not username or not password:
            return web.json_response({"error": "username and password required"}, status=400)

        invites = await db.list_invite_tokens(limit=1000)
        invite = next((i for i in invites if str(i.get("id")) == str(invite_id)), None)
        if not invite:
            return web.json_response({"error": "invite not found"}, status=404)

        if not bool(invite.get("is_active")):
            return web.json_response({"error": "invite is no longer active"}, status=410)

        roles = []
        try:
            roles = json.loads(invite.get("role_codes_json") or "[]")
        except Exception:
            roles = []

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user_id = await db.create_admin_user(
            username=username,
            password_hash=password_hash,
            totp_secret="",
            totp_enabled=False,
            is_owner=False,
            display_name=display_name,
            created_by="invite",
        )

        for role in roles:
            await db.assign_role_to_user(username, str(role).strip().lower())

        await db.consume_invite_token(int(invite_id))
        
        return web.json_response({
            "status": "accepted",
            "invite_id": invite_id,
            "user": {"id": user_id, "username": username},
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_assign_roles(request: web.Request) -> web.Response:
    """PATCH /api/admin/users/{user_id}/roles — Assign roles to user."""
    user_id = request.match_info.get("user_id")
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        data = await request.json()
        roles = data.get("roles", [])

        if not isinstance(roles, list) or not roles:
            return web.json_response({"error": "roles array required"}, status=400)

        users = await db.list_admin_users(limit=1000)
        user = next((u for u in users if str(u.get("id")) == str(user_id)), None)
        if not user:
            return web.json_response({"error": "user not found"}, status=404)

        username = str(user.get("username") or "")
        assigned = []
        failed = []
        for role in roles:
            normalized = str(role or "").strip().lower()
            if not normalized:
                continue
            ok = await db.assign_role_to_user(username, normalized)
            if ok:
                assigned.append(normalized)
            else:
                failed.append(normalized)
        
        return web.json_response({
            "status": "updated",
            "user_id": user_id,
            "roles": roles,
            "assigned": assigned,
            "failed": failed,
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_get_audit_log(request: web.Request) -> web.Response:
    """GET /api/admin/audit-log — Get audit log entries."""
    try:
        db = request.app.get("db")
        if not db:
            return web.json_response({"error": "database not available"}, status=503)

        limit = int(request.rel_url.query.get("limit", 100))
        offset = int(request.rel_url.query.get("offset", 0))

        actor = str(request.rel_url.query.get("actor", "")).strip()
        action = str(request.rel_url.query.get("action", "")).strip()
        events = await db.get_audit_events(limit=limit + max(0, offset), actor=actor, action=action)
        entries = events[offset:offset + limit]
        
        return web.json_response({
            "entries": entries,
            "limit": limit,
            "offset": offset,
            "total": len(entries),
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
