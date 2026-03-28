"""Authentication routes - login, logout, session management."""

from datetime import datetime, timezone
from aiohttp import web


def setup_auth_routes(app: web.Application, deps: dict):
    """Register authentication routes.
    
    Args:
        app: aiohttp Application
        deps: Dependencies dict
    """
    # Store dependencies
    app["auth_service"] = deps.get("auth_service")
    
    # Register routes
    app.router.add_post("/api/v2/login", handle_login)
    app.router.add_post("/api/v2/logout", handle_logout)
    app.router.add_post("/api/v2/session-activity", handle_session_activity)


async def handle_login(request: web.Request) -> web.Response:
    """POST /api/login — Login with username/password and optional TOTP."""
    try:
        auth_service = request.app.get("auth_service")
        if not auth_service:
            return web.json_response(
                {"error": "auth_service not configured"},
                status=500
            )
        
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        totp_token = data.get("totp", "")
        
        if not username or not password:
            return web.json_response(
                {"error": "username and password required"},
                status=400
            )
        
        # Authenticate user with AuthService
        is_valid, result = await auth_service.authenticate(
            username=username,
            password=password,
            totp_code=totp_token if totp_token else None
        )
        
        if not is_valid:
            return web.json_response(
                {"error": "invalid credentials"},
                status=401
            )
        
        # Extract session token (result is the token on success)
        session_token = result
        
        return web.json_response({
            "status": "ok",
            "session_token": session_token,
            "username": username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, status=200)
    
    except ValueError:
        return web.json_response(
            {"error": "invalid JSON in request body"},
            status=400
        )
    except Exception as e:
        return web.json_response(
            {"error": str(e)},
            status=500
        )


async def handle_logout(request: web.Request) -> web.Response:
    """POST /api/logout — Invalidate session."""
    try:
        auth_service = request.app.get("auth_service")
        if not auth_service:
            return web.json_response(
                {"error": "auth_service not configured"},
                status=500
            )
        
        # Extract session token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return web.json_response(
                {"error": "missing or invalid Authorization header"},
                status=401
            )
        
        session_token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Revoke the session
        success = await auth_service.revoke_session(session_token)
        if not success:
            return web.json_response(
                {"error": "invalid or expired session"},
                status=401
            )
        
        return web.json_response({
            "status": "ok",
            "message": "logged out successfully",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, status=200)
    
    except Exception as e:
        return web.json_response(
            {"error": str(e)},
            status=500
        )


async def handle_session_activity(request: web.Request) -> web.Response:
    """POST /api/session-activity — Keep-alive request to extend session."""
    try:
        auth_service = request.app.get("auth_service")
        if not auth_service:
            return web.json_response(
                {"error": "auth_service not configured"},
                status=500
            )
        
        # Extract session token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return web.json_response(
                {"error": "missing or invalid Authorization header"},
                status=401
            )
        
        session_token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Validate session (this updates last_activity internally)
        is_valid, username = await auth_service.validate_session(session_token)
        if not is_valid:
            return web.json_response(
                {"error": "invalid or expired session"},
                status=401
            )
        
        return web.json_response({
            "status": "ok",
            "message": "session activity recorded",
            "username": username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, status=200)
    
    except Exception as e:
        return web.json_response(
            {"error": str(e)},
            status=500
        )
