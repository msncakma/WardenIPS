"""Dashboard API routes - modular endpoint handlers."""

from .public import setup_public_routes
from .auth import setup_auth_routes
from .admin_users import setup_admin_user_routes
from .whitelist import setup_whitelist_routes
from .banning import setup_banning_routes
from .config import setup_config_routes
from .operational import setup_operational_routes

__all__ = [
    "setup_public_routes",
    "setup_auth_routes",
    "setup_admin_user_routes",
    "setup_whitelist_routes",
    "setup_banning_routes",
    "setup_config_routes",
    "setup_operational_routes",
    "setup_all_routes",
]


async def setup_all_routes(app, dependencies):
    """Register all route blueprints with the application.
    
    Args:
        app: aiohttp web.Application instance
        dependencies: Dict with db, firewall, config, services, etc.
    """
    # Register public routes (read-only)
    setup_public_routes(app, dependencies)
    
    # Register auth routes (login, logout, session)
    setup_auth_routes(app, dependencies)
    
    # Register admin user routes (users, invites, roles, audit)
    setup_admin_user_routes(app, dependencies)
    
    # Register whitelist routes (CRUD for whitelist entries)
    setup_whitelist_routes(app, dependencies)
    
    # Register banning routes (ban/unban operations)
    setup_banning_routes(app, dependencies)
    
    # Register config routes (get/set/reload)
    setup_config_routes(app, dependencies)
    
    # Register operational routes (firewall, plugins, database)
    setup_operational_routes(app, dependencies)
