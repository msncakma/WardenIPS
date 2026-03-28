"""Permission service - RBAC (Role-Based Access Control) checks."""

from typing import List, Dict
from enum import Enum


class Role(Enum):
    """User roles."""
    ADMIN = "admin"  # Full access
    OPERATOR = "operator"  # Can ban/unban, view config
    VIEWER = "viewer"  # Read-only access
    ANALYST = "analyst"  # Read reports, no operational changes


class PermissionService:
    """Permission and RBAC management service."""
    
    # Define permission matrix: role -> permissions
    PERMISSIONS = {
        Role.ADMIN: {
            "view_stats", "view_bans", "view_whitelist", "view_config",
            "ban_ip", "unban_ip", "whitelist_add", "whitelist_remove",
            "config_read", "config_write", "config_reload",
            "firewall_status", "firewall_sync",
            "plugin_reload",
            "database_stats", "database_optimize",
            "user_create", "user_delete", "user_update",
            "audit_view",
        },
        Role.OPERATOR: {
            "view_stats", "view_bans", "view_whitelist", "view_config",
            "ban_ip", "unban_ip", "whitelist_add", "whitelist_remove",
            "config_read",
            "firewall_status", "firewall_sync",
            "database_stats",
        },
        Role.VIEWER: {
            "view_stats", "view_bans", "view_whitelist", "view_config",
            "firewall_status",
            "database_stats",
        },
        Role.ANALYST: {
            "view_stats", "view_bans", "view_whitelist",
            "firewall_status",
            "database_stats",
        },
    }
    
    def __init__(self, db):
        """Initialize permission service.
        
        Args:
            db: Database manager
        """
        self.db = db

    PERMISSION_NODE_MAP = {
        "view_stats": "panel.view",
        "view_bans": "panel.view",
        "view_whitelist": "panel.view",
        "view_config": "panel.view",
        "ban_ip": "admin.query.run",
        "unban_ip": "admin.query.run",
        "whitelist_add": "admin.query.run",
        "whitelist_remove": "admin.query.run",
        "config_read": "panel.view",
        "config_write": "admin.config.edit",
        "config_reload": "admin.config.edit",
        "firewall_status": "panel.view",
        "firewall_sync": "admin.query.run",
        "plugin_reload": "admin.query.run",
        "database_stats": "panel.view",
        "database_optimize": "admin.query.run",
        "user_create": "admin.users.manage",
        "user_delete": "admin.users.manage",
        "user_update": "admin.users.manage",
        "audit_view": "admin.audit.view",
    }
    
    async def check_permission(
        self,
        username: str,
        permission: str,
    ) -> bool:
        """Check if user has permission.
        
        Args:
            username: Username
            permission: Permission string (e.g., "ban_ip")
        
        Returns:
            True if user has permission
        """
        try:
            effective = await self.db.get_user_effective_permissions(username)
            allow = set(effective.get("allow") or set())
            deny = set(effective.get("deny") or set())

            node = self.PERMISSION_NODE_MAP.get(permission, permission)
            if "*" in allow:
                return node not in deny and permission not in deny
            if node in deny or permission in deny:
                return False
            return node in allow or permission in allow
            
        except Exception:
            return False
    
    async def get_user_permissions(self, username: str) -> List[str]:
        """Get all permissions for user.
        
        Args:
            username: Username
        
        Returns:
            List of permission strings
        """
        try:
            effective = await self.db.get_user_effective_permissions(username)
            allow = set(effective.get("allow") or set())
            deny = set(effective.get("deny") or set())

            granted = []
            for perm, node in self.PERMISSION_NODE_MAP.items():
                if "*" in allow and node not in deny and perm not in deny:
                    granted.append(perm)
                    continue
                if (node in allow or perm in allow) and node not in deny and perm not in deny:
                    granted.append(perm)

            return sorted(set(granted))
        
        except Exception:
            return []
    
    async def get_user_role(self, username: str) -> str:
        """Get user role.
        
        Args:
            username: Username
        
        Returns:
            Role name
        """
        try:
            user = await self.db.get_admin_user_by_username(username)
            if not user:
                return "viewer"
            if bool(user.get("is_owner")):
                return "owner"

            perms = set(await self.get_user_permissions(username))
            if "user_update" in perms or "config_write" in perms:
                return "admin"
            if "ban_ip" in perms or "whitelist_add" in perms:
                return "operator"
            if "view_stats" in perms:
                return "viewer"
            return "viewer"
        
        except Exception:
            return "viewer"
    
    def get_role_permissions(self, role: str) -> List[str]:
        """Get permissions for a role.
        
        Args:
            role: Role name
        
        Returns:
            List of permission strings
        """
        try:
            role_enum = Role[role.upper()]
            return list(self.PERMISSIONS[role_enum])
        except (KeyError, AttributeError):
            return []
    
    @staticmethod
    def get_available_roles() -> List[Dict]:
        """Get available roles and their descriptions.
        
        Returns:
            List of role dicts
        """
        return [
            {
                "name": "admin",
                "description": "Full system access",
                "permissions_count": len(PermissionService.PERMISSIONS[Role.ADMIN]),
            },
            {
                "name": "operator",
                "description": "Can ban/unban, manage whitelist",
                "permissions_count": len(PermissionService.PERMISSIONS[Role.OPERATOR]),
            },
            {
                "name": "viewer",
                "description": "Read-only access to all data",
                "permissions_count": len(PermissionService.PERMISSIONS[Role.VIEWER]),
            },
            {
                "name": "analyst",
                "description": "View threat statistics and reports",
                "permissions_count": len(PermissionService.PERMISSIONS[Role.ANALYST]),
            },
        ]
