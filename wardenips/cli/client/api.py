"""API client for remote dashboard access."""

import asyncio
import json
from typing import Any, Dict, List, Optional

import aiohttp

from .base import BaseClient
from .exceptions import APIError, AuthenticationError


class APIClient(BaseClient):
    """Client that communicates with WardenIPS dashboard via HTTP API."""
    
    def __init__(self, base_url: str, api_key: str = "", timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self._headers = {
            "Content-Type": "application/json",
            "User-Agent": "wardenips-cli/2.0",
        }
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
    
    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Lazily create and return aiohttp session."""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def close(self):
        """Close the session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make HTTP request to API."""
        session = await self._ensure_session()
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() in ("GET", "DELETE"):
                async with session.request(method, url, headers=self._headers) as resp:
                    if resp.status == 401:
                        raise AuthenticationError(f"Authentication failed (401): invalid API key?")
                    if resp.status >= 400:
                        text = await resp.text()
                        raise APIError(f"{method} {endpoint} failed ({resp.status}): {text}")
                    return await resp.json()
            else:  # POST, PATCH, PUT
                async with session.request(
                    method, url, headers=self._headers, json=data or {}
                ) as resp:
                    if resp.status == 401:
                        raise AuthenticationError(f"Authentication failed (401): invalid API key?")
                    if resp.status >= 400:
                        text = await resp.text()
                        raise APIError(f"{method} {endpoint} failed ({resp.status}): {text}")
                    return await resp.json()
        except aiohttp.ClientError as e:
            raise APIError(f"Connection error: {e}")
    
    async def ban_ip(self, ip: str, duration: int = 0, reason: str = "") -> Dict[str, Any]:
        """Ban an IP address."""
        return await self._request(
            "POST",
            "/api/admin/ban-ip",
            {
                "ip": ip,
                "duration": duration,
                "reason": reason,
            },
        )
    
    async def unban_ip(self, ip: str) -> Dict[str, Any]:
        """Unban an IP address."""
        return await self._request(
            "DELETE",
            f"/api/admin/ban/{ip}",
        )
    
    async def list_bans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List active bans."""
        result = await self._request("GET", f"/api/admin/bans?limit={limit}")
        return result.get("bans", []) if isinstance(result, dict) else result
    
    async def add_whitelist(self, ip_or_cidr: str, reason: str = "", tag: str = "") -> Dict[str, Any]:
        """Add IP/CIDR to whitelist."""
        return await self._request(
            "POST",
            "/api/admin/whitelist/add",
            {
                "ip": ip_or_cidr,
                "reason": reason,
                "tag": tag,
            },
        )
    
    async def remove_whitelist(self, ip_or_cidr: str) -> Dict[str, Any]:
        """Remove IP/CIDR from whitelist."""
        return await self._request(
            "DELETE",
            f"/api/admin/whitelist/{ip_or_cidr}",
        )
    
    async def list_whitelist(self) -> List[Dict[str, Any]]:
        """List whitelist entries."""
        result = await self._request("GET", "/api/admin/whitelist")
        return result.get("whitelist", []) if isinstance(result, dict) else result
    
    async def get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status."""
        return await self._request("GET", "/api/admin/firewall/status")
    
    async def sync_firewall(self, dry_run: bool = False) -> Dict[str, Any]:
        """Reconcile firewall state with database."""
        return await self._request(
            "POST",
            "/api/admin/firewall/sync",
            {"dry_run": dry_run},
        )
    
    async def get_config(self, key: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration value(s)."""
        if key:
            return await self._request("GET", f"/api/admin/config/{key}")
        else:
            return await self._request("GET", "/api/admin/config")
    
    async def set_config(self, key: str, value: Any) -> Dict[str, Any]:
        """Set configuration value."""
        return await self._request(
            "PATCH",
            "/api/admin/config",
            {key: value},
        )
    
    async def reload_config(self, components: Optional[List[str]] = None) -> Dict[str, Any]:
        """Reload configuration (hot-reload)."""
        return await self._request(
            "POST",
            "/api/admin/config/reload",
            {"components": components} if components else {},
        )
    
    async def get_plugin_list(self) -> List[Dict[str, Any]]:
        """List all plugins."""
        result = await self._request("GET", "/api/admin/plugins")
        return result.get("plugins", []) if isinstance(result, dict) else result
    
    async def get_plugin_status(self, name: str) -> Dict[str, Any]:
        """Get plugin status."""
        return await self._request("GET", f"/api/admin/plugins/{name}")
    
    async def reload_plugin(self, name: str) -> Dict[str, Any]:
        """Reload plugin configuration."""
        return await self._request(
            "POST",
            f"/api/admin/plugins/{name}/reload",
        )
    
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        return await self._request("GET", "/api/admin/database/stats")
    
    async def optimize_database(self) -> Dict[str, Any]:
        """Optimize database (VACUUM + ANALYZE)."""
        return await self._request(
            "POST",
            "/api/admin/database/optimize",
        )
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get full system status report."""
        return await self._request("GET", "/api/health")
