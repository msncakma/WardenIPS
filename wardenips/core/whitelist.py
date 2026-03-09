"""
WardenIPS - Asynchronously manages IP whitelists.
==========================================

IP and CIDR-based whitelist control, geofencing support,
and hot-reload capability.

Prevents managers from being locked out of their own servers.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import List, Optional, Set, Union

from wardenips.core.config import ConfigManager
from wardenips.core.exceptions import WardenWhitelistError
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# IP ağ tipi kısaltmaları
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class WhitelistManager:
    """
    Asynchronously manages IP whitelists.

    Reads whitelist and geofencing settings from config.yaml
    and checks if incoming IP addresses are authorized.

    Features:
        - IPv4 and IPv6 unique IP support.
        - CIDR block (network ranges) support.
        - Geofencing — country-based allow/deny rules.
        - Hot-reload — automatically updates the list on configuration changes.
        - O(1) lookup for unique IPs, O(n) for CIDR scanning (n = number of CIDRs).

    Usage:
        wl = await WhitelistManager.create(config)
        if await wl.is_whitelisted("192.168.1.1"):
            print("IP is in the safe list!")
    """

    def __init__(self) -> None:
        self._whitelisted_ips: Set[IPAddress] = set()
        self._whitelisted_networks: List[IPNetwork] = []
        self._geofencing_enabled: bool = False
        self._geofencing_mode: str = "allow"
        self._geofencing_countries: Set[str] = set()
        self._enabled: bool = True
        self._lock: asyncio.Lock = asyncio.Lock()

    # ── Factory ──

    @classmethod
    async def create(cls, config: ConfigManager) -> WhitelistManager:
        """
        Creates a WhitelistManager instance from a ConfigManager.

        Args:
            config: Loaded ConfigManager instance.

        Returns:
            Configured WhitelistManager.
        """
        instance = cls()
        await instance._load_from_config(config)
        return instance

    # ── Ana API ──

    async def is_whitelisted(self, ip_str: str) -> bool:
        """
        Checks if an IP address is whitelisted.

        Control order:
            1. Whitelist disabled → False (all IPs are evaluated)
            2. Unique IP match (O(1) set lookup)
            3. CIDR network match

        Args:
            ip_str: IP address to check (string).

        Returns:
            True if IP is whitelisted, False otherwise.
        """
        if not self._enabled:
            return False

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.warning("Invalid IP format, whitelist check failed: %s", ip_str)
            return False

        # 1. Tekil IP kontrolü — O(1)
        if ip in self._whitelisted_ips:
            logger.debug("IP whitelist'te bulundu (unique): %s", ip_str)
            return True

        # 2. CIDR ağ kontrolü
        for network in self._whitelisted_networks:
            if ip in network:
                logger.debug(
                    "IP found in whitelist (CIDR %s): %s",
                    network,
                    ip_str,
                )
                return True

        return False

    async def is_country_allowed(self, country_code: Optional[str]) -> bool:
        """
        Checks if a country code is allowed based on geofencing rules.

        Args:
            country_code: ISO 3166-1 alpha-2 country code (e.g., "TR").
                          None if country is unknown.

        Returns:
            True if the connection is allowed.
        """
        if not self._geofencing_enabled:
            return True

        if country_code is None:
            # Ülke tespit edilemediyse varsayılan davranış:
            # - "allow" modeunda izin VERME (güvenli taraf)
            # - "deny" modeunda izin VER
            if self._geofencing_mode == "allow":
                logger.warning(
                    "Country code not detected and geofencing 'allow' mode — "
                    "connection denied."
                )
                return False
            return True

        code = country_code.upper()

        if self._geofencing_mode == "allow":
            allowed = code in self._geofencing_countries
            if not allowed:
                logger.info(
                    "Geofencing: %s country code not in 'allow' list — connection denied.",
                    code,
                )
            return allowed

        elif self._geofencing_mode == "deny":
            denied = code in self._geofencing_countries
            if denied:
                logger.info(
                    "Geofencing: %s country code in 'deny' list — connection denied.",
                    code,
                )
            return not denied

        # Bilinmeyen mode — güvenli tarafta kal, izin ver
        logger.warning("Geofencing: Unknown mode '%s', allowing connection.", self._geofencing_mode)
        return True

    async def reload(self, config: ConfigManager) -> None:
        """
        Reloads the whitelist configuration from the updated config.
        Thread-safe; locks during reload to prevent concurrent access.

        Args:
            config: Updated ConfigManager instance.
        """
        async with self._lock:
            self._whitelisted_ips.clear()
            self._whitelisted_networks.clear()
            self._geofencing_countries.clear()
            await self._load_from_config(config)
            logger.info("Whitelist reloaded.")

    # ── Information ──

    @property
    def stats(self) -> dict:
        """Returns whitelist statistics."""
        return {
            "enabled": self._enabled,
            "ip_count": len(self._whitelisted_ips),
            "cidr_count": len(self._whitelisted_networks),
            "geofencing_enabled": self._geofencing_enabled,
            "geofencing_mode": self._geofencing_mode,
            "geofencing_countries": sorted(self._geofencing_countries),
        }

    # ── Internal Methods ──

    async def _load_from_config(self, config: ConfigManager) -> None:
        """
        Loads whitelist and geofencing settings from ConfigManager.

        Args:
            config: ConfigManager instance.
        """
        # ── Whitelist ──
        wl_section = config.get_section("whitelist")
        self._enabled = wl_section.get("enabled", True)

        if not self._enabled:
            logger.warning(
                "Whitelist disabled! All IPs will be evaluated (manager lock risk)."
            )
            return

        # Unique IPs
        raw_ips: List[str] = wl_section.get("ips", [])
        for raw_ip in raw_ips:
            try:
                self._whitelisted_ips.add(ipaddress.ip_address(raw_ip.strip()))
            except ValueError:
                logger.error(
                    "Invalid whitelist IP address skipped: '%s'", raw_ip
                )

        # CIDR networks
        raw_cidrs: List[str] = wl_section.get("cidr_ranges", [])
        for raw_cidr in raw_cidrs:
            try:
                network = ipaddress.ip_network(raw_cidr.strip(), strict=False)
                self._whitelisted_networks.append(network)
            except ValueError:
                logger.error(
                    "Invalid whitelist CIDR range skipped: '%s'", raw_cidr
                )

        logger.info(
            "Whitelist loaded — %d unique IP, %d CIDR networks.",
            len(self._whitelisted_ips),
            len(self._whitelisted_networks),
        )

        # ── Geofencing ──
        geo_section = config.get_section("geofencing")
        self._geofencing_enabled = geo_section.get("enabled", False)
        self._geofencing_mode = geo_section.get("mode", "allow").lower()
        raw_countries: List[str] = geo_section.get("countries", [])
        self._geofencing_countries = {c.upper() for c in raw_countries}

        if self._geofencing_enabled:
            logger.info(
                "Geofencing aktif — Mod: %s, Ülkeler: %s",
                self._geofencing_mode,
                sorted(self._geofencing_countries),
            )

    def __repr__(self) -> str:
        return (
            f"<WhitelistManager "
            f"enabled={self._enabled} "
            f"ips={len(self._whitelisted_ips)} "
            f"cidrs={len(self._whitelisted_networks)} "
            f"geofencing={self._geofencing_enabled}>"
        )
