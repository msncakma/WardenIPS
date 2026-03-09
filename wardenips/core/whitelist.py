"""
WardenIPS - Asenkron Whitelist Yöneticisi
==========================================

IP ve CIDR tabanlı whitelist kontrolü, geofencing desteği
ve hot-reload yeteneği sağlar.

Yöneticilerin kendi sunucularından kilitlenmesini engeller.
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
    Asenkron Whitelist yöneticisi.

    config.yaml'daki whitelist ve geofencing ayarlarını okuyarak
    gelen IP adreslerinin güvenli olup olmadığını kontrol eder.

    Özellikler:
        - IPv4 ve IPv6 unique IP desteği
        - CIDR blokları (ağ aralıkları) desteği
        - Geofencing — ülke bazlı izin/engelleme
        - Hot-reload — yapılandırma değişikliklerinde listeyi güncelleme
        - O(1) unique IP arama, O(n) CIDR tarama (n = CIDR sayısı)

    Kullanım:
        wl = await WhitelistManager.create(config)
        if await wl.is_whitelisted("192.168.1.1"):
            print("IP güvenli listede!")
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
        ConfigManager'dan yapılandırmayı okuyarak WhitelistManager oluşturur.

        Args:
            config: Yüklenmiş ConfigManager instance.

        Returns:
            Yapılandırılmış WhitelistManager.
        """
        instance = cls()
        await instance._load_from_config(config)
        return instance

    # ── Ana API ──

    async def is_whitelisted(self, ip_str: str) -> bool:
        """
        Bir IP adresinin whitelist'te olup olmadığını kontrol eder.

        Kontrol sırası:
            1. Whitelist devre dışı ise → False (her IP değerlendirilir)
            2. Tekil IP eşleşmesi (O(1) set lookup)
            3. CIDR ağ aralığı eşleşmesi

        Args:
            ip_str: Kontrol edilecek IP adresi (string).

        Returns:
            True ise IP güvenli, banlanmamalı.
        """
        if not self._enabled:
            return False

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.warning("Geçersiz IP formatı, whitelist kontrolü başarısız: %s", ip_str)
            return False

        # 1. Tekil IP kontrolü — O(1)
        if ip in self._whitelisted_ips:
            logger.debug("IP whitelist'te bulundu (tekil): %s", ip_str)
            return True

        # 2. CIDR ağ kontrolü
        for network in self._whitelisted_networks:
            if ip in network:
                logger.debug(
                    "IP whitelist'te bulundu (CIDR %s): %s",
                    network,
                    ip_str,
                )
                return True

        return False

    async def is_country_allowed(self, country_code: Optional[str]) -> bool:
        """
        Geofencing kurallarına göre bir ülke kodunun izinli olup olmadığını kontrol eder.

        Args:
            country_code: ISO 3166-1 alpha-2 ülke kodu (örn: "TR").
                          None ise ülke bilinmiyor demektir.

        Returns:
            True ise bağlantıya izin verilir.
        """
        if not self._geofencing_enabled:
            return True

        if country_code is None:
            # Ülke tespit edilemediyse varsayılan davranış:
            # - "allow" modeunda izin VERME (güvenli taraf)
            # - "deny" modeunda izin VER
            if self._geofencing_mode == "allow":
                logger.warning(
                    "Ülke kodu tespit edilemedi ve geofencing 'allow' modeunda — "
                    "bağlantı reddedildi."
                )
                return False
            return True

        code = country_code.upper()

        if self._geofencing_mode == "allow":
            allowed = code in self._geofencing_countries
            if not allowed:
                logger.info(
                    "Geofencing: %s ülkesi 'allow' listesinde değil — reddedildi.",
                    code,
                )
            return allowed

        elif self._geofencing_mode == "deny":
            denied = code in self._geofencing_countries
            if denied:
                logger.info(
                    "Geofencing: %s ülkesi 'deny' listesinde — reddedildi.",
                    code,
                )
            return not denied

        # Bilinmeyen mode — güvenli tarafta kal, izin ver
        logger.warning("Geofencing: Bilinmeyen mode '%s', izin veriliyor.", self._geofencing_mode)
        return True

    async def reload(self, config: ConfigManager) -> None:
        """
        Whitelist yapılandırmasını güncellenmiş config'den yeniden yükler.
        Thread-safe; yeniden yükleme sırasında kontroller bekletilir.

        Args:
            config: Güncel ConfigManager instance.
        """
        async with self._lock:
            self._whitelisted_ips.clear()
            self._whitelisted_networks.clear()
            self._geofencing_countries.clear()
            await self._load_from_config(config)
            logger.info("Whitelist yeniden yüklendi.")

    # ── Bilgi ──

    @property
    def stats(self) -> dict:
        """Whitelist istatistiklerini döndürür."""
        return {
            "enabled": self._enabled,
            "ip_count": len(self._whitelisted_ips),
            "cidr_count": len(self._whitelisted_networks),
            "geofencing_enabled": self._geofencing_enabled,
            "geofencing_mode": self._geofencing_mode,
            "geofencing_countries": sorted(self._geofencing_countries),
        }

    # ── Dahili Metodlar ──

    async def _load_from_config(self, config: ConfigManager) -> None:
        """
        ConfigManager'dan whitelist ve geofencing ayarlarını okur.

        Args:
            config: ConfigManager instance.
        """
        # ── Whitelist ──
        wl_section = config.get_section("whitelist")
        self._enabled = wl_section.get("enabled", True)

        if not self._enabled:
            logger.warning(
                "Whitelist DEVRE DIŞI! Tüm IP'ler analiz edilecek (yönetici kilidi riski)."
            )
            return

        # Tekil IP'ler
        raw_ips: List[str] = wl_section.get("ips", [])
        for raw_ip in raw_ips:
            try:
                self._whitelisted_ips.add(ipaddress.ip_address(raw_ip.strip()))
            except ValueError:
                logger.error(
                    "Geçersiz whitelist IP adresi atlanıyor: '%s'", raw_ip
                )

        # CIDR ağ aralıkları
        raw_cidrs: List[str] = wl_section.get("cidr_ranges", [])
        for raw_cidr in raw_cidrs:
            try:
                network = ipaddress.ip_network(raw_cidr.strip(), strict=False)
                self._whitelisted_networks.append(network)
            except ValueError:
                logger.error(
                    "Geçersiz whitelist CIDR aralığı atlanıyor: '%s'", raw_cidr
                )

        logger.info(
            "Whitelist loaded — %d unique IP, %d CIDR aralığı.",
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
