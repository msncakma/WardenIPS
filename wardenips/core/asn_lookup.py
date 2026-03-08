"""
WardenIPS - Lokal ASN Lookup Motoru
=====================================

MaxMind GeoLite2 ASN ve Country veritabanlarini lokal olarak okuyarak
IP adreslerinin ASN numarasi, organizasyon adi, countries kodu ve
datacenter durumunu saniyenin binde biri hizinda cozer.

API limitlerine takilmaz — tamamen lokal islem.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Set

from wardenips.core.exceptions import WardenError
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# GeoIP2 kutuphanesi yalnizca MaxMind .mmdb dosyalari mevcutsa kullanilir.
try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False
    logger.warning(
        "geoip2 kutuphanesi bulunamadi. ASN lookup devre disi. "
        "Yuklemek icin: pip install geoip2"
    )


class ASNLookupResult:
    """
    Tek bir IP icin ASN sorgu sonucu.

    Attributes:
        asn_number:    Otonom Sistem numarasi (orn: 16509).
        asn_org:       Organizasyon adi (orn: "AMAZON-02").
        country_code:  ISO 3166-1 alpha-2 countries kodu (orn: "TR").
        is_datacenter: IP bilinen bir datacenter ASN'ine mi ait?
    """

    __slots__ = ("asn_number", "asn_org", "country_code", "is_datacenter")

    def __init__(
        self,
        asn_number: Optional[int] = None,
        asn_org: Optional[str] = None,
        country_code: Optional[str] = None,
        is_datacenter: bool = False,
    ) -> None:
        self.asn_number = asn_number
        self.asn_org = asn_org
        self.country_code = country_code
        self.is_datacenter = is_datacenter

    def __repr__(self) -> str:
        return (
            f"<ASNLookupResult "
            f"ASN={self.asn_number} "
            f"Org='{self.asn_org}' "
            f"Country={self.country_code} "
            f"DC={self.is_datacenter}>"
        )


class ASNLookupEngine:
    """
    MaxMind GeoLite2 tabanli lokal ASN sorgu motoru.

    GeoLite2-ASN.mmdb  -> ASN numarasi ve organizasyon adi
    GeoLite2-Country.mmdb -> Ulke kodu (geofencing icin)

    Veritabani dosyalari mevcut degilse graceful degradation uygular:
    motor calismaya devam eder, sadece bilgi eksik kalir.

    Usage:
        engine = ASNLookupEngine(config)
        result = engine.lookup("8.8.8.8")
        print(result.asn_number)   # 15169
        print(result.asn_org)      # "GOOGLE"
        print(result.is_datacenter) # True
    """

    def __init__(self, config) -> None:
        """
        ASN motorunu yapilandirir.

        Args:
            config: ConfigManager instance.
        """
        self._asn_reader: Optional[geoip2.database.Reader] = None
        self._country_reader: Optional[geoip2.database.Reader] = None
        self._datacenter_asns: Set[int] = set()
        self._initialized: bool = False

        self._load(config)

    def _load(self, config) -> None:
        """MaxMind veritabanlarini yukler."""

        if not _GEOIP2_AVAILABLE:
            logger.error(
                "geoip2 library not found — ASN engine disabled."
            )
            return

        maxmind_section = config.get_section("maxmind")

        # -- ASN Veritabani --
        asn_db_path = maxmind_section.get("asn_db_path", "")
        if asn_db_path and Path(asn_db_path).exists():
            try:
                self._asn_reader = geoip2.database.Reader(asn_db_path)
                logger.info("GeoLite2-ASN veritabani yuklendi: %s", asn_db_path)
            except Exception as exc:
                logger.error(
                    "GeoLite2-ASN veritabani acilamadi: %s — %s",
                    asn_db_path, exc,
                )
        else:
            logger.warning(
                "GeoLite2-ASN database not found: %s — "
                "ASN lookup will be disabled.",
                asn_db_path,
            )

        # -- Country Veritabani --
        country_db_path = maxmind_section.get("country_db_path", "")
        if country_db_path and Path(country_db_path).exists():
            try:
                self._country_reader = geoip2.database.Reader(country_db_path)
                logger.info(
                    "GeoLite2-Country veritabani yuklendi: %s", country_db_path
                )
            except Exception as exc:
                logger.error(
                    "GeoLite2-Country veritabani acilamadi: %s — %s",
                    country_db_path, exc,
                )
        else:
            logger.warning(
                "GeoLite2-Country database not found: %s — "
                "Country lookup will be disabled.",
                country_db_path,
            )

        # -- Datacenter ASN Listesi --
        dc_asns = maxmind_section.get("datacenter_asns", [])
        self._datacenter_asns = set(dc_asns)
        logger.info(
            "Known datacenter ASN count: %d", len(self._datacenter_asns)
        )

        self._initialized = True

    # ── Ana API ──

    def lookup(self, ip_str: str) -> ASNLookupResult:
        """
        Bir IP adresi icin ASN, organizasyon, countries ve datacenter bilgisini sorgular.

        MaxMind veritabanlarindan lokal olarak okur — hicbir harici API cagrisi yapilmaz.
        Veritabani yuklu degilse bos (ama gecerli) bir sonuc dondurur.

        Args:
            ip_str: Sorgulanacak IP adresi (string).

        Returns:
            ASNLookupResult nesnesi.
        """
        result = ASNLookupResult()

        if not self._initialized:
            return result

        # -- ASN Sorgusu --
        if self._asn_reader is not None:
            try:
                asn_response = self._asn_reader.asn(ip_str)
                result.asn_number = asn_response.autonomous_system_number
                result.asn_org = asn_response.autonomous_system_organization
                # Datacenter kontrolu
                if result.asn_number and result.asn_number in self._datacenter_asns:
                    result.is_datacenter = True
            except geoip2.errors.AddressNotFoundError:
                logger.debug("ASN kaydinda bulunamadi: %s", ip_str)
            except Exception as exc:
                logger.warning("ASN sorgusu basarisiz (%s): %s", ip_str, exc)

        # -- Ulke Sorgusu --
        if self._country_reader is not None:
            try:
                country_response = self._country_reader.country(ip_str)
                result.country_code = country_response.country.iso_code
            except geoip2.errors.AddressNotFoundError:
                logger.debug("Ulke kaydinda bulunamadi: %s", ip_str)
            except Exception as exc:
                logger.warning("Ulke sorgusu basarisiz (%s): %s", ip_str, exc)

        return result

    def is_datacenter_ip(self, ip_str: str) -> bool:
        """
        IP'nin datacenter'a ait olup olmadigini hizlica kontrol eder.

        Args:
            ip_str: Kontrol edilecek IP.

        Returns:
            True ise datacenter IP'si.
        """
        return self.lookup(ip_str).is_datacenter

    # ── Kaynak Yonetimi ──

    def close(self) -> None:
        """MaxMind reader nesnelerini kapatir."""
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None
            logger.debug("ASN reader kapatildi.")
        if self._country_reader:
            self._country_reader.close()
            self._country_reader = None
            logger.debug("Country reader kapatildi.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def __repr__(self) -> str:
        return (
            f"<ASNLookupEngine "
            f"asn_db={'loaded' if self._asn_reader else 'N/A'} "
            f"country_db={'loaded' if self._country_reader else 'N/A'} "
            f"dc_asns={len(self._datacenter_asns)}>"
        )
