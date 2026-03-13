"""
WardenIPS - Optional GeoLite2 Country Lookup
===========================================

Provides country-code enrichment for dashboard heatmaps when a
GeoLite2-Country.mmdb database is available locally.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from wardenips.core.logger import get_logger

logger = get_logger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False


class CountryLookupEngine:
    """Reads country codes from a local GeoLite2 Country database."""

    def __init__(self, config) -> None:
        self._reader: Optional[geoip2.database.Reader] = None
        self._enabled: bool = False
        self._db_path: str = ""
        self._load(config)

    def _load(self, config) -> None:
        if not _GEOIP2_AVAILABLE:
            logger.debug("geoip2 not installed; country lookup disabled.")
            return

        asn_section = config.get_section("asn_protection")
        self._enabled = bool(asn_section.get("enabled", False))
        self._db_path = str(
            asn_section.get(
                "country_db_path",
                "/var/lib/wardenips/GeoLite2-Country.mmdb",
            )
        )

        if not self._enabled:
            return

        db_file = Path(self._db_path)
        if not db_file.exists():
            logger.info(
                "GeoLite2-Country database not found: %s — country heatmap enrichment disabled.",
                self._db_path,
            )
            return

        try:
            self._reader = geoip2.database.Reader(str(db_file))
            logger.info("GeoLite2-Country database loaded: %s", self._db_path)
        except Exception as exc:
            logger.warning("Failed to load GeoLite2-Country database %s: %s", self._db_path, exc)
            self._reader = None

    def lookup_country_code(self, ip_str: str) -> Optional[str]:
        if not self._reader:
            return None
        try:
            response = self._reader.country(ip_str)
            code = response.country.iso_code or response.registered_country.iso_code
            return str(code).upper() if code else None
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as exc:
            logger.debug("Country lookup failed for %s: %s", ip_str, exc)
            return None

    def close(self) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None
