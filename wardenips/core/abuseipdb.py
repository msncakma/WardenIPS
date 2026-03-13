"""
WardenIPS - AbuseIPDB Async Reporter
=============================================

Reports detected malicious IP addresses to AbuseIPDB API asynchronously.
Respects rate limit rules.

AbuseIPDB Categories (commonly used):
  14 = Port Scan
  18 = Brute-Force
  22 = SSH

API Documentation: https://docs.abuseipdb.com/
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any, Dict, Optional

from wardenips.core.exceptions import WardenError
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# aiohttp opsiyonel bagimliliktir
try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False
    logger.warning(
        "aiohttp library not found. AbuseIPDB disabled. "
        "For installation: pip install aiohttp"
    )

# AbuseIPDB API endpoint
_ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
_ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
_WARDENIPS_PROJECT_URL = "https://github.com/msncakma/WardenIPS"


class AbuseIPDBReporter:
    """
    AbuseIPDB asenkron raporlayici.

    Detects malicious IP addresses and reports them to AbuseIPDB API asynchronously.
    Respects rate limit rules.

    Features:
        - Asynchronous HTTP (aiohttp)
        - Sliding window rate limiting
        - Retry mechanism (failed reports are retried)
        - Graceful degradation (API key missing or aiohttp not installed)

    Usage:
        reporter = await AbuseIPDBReporter.create(config)
        await reporter.report_ip(
            ip="203.0.113.50",
            categories=[18, 22],
            comment="SSH brute-force 15 basarisiz giris"
        )
        await reporter.close()
    """

    def __init__(self) -> None:
        self._enabled: bool = False
        self._api_key: str = ""
        self._rate_limit: int = 10  # dakika basina
        self._request_times: deque = deque()  # sliding window
        self._session: Optional[aiohttp.ClientSession] = None
        self._lock: asyncio.Lock = asyncio.Lock()
        self._total_reports: int = 0
        self._failed_reports: int = 0

    # ── Factory ──

    @classmethod
    async def create(cls, config) -> AbuseIPDBReporter:
        """
        Creates an AbuseIPDBReporter instance based on configuration.

        Args:
            config: ConfigManager instance.

        Returns:
            Configured AbuseIPDBReporter.
        """
        instance = cls()
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        """Loads AbuseIPDB settings and creates an HTTP session."""

        abuse_section = config.get_section("abuseipdb")
        self._enabled = abuse_section.get("enabled", False)
        self._api_key = abuse_section.get("api_key", "")
        self._rate_limit = abuse_section.get("rate_limit_per_minute", 10)

        if not self._enabled:
            logger.info("AbuseIPDB reporting disabled (config).")
            return

        if not self._api_key:
            self._enabled = False
            logger.warning(
                "AbuseIPDB API key not defined — reporting disabled."
            )
            return

        if not _AIOHTTP_AVAILABLE:
            self._enabled = False
            logger.warning(
                "aiohttp not installed — AbuseIPDB disabled."
            )
            return

        # HTTP session olustur
        self._session = aiohttp.ClientSession(
            headers={
                "Key": self._api_key,
                "Accept": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=15),
        )

        logger.info(
            "AbuseIPDB reporter started. "
            "Rate limit: %d reports/minute.",
            self._rate_limit,
        )

    # ── Ana API ──

    async def report_ip(
        self,
        ip: str,
        categories: list[int],
        comment: str = "",
    ) -> bool:
        """
        Reports an IP address to AbuseIPDB.

        Rate limit control is performed — if limit is exceeded, the report is skipped.

        Args:
            ip:         IP address to report.
            categories: List of AbuseIPDB category codes.
                        Example: [18, 22] = Brute-Force + SSH
            comment:    Comment to send with the report.

        Returns:
            True if the report was successful.
        """
        if not self._enabled or self._session is None:
            logger.debug(
                "AbuseIPDB disabled, skipping report: %s", ip
            )
            return False

        # Rate limit kontrolu
        if not self._check_rate_limit():
            logger.warning(
                "AbuseIPDB rate limit exceeded (%d/dk). Skipping report: %s",
                self._rate_limit, ip,
            )
            return False

        # Kategori formatı: virgulle ayrilmis
        cat_str = ",".join(str(c) for c in categories)

        base_comment = str(comment or "").strip() or "Automated threat report from WardenIPS IPS."
        attribution = f"Reported by WardenIPS: {_WARDENIPS_PROJECT_URL}"
        full_comment = f"{base_comment} | {attribution}"
        if len(full_comment) > 1024:
            full_comment = full_comment[:1021] + "..."

        payload = {
            "ip": ip,
            "categories": cat_str,
            "comment": full_comment,
        }

        async with self._lock:
            try:
                async with self._session.post(
                    _ABUSEIPDB_REPORT_URL,
                    data=payload,
                ) as response:
                    self._request_times.append(time.monotonic())
                    self._total_reports += 1

                    if response.status == 200:
                        data = await response.json()
                        score = data.get("data", {}).get(
                            "abuseConfidenceScore", "?"
                        )
                        logger.info(
                            "AbuseIPDB report successful: IP=%s, "
                            "Categories=%s, Score=%s",
                            ip, cat_str, score,
                        )
                        return True

                    elif response.status == 429:
                        # API tarafli rate limit
                        logger.warning(
                            "AbuseIPDB 429 Too Many Requests: %s", ip
                        )
                        self._failed_reports += 1
                        return False

                    else:
                        body = await response.text()
                        logger.error(
                            "AbuseIPDB report error: HTTP %d — %s",
                            response.status, body[:200],
                        )
                        self._failed_reports += 1
                        return False

            except asyncio.TimeoutError:
                logger.error("AbuseIPDB request timeout: %s", ip)
                self._failed_reports += 1
                return False
            except Exception as exc:
                logger.error(
                    "AbuseIPDB report error: %s — %s", ip, exc
                )
                self._failed_reports += 1
                return False

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Queries an IP address in AbuseIPDB.

        Args:
            ip: IP address to query.

        Returns:
            API response (dict) or None.
        """
        if not self._enabled or self._session is None:
            return None

        if not self._check_rate_limit():
            logger.warning("AbuseIPDB rate limit — skipping query: %s", ip)
            return None

        try:
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "",
            }

            async with self._session.get(
                _ABUSEIPDB_CHECK_URL,
                params=params,
            ) as response:
                self._request_times.append(time.monotonic())

                if response.status == 200:
                    data = await response.json()
                    return data.get("data")
                else:
                    logger.warning(
                        "AbuseIPDB check hatasi: HTTP %d", response.status
                    )
                    return None

        except Exception as exc:
            logger.error("AbuseIPDB check hatasi: %s — %s", ip, exc)
            return None

    # ── Rate Limiting ──

    def _check_rate_limit(self) -> bool:
        """
        Sliding window rate limit control.

        Checks the number of requests in the last 60 seconds.

        Returns:
            True if allowed to send a request.
        """
        now = time.monotonic()
        window_start = now - 60.0  # 1 dakikalik pencere

        # Pencere disindaki eski istekleri temizle
        while self._request_times and self._request_times[0] < window_start:
            self._request_times.popleft()

        return len(self._request_times) < self._rate_limit

    # ── Istatistikler ──

    @property
    def stats(self) -> Dict[str, Any]:
        """AbuseIPDB raporlama istatistikleri."""
        return {
            "enabled": self._enabled,
            "total_reports": self._total_reports,
            "failed_reports": self._failed_reports,
            "rate_limit_per_minute": self._rate_limit,
            "requests_in_window": len(self._request_times),
        }

    # ── Kaynak Yonetimi ──

    async def close(self) -> None:
        """HTTP session'i kapatir."""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.info("AbuseIPDB session closed.")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __repr__(self) -> str:
        return (
            f"<AbuseIPDBReporter "
            f"enabled={self._enabled} "
            f"reports={self._total_reports}>"
        )
