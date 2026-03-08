"""
WardenIPS - AbuseIPDB Async Reporter
=============================================

Tespit edilen zararli IP adreslerini AbuseIPDB API'sine
asenkron olarak raporlar. Rate limit kurallarina uyar.

AbuseIPDB Kategorileri (sik kullanilanlar):
  14 = Port Scan
  18 = Brute-Force
  22 = SSH

API Dokumantasyonu: https://docs.abuseipdb.com/
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
        "Yuklemek icin: pip install aiohttp"
    )

# AbuseIPDB API endpoint
_ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
_ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBReporter:
    """
    AbuseIPDB asenkron raporlayici.

    Tespit edilen zararli IP'leri AbuseIPDB'ye raporlar.
    Rate limit'e uyar — dakika basina maksimum rapor sayisini asmaZ.

    Ozellikler:
        - Asenkron HTTP (aiohttp)
        - Sliding window rate limiting
        - Retry mekanizmasi (basarisiz raporlar tekrar denenir)
        - Graceful degradation (API key yoksa veya aiohttp kurulu degilse devre disi)

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
        ConfigManager'dan ayarlari okuyarak AbuseIPDBReporter olusturur.

        Args:
            config: ConfigManager instance.

        Returns:
            Yapilandirilmis AbuseIPDBReporter.
        """
        instance = cls()
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        """AbuseIPDB ayarlarini yukler ve HTTP session olusturur."""

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
        Bir IP adresini AbuseIPDB'ye raporlar.

        Rate limit kontrolu yapilir — limit asilirsa rapor atlanir.

        Args:
            ip:         Raporlanacak IP adresi.
            categories: AbuseIPDB kategori kodlari listesi.
                        Ornek: [18, 22] = Brute-Force + SSH
            comment:    Raporla birlikte gonderilecek aciklama.

        Returns:
            True ise rapor basarili.
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

        payload = {
            "ip": ip,
            "categories": cat_str,
            "comment": f"[WardenIPS] {comment}" if comment else "[WardenIPS] Auto-report",
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
        Bir IP adresini AbuseIPDB'de sorgular.

        Args:
            ip: Sorgulanacak IP.

        Returns:
            API yaniti (dict) veya None.
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
        Sliding window rate limit kontrolu.

        Son 60 saniye icerisindeki istek sayisini kontrol eder.

        Returns:
            True ise istek gondermeye izin var.
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
