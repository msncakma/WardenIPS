"""
WardenIPS - Lokal ASN Koruma Motoru
====================================

Loyalsoldier/geoip GitHub reposundan (ücretsiz, üyelik yok) sunulan
GeoLite2 ASN veritabanıni kullanarak, IP adreslerinin ASN numarası,
organizasyon adı ve "şüpheli ASN listesi"nde olup olmadığını saniyenin
binde biri hızında çözer.

API limitlerine takılmaz — tamamen lokal işlem.
Üyelik gerektirmez — sadece GitHub'dan otomatik indirilmiş dosya.

Otomatik Güncellemeler:
- Her Perşembe günü (Loyalsoldier repo update zamanlaması)
- Ağ hatası durumunda sessiz başarısız olur, eski dosya kullanılır
- weekly_update() async method ile manuel çağrılabilir
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from pathlib import Path
from typing import Optional, Set
from urllib.error import URLError
from urllib.request import urlretrieve

from wardenips.core.exceptions import WardenError
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# GeoIP2 kütüphanesi yalnızca MaxMind-uyumlu .mmdb dosyaları mevcutsa kullanılır.
try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False
    logger.warning(
        "geoip2 kütüphanesi bulunamadı. ASN koruma devre dışı. "
        "Yüklemek için: pip install geoip2"
    )


class ASNLookupResult:
    """
    Tek bir IP için ASN sorgu sonucu.

    Attributes:
        asn_number:     Otonom Sistem numarası (orn: 16509).
        asn_org:        Organizasyon adı (orn: "AMAZON-02").
        is_suspicious:  IP şüpheli ASN listesinde mi?
    """

    __slots__ = ("asn_number", "asn_org", "is_suspicious")

    def __init__(
        self,
        asn_number: Optional[int] = None,
        asn_org: Optional[str] = None,
        is_suspicious: bool = False,
    ) -> None:
        self.asn_number = asn_number
        self.asn_org = asn_org
        self.is_suspicious = is_suspicious

    def __repr__(self) -> str:
        return (
            f"<ASNLookupResult "
            f"ASN={self.asn_number} "
            f"Org='{self.asn_org}' "
            f"Suspicious={self.is_suspicious}>"
        )


class ASNLookupEngine:
    """
    Loyalsoldier/geoip tabanındaki lokal ASN sorgu motoru.

    GeoLite2-ASN.mmdb (GitHub'dan ücretsiz, üyelik yok)
    -> ASN numarası ve organizasyon adı
    -> Kullanıcı tarafından tanımlanmış "şüpheli ASN" listesinde kontrolü

    Veritabanı dosyası mevcut değilse graceful degradation uygular:
    motor çalışmaya devam eder, sadece bilgi eksik kalır.

    Usage:
        engine = ASNLookupEngine(config)
        result = engine.lookup("8.8.8.8")
        print(result.asn_number)      # 15169
        print(result.asn_org)         # "GOOGLE"
        print(result.is_suspicious)   # False (siz eklememedikçe)
    """

    # Loyalsoldier/geoip GitHub kaynağı
    GITHUB_ASN_URL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-ASN.mmdb"

    def __init__(self, config) -> None:
        """
        ASN motorunu yapılandırır.

        Args:
            config: ConfigManager instance.
        """
        self._asn_reader: Optional[geoip2.database.Reader] = None
        self._suspicious_asns: Set[int] = set()
        self._initialized: bool = False

        self._load(config)

    async def ensure_asn_database(self, config) -> bool:
        """
        ASN veritabanının mevcut olup olmadığını kontrol eder,
        yoksa GitHub'dan otomatik olarak indirir.

        Returns:
            True ise dosya mevcut/başarıyla indirildi, False ise başarısız.
        """
        asn_section = config.get_section("asn_protection")
        db_path = asn_section.get("db_path", "/opt/wardenips/assets/GeoLite2-ASN.mmdb")
        
        db_file = Path(db_path)
        
        # Dosya zaten mevcutsa hiçbir şey yapma
        if db_file.exists():
            logger.info("GeoLite2-ASN.mmdb zaten mevcut: %s", db_path)
            return True
        
        # Klasörü oluştur
        db_file.parent.mkdir(parents=True, exist_ok=True)
        
        # GitHub'dan indir
        logger.info("GeoLite2-ASN.mmdb GitHub'dan indiriliyor: %s", self.GITHUB_ASN_URL)
        try:
            await asyncio.to_thread(
                urlretrieve,
                self.GITHUB_ASN_URL,
                str(db_file)
            )
            logger.info("GeoLite2-ASN.mmdb başarıyla indirildi: %s", db_path)
            return True
        except (URLError, Exception) as exc:
            logger.error("GeoLite2-ASN.mmdb indirilemedi: %s", exc)
            return False

    def _load(self, config) -> None:
        """ASN veritabanını yükler."""

        if not _GEOIP2_AVAILABLE:
            logger.error("geoip2 library not found — ASN engine disabled.")
            return

        asn_section = config.get_section("asn_protection")

        if not asn_section.get("enabled", False):
            logger.info("ASN koruma devre dışı (config: asn_protection.enabled=false)")
            return

        # -- ASN Veritabanı --
        db_path = asn_section.get("db_path", "/opt/wardenips/assets/GeoLite2-ASN.mmdb")
        if Path(db_path).exists():
            try:
                self._asn_reader = geoip2.database.Reader(db_path)
                logger.info("GeoLite2-ASN veritabanı yüklendi: %s", db_path)
            except Exception as exc:
                logger.error(
                    "GeoLite2-ASN veritabanı açılamadı: %s — %s",
                    db_path, exc,
                )
        else:
            logger.warning(
                "GeoLite2-ASN database not found: %s — "
                "ASN lookup will be disabled. "
                "Dosya sistem başlangıçında otomatik indirilecek.",
                db_path,
            )

        # -- Şüpheli ASN Listesi --
        suspicious_asns_config = asn_section.get("suspicious_asns", [])
        self._suspicious_asns = self._parse_asn_list(suspicious_asns_config)
        logger.info(
            "Şüpheli ASN sayısı: %d", len(self._suspicious_asns)
        )

        self._initialized = True

    @staticmethod
    def _parse_asn_list(raw_list: list) -> Set[int]:
        """
        ASN listesini parse eder.
        Girdi: ["AS16509", "14061", "AS20473"]
        Çıktı: {16509, 14061, 20473}
        """
        parsed = set()
        for item in raw_list:
            try:
                # "AS" ön ekini kaldır
                item_str = str(item).replace("AS", "").replace("as", "").strip()
                parsed.add(int(item_str))
            except (ValueError, TypeError):
                logger.warning("Geçersiz ASN formatı: %s", item)
        return parsed

    # ── Ana API ──

    def lookup(self, ip_str: str) -> ASNLookupResult:
        """
        Bir IP adresi için ASN, organizasyon ve şüpheli ASN kontrolünü sorgular.

        Veritabanından lokal olarak okur — hiçbir harici API çağrısı yapılmaz.
        Veritabanı yüklü değilse boş (ama geçerli) bir sonuç döndürür.

        Args:
            ip_str: Sorgulanacak IP adresi (string).

        Returns:
            ASNLookupResult nesnesi.
        """
        result = ASNLookupResult()

        if not self._initialized or self._asn_reader is None:
            return result

        # -- ASN Sorgusu --
        try:
            asn_response = self._asn_reader.asn(ip_str)
            result.asn_number = asn_response.autonomous_system_number
            result.asn_org = asn_response.autonomous_system_organization
            
            # Şüpheli ASN kontrolü
            if result.asn_number and result.asn_number in self._suspicious_asns:
                result.is_suspicious = True
                
        except geoip2.errors.AddressNotFoundError:
            logger.debug("ASN kaydında bulunamadı: %s", ip_str)
        except Exception as exc:
            logger.warning("ASN sorgusu başarısız (%s): %s", ip_str, exc)

        return result

    def is_suspicious_ip(self, ip_str: str) -> bool:
        """
        IP'nin şüpheli ASN'de olup olmadığını hızlıca kontrol eder.

        Args:
            ip_str: Kontrol edilecek IP.

        Returns:
            True ise şüpheli ASN.
        """
        return self.lookup(ip_str).is_suspicious

    # ── Kaynak Yönetimi ──

    def close(self) -> None:
        """ASN reader nesnesini kapatır."""
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None
            logger.debug("ASN reader kapatıldı.")

    # ── Haftalık Güncelleme ──

    async def weekly_update(self, config) -> bool:
        """
        GeoLite2-ASN.mmdb'yi GitHub'dan haftalık olarak güncelle.
        
        Perşembe günü Loyalsoldier repo'su güncellendiği için,
        bu method Perşembe gecesi otomatik çalışmalı.
        
        Returns:
            True ise güncelleme başarılı, False ise başarısız/atlandı.
        """
        asn_section = config.get_section("asn_protection")
        
        if not asn_section.get("auto_update_enabled", True):
            logger.debug("ASN auto_update disabled in config")
            return False
        
        db_path = asn_section.get("db_path", "/opt/wardenips/assets/GeoLite2-ASN.mmdb")
        db_file = Path(db_path)
        
        logger.info("GeoLite2-ASN haftalık güncellemesi başlıyor...")
        
        try:
            # Geçici dosya olarak indir
            temp_file = db_file.parent / f"{db_file.name}.tmp"
            
            await asyncio.to_thread(
                urlretrieve,
                self.GITHUB_ASN_URL,
                str(temp_file)
            )
            
            # Dosya boyutunu kontrol et (en az 1MB olmalı)
            if temp_file.stat().st_size < 1_000_000:
                logger.warning(
                    "GeoLite2-ASN güncellemesi başarısız: dosya çok küçük"
                )
                temp_file.unlink(missing_ok=True)
                return False
            
            # Eski dosyayı yedekle, yenisini koy
            backup_file = db_file.parent / f"{db_file.name}.bak"
            if db_file.exists():
                db_file.replace(backup_file)
            
            temp_file.rename(db_file)
            
            # Reader'ı yeniden yükle
            self._load(config)
            
            logger.info(
                "GeoLite2-ASN başarıyla güncellendi. Eski sürüm: %s",
                backup_file,
            )
            return True
            
        except (URLError, OSError, Exception) as exc:
            logger.error("GeoLite2-ASN güncellemesi başarısız: %s", exc)
            return False
    
    def get_next_thursday_update_time(self) -> datetime.datetime:
        """
        Bir sonraki Perşembe günü saat 03:00 UTC'yi hesapla.
        (Loyalsoldier repo update zamanlaması)
        
        Returns:
            datetime.datetime object.
        """
        now = datetime.datetime.utcnow()
        # Perşembe = 3 (Monday=0)
        days_until_thursday = (3 - now.weekday()) % 7
        if days_until_thursday == 0 and now.hour >= 3:
            # Bugün Perşembe ama saat 03:00 geçti, next week
            days_until_thursday = 7
        
        next_thursday = now + datetime.timedelta(days=days_until_thursday)
        next_update = next_thursday.replace(hour=3, minute=0, second=0, microsecond=0)
        return next_update

    def start_weekly_scheduler(self, config) -> asyncio.Task:
        """
        Haftalık güncelleme scheduler'ını başlat.
        
        Her Perşembe sabahı 03:00 UTC'de GeoLite2-ASN'yi GitHub'dan güncelle.
        Çalışır durumda kalacağı sürece loop'ta kalır.
        
        Returns:
            asyncio.Task — background task olarak çalışır.
        """
        async def _update_loop():
            while True:
                try:
                    next_update = self.get_next_thursday_update_time()
                    wait_seconds = (
                        next_update - datetime.datetime.utcnow()
                    ).total_seconds()
                    
                    logger.info(
                        "Sonraki ASN güncellemesi: %s UTC (%d saniye)",
                        next_update.isoformat(),
                        wait_seconds,
                    )
                    
                    # İlk olarak wait et
                    await asyncio.sleep(wait_seconds)
                    
                    # Güncellemeyi yap
                    success = await self.weekly_update(config)
                    if success:
                        logger.info("✓ Haftalık ASN güncellemesi tamamlandı")
                    else:
                        logger.warning("✗ Haftalık ASN güncellemesi başarısız, eski sürüm korunmuştur")
                    
                except asyncio.CancelledError:
                    logger.debug("ASN scheduler task cancelled")
                    break
                except Exception as exc:
                    logger.error("ASN scheduler error: %s", exc)
                    # Hata durumunda, 1 saat sonra tekrar dene
                    await asyncio.sleep(3600)
        
        return asyncio.create_task(_update_loop())


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
