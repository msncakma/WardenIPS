"""
WardenIPS - KVKK Uyumlu IP Hash'leme Modulu
==============================================

KVKK (Kisisel Verilerin Korunmasi Kanunu) geregi IP adresleri
veritabanina duz metin olarak YAZILMAZ.

Bu modeul, IP adreslerini yapilandirmada tanimlanan bir Salt degeri
ile SHA-256 hash'leyerek anonimlestirir. Ayni IP + ayni Salt
= her zaman ayni hash, boylece korelasyon analizi yapilabilir
ama IP geri elde edilemez.

DİKKAT: Salt degeri degistirilirse eski hash'ler eslesmez!
"""

from __future__ import annotations

import hashlib
import hmac

from wardenips.core.logger import get_logger

logger = get_logger(__name__)


class IPHasher:
    """
    KVKK uyumlu IP anonimlestiricisi.

    HMAC + SHA-256 kullanarak IP adreslerini tek yonlu hash'ler.
    Salt degeri config.yaml'dan alinir.

    Usage:
        hasher = IPHasher(salt="guclu-salt-degeri", algorithm="sha256")
        hashed = hasher.hash_ip("192.168.1.1")
        # hashed = "a3f2b8c1d4e5..."  (64 char hex)
    """

    # Desteklenen hash algoritmalari
    _SUPPORTED_ALGORITHMS = {"sha256", "sha384", "sha512"}

    def __init__(self, salt: str, algorithm: str = "sha256") -> None:
        """
        IP hasher'i baslatir.

        Args:
            salt:      Hash'lemede kullanilacak gizli salt degeri.
            algorithm: Hash algoritmasi ("sha256", "sha384", "sha512").

        Raises:
            ValueError: Salt bos ise veya algoritma desteklenmiyorsa.
        """
        if not salt or salt == "BURAYA-GUCLU-BIR-SALT-DEGERI-YAZIN":
            logger.warning(
                "IP hash salt degeri degistirilmemis veya bos! "
                "Guvenlik riski — config.yaml'da salt degerini guncelleyin."
            )

        if algorithm not in self._SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Desteklenmeyen hash algoritmasi: '{algorithm}'. "
                f"Desteklenenler: {self._SUPPORTED_ALGORITHMS}"
            )

        self._salt: bytes = salt.encode("utf-8")
        self._algorithm: str = algorithm

        logger.debug(
            "IPHasher started. Algorithm: %s, Salt length: %d",
            algorithm, len(self._salt),
        )

    def hash_ip(self, ip_str: str) -> str:
        """
        Bir IP adresini HMAC + hash ile anonimlestirir.

        HMAC kullanimi basit hash+salt'a gore daha guvenlidir
        (length extension saldirilarina karsi koruma saglar).

        Args:
            ip_str: Hash'lenecek IP adresi (duz metin).

        Returns:
            Hex formatinda hash string (orn: "a3f2b8..." 64 karakter).
        """
        if not self._enabled:
            return ip_str.strip()
            
        ip_bytes = ip_str.strip().encode("utf-8")
        digest = hmac.new(self._salt, ip_bytes, self._algorithm).hexdigest()
        return digest

    def verify_ip(self, ip_str: str, expected_hash: str) -> bool:
        """
        Bir IP'nin bilinen bir hash ile eslesip eslesmedigini dogrular.

        Zamanlama saldirilarina karsi hmac.compare_digest kullanir.

        Args:
            ip_str:        Dogrulanacak IP adresi.
            expected_hash: Beklenen hash degeri.

        Returns:
            True ise hash'ler eslesir.
        """
        if not self._enabled:
            return ip_str.strip() == expected_hash.strip()
            
        computed = self.hash_ip(ip_str)
        return hmac.compare_digest(computed, expected_hash)

    @classmethod
    def from_config(cls, config) -> IPHasher:
        """
        ConfigManager'dan salt ve algoritma ayarlarini okuyarak
        IPHasher olusturur.

        Args:
            config: ConfigManager instance.

        Returns:
            Yapilandirilmis IPHasher.
        """
        db_section = config.get_section("database")
        hashing = db_section.get("ip_hashing", {})
        salt = hashing.get("salt", "")
        algorithm = hashing.get("algorithm", "sha256")
        enabled = hashing.get("enabled", True)
        return cls(salt=salt, algorithm=algorithm, enabled=enabled)

    def __repr__(self) -> str:
        return f"<IPHasher algorithm={self._algorithm}>"
