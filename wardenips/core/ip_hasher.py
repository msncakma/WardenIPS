"""
WardenIPS - KVKK Uyumlu IP Hash'leme Modulu
==============================================

This module anonymizes IP addresses using a SHA-256 hash, 
based on a salt value defined in the configuration. 

The same IP + same salt = always the same hash, 
allowing correlation analysis, but the IP cannot be 
retrieved. 

WARNING: If the salt value is changed, the old hashes 
will not match!
"""

from __future__ import annotations

import hashlib
import hmac

from wardenips.core.logger import get_logger

logger = get_logger(__name__)


class IPHasher:
    """
    Using HMAC + SHA-256 to anonymize IP addresses.
    The same IP + same salt = always the same hash, 
    allowing correlation analysis, but the IP cannot be 
    retrieved. 

    Usage:
        hasher = IPHasher(salt="guclu-salt-degeri", algorithm="sha256")
        hashed = hasher.hash_ip("192.168.1.1")
        # hashed = "a3f2b8c1d4e5..."  (64 char hex)
    """

    # Supported hash algorithms
    _SUPPORTED_ALGORITHMS = {"sha256", "sha384", "sha512"}

    def __init__(self, salt: str, algorithm: str = "sha256", enabled: bool = True) -> None:
        """
        Starting the IP hasher.

        Args:
            salt:      Hash algorithm salt value.
            algorithm: Hash algorithm ("sha256", "sha384", "sha512").
            enabled:   If false, skips hashing and returns the original IP.

        Raises:
            ValueError: If salt is empty or algorithm is unsupported.
        """
        self._enabled = enabled

        if self._enabled and (not salt or salt == "BURAYA-GUCLU-BIR-SALT-DEGERI-YAZIN" or salt == "YOUR-RANDOM-SECURE-SALT-STRING-HERE"):
            logger.warning(
                "IP hash salt is unchanged or empty! Security risk "
                "— please update the salt in config.yaml."
            )

        if algorithm not in self._SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported hash algorithm: '{algorithm}'. "
                f"Supported algorithms: {self._SUPPORTED_ALGORITHMS}"
            )

        self._salt: bytes = salt.encode("utf-8")
        self._algorithm: str = algorithm

        logger.debug(
            "IPHasher started. Algorithm: %s, Salt length: %d",
            algorithm, len(self._salt),
        )

    def hash_ip(self, ip_str: str) -> str:
        """
        Anonymizes an IP address using HMAC + hash.

        HMAC usage is more secure than simple hash+salt
        (prevents length extension attacks).

        Args:
            ip_str: IP address to hash (plain text).

        Returns:
            Hex formatted hash string (e.g. "a3f2b8..." 64 characters).
        """
        if not self._enabled:
            return ip_str.strip()
            
        ip_bytes = ip_str.strip().encode("utf-8")
        digest = hmac.new(self._salt, ip_bytes, self._algorithm).hexdigest()
        return digest

    def verify_ip(self, ip_str: str, expected_hash: str) -> bool:
        """
        Verifies if an IP matches a known hash.

        Uses hmac.compare_digest to prevent timing attacks.

        Args:
            ip_str:        IP address to verify.
            expected_hash: Expected hash value.

        Returns:
            True if the hashes match.
        """
        if not self._enabled:
            return ip_str.strip() == expected_hash.strip()
            
        computed = self.hash_ip(ip_str)
        return hmac.compare_digest(computed, expected_hash)

    @classmethod
    def from_config(cls, config) -> IPHasher:
        """
        Creates an IPHasher instance based on configuration.

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
