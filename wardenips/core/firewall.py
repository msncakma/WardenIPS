"""
WardenIPS - Async Firewall Module (ipset)
=====================================================

Blocks IP addresses with high performance using ipset + iptables.
Standart iptables'a tek tek kural eklemek yerine ipset hash tablosu
kullanir — binlerce IP banlansa bile sunucu yuku artmaz.

Mimari:
  1. 'warden_blacklist' adinda bir ipset seti olusturulur
  2. iptables'a bu sete yonlendiren tek bir DROP kurali eklenir
  3. Ban islemi: ipset'e IP eklenir (timeout ile)
  4. Unban islemi: ipset'ten IP cikarilir

NOT: Bu modeul root (sudo) yetkisi gerektirir.
     Windows'ta simulation modeunda calisir (komutlar loglanir ama calistirilmaz).
"""

from __future__ import annotations

import asyncio
import platform
import shutil
from typing import Optional

from wardenips.core.exceptions import WardenFirewallError
from wardenips.core.logger import get_logger

logger = get_logger(__name__)


class FirewallManager:
    """
    Asenkron ipset tabanli guvenlik duvari yoneticisi.

    ipset hash:ip seti olusturur, IP ekler/cikarir.
    iptables ile DROP kurali iliskilendirir.

    Ozellikler:
        - ipset hash:ip: O(1) lookup — binlerce IP yuku artirmaz
        - Otomatik timeout: Belirtilen sureden sonra ban kalkar
        - Whitelist korumasi: Banlama oncesi whitelist kontrolu yapilir
        - Simulation modeu: Root degilse veya Windows'ta gerçek komut calistirmaz

    Usage:
        fw = await FirewallManager.create(config, whitelist_manager)
        await fw.ban_ip("203.0.113.50", duration=3600, reason="Brute-force")
        await fw.unban_ip("203.0.113.50")
        await fw.shutdown()
    """

    def __init__(self) -> None:
        self._set_name: str = "warden_blacklist"
        self._default_ban_duration: int = 3600
        self._simulation_mode: bool = False
        self._whitelist = None
        self._initialized: bool = False

    # ── Factory ──

    @classmethod
    async def create(cls, config, whitelist_manager=None) -> FirewallManager:
        """
        FirewallManager olusturur ve ipset setini hazirlar.

        Args:
            config:            ConfigManager instance.
            whitelist_manager: WhitelistManager instance (ban oncesi kontrol icin).

        Returns:
            Hazir FirewallManager.
        """
        instance = cls()
        instance._whitelist = whitelist_manager
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        """
        ipset setini ve iptables kuralini olusturur.
        """
        fw_section = config.get_section("firewall")
        ipset_section = fw_section.get("ipset", {})
        self._set_name = ipset_section.get("set_name", "warden_blacklist")
        self._default_ban_duration = ipset_section.get(
            "default_ban_duration", 3600
        )

        # Platform ve yetki kontrolu
        is_linux = platform.system() == "Linux"
        
        # Manual path for ipset when run with sudo
        if is_linux:
            import os
            search_path = os.environ.get("PATH", "") + os.pathsep + "/sbin" + os.pathsep + "/usr/sbin"
            has_ipset = shutil.which("ipset", path=search_path) is not None
        else:
            has_ipset = False

        if not is_linux or not has_ipset:
            self._simulation_mode = True
            reason = "Linux degil" if not is_linux else "ipset bulunamadi"
            logger.warning(
                "Guvenlik duvari SIMULASYON modeunda! Reason: %s. "
                "Commands will be logged but not executed.",
                reason,
            )
        else:
            # Root kontrolu
            import os
            if os.geteuid() != 0:
                self._simulation_mode = True
                logger.warning(
                    "Root yetkisi yok — guvenlik duvari SIMULASYON modeunda!"
                )

        # ipset setini olustur
        await self._exec_command(
            "ipset", "create", self._set_name,
            "hash:ip", "timeout", str(self._default_ban_duration),
            "-exist",
        )

        # iptables DROP kuralini ekle (zaten varsa tekrar eklenmez)
        await self._exec_command(
            "iptables", "-C", "INPUT",
            "-m", "set", "--match-set", self._set_name, "src",
            "-j", "DROP",
            ignore_errors=True,  # -C (check) hata donerse kural yok demektir
        )
        # Kural yoksa ekle
        await self._exec_command(
            "iptables", "-I", "INPUT",
            "-m", "set", "--match-set", self._set_name, "src",
            "-j", "DROP",
        )

        self._initialized = True
        logger.info(
            "Firewall started. Set: '%s', "
            "Default ban duration: %ds, Simulation: %s",
            self._set_name, self._default_ban_duration, self._simulation_mode,
        )

    # ── Ana API ──

    async def ban_ip(
        self,
        ip_str: str,
        duration: Optional[int] = None,
        reason: str = "",
    ) -> bool:
        """
        Bir IP adresini banlar (ipset'e ekler).

        Ban oncesi whitelist kontrolu yapar — whitelist'teki IP'ler
        ASLA banlanmaz (yonetici kilidi korumasi).

        Args:
            ip_str:   Banlanacak IP adresi.
            duration: Ban suresi (saniye). None = config varsayilani.
                      0 = kalici (timeout yok).
            reason:   Ban sebebi (loglama icin).

        Returns:
            True ise ban basarili, False ise atlanmis (whitelist vb.)
        """
        # Whitelist korumasi
        if self._whitelist:
            if await self._whitelist.is_whitelisted(ip_str):
                logger.warning(
                    "BAN BLOCKED! IP is in whitelist: %s — "
                    "Admin lock protection active.",
                    ip_str,
                )
                return False

        ban_duration = duration if duration is not None else self._default_ban_duration

        if ban_duration > 0:
            success = await self._exec_command(
                "ipset", "add", self._set_name, ip_str,
                "timeout", str(ban_duration),
                "-exist",
            )
        else:
            # Kalici ban (timeout 0)
            success = await self._exec_command(
                "ipset", "add", self._set_name, ip_str,
                "-exist",
            )

        if success:
            dur_str = f"{ban_duration}s" if ban_duration > 0 else "KALICI"
            logger.info(
                "IP BANNED: %s | Duration: %s | Reason: %s",
                ip_str, dur_str, reason,
            )
        return success

    async def unban_ip(self, ip_str: str) -> bool:
        """
        Bir IP adresinin banini kaldirir (ipset'ten cikarir).

        Args:
            ip_str: Bani kaldirilacak IP adresi.

        Returns:
            True ise basarili.
        """
        success = await self._exec_command(
            "ipset", "del", self._set_name, ip_str,
            "-exist",
        )
        if success:
            logger.info("IP UNBANNED: %s", ip_str)
        return success

    async def is_banned(self, ip_str: str) -> bool:
        """
        Bir IP'nin ipset setinde olup olmadigini kontrol eder.

        Args:
            ip_str: Kontrol edilecek IP.

        Returns:
            True ise IP banli.
        """
        success = await self._exec_command(
            "ipset", "test", self._set_name, ip_str,
            ignore_errors=True,
        )
        return success

    async def flush(self) -> bool:
        """
        Tum banlari kaldirir (ipset setini bosaltir).

        DIKKAT: Tum aktif banlar silinir!

        Returns:
            True ise basarili.
        """
        success = await self._exec_command(
            "ipset", "flush", self._set_name
        )
        if success:
            logger.warning("ALL BANS REMOVED! Set '%s' flushed.", self._set_name)
        return success

    async def get_banned_count(self) -> int:
        """
        Aktif ban sayisini dondurur.

        Returns:
            ipset setindeki eleman sayisi.
        """
        if self._simulation_mode:
            return 0

        try:
            proc = await asyncio.create_subprocess_exec(
                "ipset", "list", self._set_name, "-t",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace")

            for line in output.splitlines():
                if line.strip().startswith("Number of entries:"):
                    return int(line.split(":")[-1].strip())
        except Exception as exc:
            logger.debug("Failed to get ban count: %s", exc)

        return 0

    # ── Shutdown ──

    async def shutdown(self) -> None:
        """
        Guvenlik duvari modeulu kapatilirken cagrilir.
        ipset seti ve iptables kurallari korunur (banlar devam eder).
        """
        logger.info(
            "Guvenlik duvari modeulu kapatiliyor. "
            "Note: ipset set '%s' and rules will be preserved.",
            self._set_name,
        )

    # ── Dahili: Komut Calistirici ──

    async def _exec_command(
        self,
        *args: str,
        ignore_errors: bool = False,
    ) -> bool:
        """
        Bir sistem komutunu asenkron olarak calistirir.

        Simulasyon modeunda komut calistirilmaz, sadece loglanir.

        Args:
            *args:         Komut ve argumanlari.
            ignore_errors: True ise hata durumunda False doner (exception firlatmaz).

        Returns:
            True ise komut basarili.
        """
        cmd_str = " ".join(args)

        if self._simulation_mode:
            logger.debug("[SIMULASYON] %s", cmd_str)
            return True

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode("utf-8", errors="replace").strip()
                if ignore_errors:
                    logger.debug(
                        "Command returned error (ignored): %s — %s",
                        cmd_str, error_msg,
                    )
                    return False
                else:
                    logger.error(
                        "Firewall command error: %s — %s",
                        cmd_str, error_msg,
                    )
                    return False

            return True

        except FileNotFoundError:
            if not ignore_errors:
                logger.error("Command not found: %s", args[0])
            return False
        except Exception as exc:
            if not ignore_errors:
                logger.error("Command execution error: %s — %s", cmd_str, exc)
            return False

    @property
    def simulation_mode(self) -> bool:
        """Simulasyon modeunda mi?"""
        return self._simulation_mode

    def __repr__(self) -> str:
        return (
            f"<FirewallManager "
            f"set='{self._set_name}' "
            f"simulation={self._simulation_mode}>"
        )
