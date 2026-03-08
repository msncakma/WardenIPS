"""
WardenIPS - BasePlugin Abstract Class
======================================

Tum WardenIPS pluginleri bu soyut siniftan turetilir.
SSH, Minecraft, Nginx vb. her servis icin ayri bir plugin yazilir.

Plugin sorumluluklari:
    1. Log satirini regex ile ayristirmak (parse)
    2. ConnectionEvent olusturmak
    3. Calculate risk scoremak
    4. Aksiyon onermek (ban, rapor, vb.)

Yeni plugin ekleme:
    1. BasePlugin'den turet
    2. parse_line() metodunu implement et
    3. config.yaml'a plugin bolumu ekle
    4. PluginManager'a kaydet
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, List, Optional

from wardenips.core.logger import get_logger
from wardenips.core.modeels import ConnectionEvent

if TYPE_CHECKING:
    from wardenips.core.config import ConfigManager

logger = get_logger(__name__)


class BasePlugin(abc.ABC):
    """
    WardenIPS plugin soyut temel sinifi.

    Tum pluginler bu siniftan turetilmeli ve
    soyut metodlari implement etmelidir.

    Ornek:
        class SSHPlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "SSH"

            @property
            def log_file_path(self) -> str:
                return self._config.get("plugins.ssh.log_path", "/var/log/auth.log")

            async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
                # regex ile auth.log satirini ayristir
                ...

            async def calculate_risk(self, event, context) -> int:
                # risk skoru hesapla
                ...
    """

    def __init__(self, config: ConfigManager) -> None:
        """
        Plugin'i yapilandirir.

        Args:
            config: ConfigManager instance.
        """
        self._config = config
        self._enabled: bool = True
        self._lines_processed: int = 0
        self._events_generated: int = 0
        self._logger = get_logger(f"plugin.{self.name.lower()}")

    # ══════════════════════════════════════════════════════════
    #  SOYUT METODLAR (Her plugin BUNLARI implement ETMELI)
    # ══════════════════════════════════════════════════════════

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Plugin adi (benzersiz olmali).

        Returns:
            Plugin adi string (orn: "SSH", "Minecraft", "Nginx").
        """
        ...

    @property
    @abc.abstractmethod
    def log_file_path(self) -> str:
        """
        Izlenecek log dosyasinin yolu.

        Returns:
            Log dosyasi tam yolu.
        """
        ...

    @abc.abstractmethod
    async def parse_line(self, line: str) -> Optional[ConnectionEvent]:
        """
        Bir log satirini ayristirir ve ConnectionEvent olusturur.

        Bu metod her yeni log satiri icin cagrilir.
        Satir plugin ile ilgili degilse None dondurmelidir.

        Args:
            line: Ham log satiri.

        Returns:
            ConnectionEvent nesnesi veya None (ilgisiz satir).
        """
        ...

    @abc.abstractmethod
    async def calculate_risk(
        self,
        event: ConnectionEvent,
        context: dict,
    ) -> int:
        """
        Bir events icin risk skoru hesaplar (0-100).

        Context, gecmis eventslar ve ASN bilgisi gibi
        ek verileri iceren sozluktur.

        Args:
            event:   Ayristirilmis ConnectionEvent.
            context: Ek analiz verileri:
                     - "recent_events": Son N dakikadaki eventslar
                     - "event_count": Olay sayisi
                     - "asn_result": ASN lookup sonucu
                     - "is_datacenter": Datacenter IP'si mi?

        Returns:
            0-100 arasi risk skoru.
        """
        ...

    # ══════════════════════════════════════════════════════════
    #  OPSIYONEL METODLAR (Override edilebilir)
    # ══════════════════════════════════════════════════════════

    async def on_start(self) -> None:
        """
        Plugin baslatildiginda cagrilir.
        Override ederek ozel baslangic islemi yapilabilir.
        """
        self._logger.info("Plugin started: %s", self.name)

    async def on_stop(self) -> None:
        """
        Plugin durduruldugunda cagrilir.
        Override ederek ozel temizlik islemi yapilabilir.
        """
        self._logger.info(
            "Plugin stopped: %s — Processed: %d satir, %d events",
            self.name, self._lines_processed, self._events_generated,
        )

    async def on_event(self, event: ConnectionEvent) -> None:
        """
        Basarili parse sonrasi events isleme hook'u.
        Override ederek ek islem yapilabilir (orn: metrik toplama).

        Args:
            event: Olusan ConnectionEvent.
        """
        pass

    def get_action_recommendation(self, risk_score: int) -> str:
        """
        Risk skoruna gore aksiyon onerisi dondurur.

        Args:
            risk_score: Hesaplanan risk skoru (0-100).

        Returns:
            Aksiyon onerisi string.
        """
        ban_threshold = self._config.get("firewall.ban_threshold", 70)

        if risk_score >= ban_threshold:
            return "BAN"
        elif risk_score >= 40:
            return "WATCH"
        elif risk_score >= 10:
            return "LOG"
        else:
            return "IGNORE"

    # ══════════════════════════════════════════════════════════
    #  LOG TAILER CALLBACK (Otomatik olarak baglanir)
    # ══════════════════════════════════════════════════════════

    async def handle_line(self, line: str) -> Optional[ConnectionEvent]:
        """
        LogTailer tarafindan her yeni satir icin cagrilan callback.

        Bu metod:
        1. parse_line() ile satiri ayristirir
        2. Basarili parse'ta on_event() hook'unu calistirir
        3. Istatistikleri gunceller

        Args:
            line: Ham log satiri.

        Returns:
            ConnectionEvent veya None.
        """
        self._lines_processed += 1

        try:
            event = await self.parse_line(line)
            if event is not None:
                self._events_generated += 1
                await self.on_event(event)
                return event
        except Exception as exc:
            self._logger.error(
                "Line parsing error: %s — %s",
                exc, line[:100],
            )

        return None

    # ══════════════════════════════════════════════════════════
    #  BILGI
    # ══════════════════════════════════════════════════════════

    @property
    def is_enabled(self) -> bool:
        """Plugin aktif mi?"""
        return self._enabled

    @is_enabled.setter
    def is_enabled(self, value: bool) -> None:
        self._enabled = value

    @property
    def stats(self) -> dict:
        """Plugin istatistikleri."""
        return {
            "name": self.name,
            "enabled": self._enabled,
            "log_file": self.log_file_path,
            "lines_processed": self._lines_processed,
            "events_generated": self._events_generated,
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"name='{self.name}' "
            f"enabled={self._enabled} "
            f"lines={self._lines_processed} "
            f"events={self._events_generated}>"
        )


class PluginManager:
    """
    Plugin yoneticisi.

    Pluginleri yukleme, baslatma, durdurma ve listeleme islerini yonetir.
    LogTailer ile pluginleri otomatik olarak iliskilendirir.

    Usage:
        manager = PluginManager(config)
        manager.register(SSHPlugin(config))
        manager.register(MinecraftPlugin(config))
        await manager.start_all()
        # ...
        await manager.stop_all()
    """

    def __init__(self, config: ConfigManager) -> None:
        self._config = config
        self._plugins: dict[str, BasePlugin] = {}
        self._logger = get_logger("plugin_manager")

    def register(self, plugin: BasePlugin) -> None:
        """
        Bir plugin'i kaydeder.

        Args:
            plugin: BasePlugin'den turetilmis plugin instance.

        Raises:
            ValueError: Ayni isimde plugin zaten kayitliysa.
        """
        if plugin.name in self._plugins:
            raise ValueError(
                f"Plugin already registered: '{plugin.name}'"
            )

        self._plugins[plugin.name] = plugin
        self._logger.info(
            "Plugin registered: %s (log: %s)",
            plugin.name, plugin.log_file_path,
        )

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Ismine gore plugin dondurur."""
        return self._plugins.get(name)

    @property
    def plugins(self) -> List[BasePlugin]:
        """Kayitli tum pluginlerin listesi."""
        return list(self._plugins.values())

    @property
    def enabled_plugins(self) -> List[BasePlugin]:
        """Sadece aktif pluginlerin listesi."""
        return [p for p in self._plugins.values() if p.is_enabled]

    async def start_all(self) -> None:
        """Tum aktif pluginleri baslatir."""
        for plugin in self.enabled_plugins:
            try:
                await plugin.on_start()
            except Exception as exc:
                self._logger.error(
                    "Plugin start error (%s): %s",
                    plugin.name, exc,
                )

    async def stop_all(self) -> None:
        """Tum pluginleri durdurur."""
        for plugin in self._plugins.values():
            try:
                await plugin.on_stop()
            except Exception as exc:
                self._logger.error(
                    "Plugin stop error (%s): %s",
                    plugin.name, exc,
                )

    @property
    def stats(self) -> dict:
        """Tum plugin istatistikleri."""
        return {
            "total_plugins": len(self._plugins),
            "enabled_plugins": len(self.enabled_plugins),
            "plugins": {
                name: p.stats for name, p in self._plugins.items()
            },
        }

    def __repr__(self) -> str:
        return (
            f"<PluginManager "
            f"plugins={len(self._plugins)} "
            f"enabled={len(self.enabled_plugins)}>"
        )
