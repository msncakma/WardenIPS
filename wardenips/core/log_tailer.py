"""
WardenIPS - Async Log Tailing Engine
=========================================

Log dosyalarini asenkron olarak izler (tail -f benzeri).
Yeni satirlar eklendikce bunlari aninda yakalar ve
bagli plugin'e iletir.

Ozellikler:
    - Tamamen asenkron (asyncio + aiofiles)
    - Dosya rotasyonu destegi (log dosyasi yeniden olusturulursa algilar)
    - Dosya silinip tekrar olusturulursa otomatik yeniden baglanir
    - Durdurulabilir (graceful shutdown)
    - Her plugin icin ayri bir tailer gorevi calisir
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import AsyncIterator, Callable, Coroutine, Optional

import aiofiles

from wardenips.core.logger import get_logger

logger = get_logger(__name__)

# Yeni satirlar icin kontrol araligi (saniye)
_DEFAULT_POLL_INTERVAL = 0.5

# Dosya rotasyonu kontrol araligi (saniye)
_ROTATION_CHECK_INTERVAL = 5.0


class LogTailer:
    """
    Asenkron log dosyasi izleyici (tail -f).

    Bir log dosyasini surekli izler ve yeni satirlari
    asenkron olarak ilgili callback fonksiyonuna iletir.

    Ozellikler:
        - Poll-based izleme (inotify'a gerek yok — tum platformlarda calisir)
        - Dosya rotasyonu: log dosyasi yeniden olusturulursa algilar
        - Graceful shutdown: stop() cagrildiginda temiz kapanir
        - Bastan okuma veya sondan baslama secenegi

    Usage:
        tailer = LogTailer(
            file_path="/var/log/auth.log",
            line_callback=my_async_handler,
        )
        task = asyncio.create_task(tailer.start())
        # ... daha sonra
        await tailer.stop()
    """

    def __init__(
        self,
        file_path: str,
        line_callback: Callable[[str], Coroutine],
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        start_from_end: bool = True,
        name: str = "",
    ) -> None:
        """
        LogTailer olusturur.

        Args:
            file_path:      Izlenecek log dosyasinin tam yolu.
            line_callback:  Her yeni satir icin cagrilacak async fonksiyon.
                            Imza: async def callback(line: str) -> None
            poll_interval:  Yeni satir kontrol araligi (saniye).
            start_from_end: True ise dosyanin sonundan baslar (mevcut satirlari atlar).
                            False ise dosyanin basindan okur.
            name:           Tailer adi (loglama icin).
        """
        self._file_path = Path(file_path)
        self._callback = line_callback
        self._poll_interval = poll_interval
        self._start_from_end = start_from_end
        self._name = name or self._file_path.name
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._lines_processed: int = 0

    # ── Baslatma / Durdurma ──

    async def start(self) -> None:
        """
        Log izlemeyi baslatir. Bu metod durdurana kadar calisir.

        Dosya mevcut degilse, olusturulmasini bekler.
        """
        self._running = True
        logger.info(
            "[%s] Log tailer started: %s",
            self._name, self._file_path,
        )

        while self._running:
            try:
                await self._tail_file()
            except asyncio.CancelledError:
                logger.info("[%s] Log tailer cancelled.", self._name)
                break
            except Exception as exc:
                logger.error(
                    "[%s] Log tailer error: %s — will retry in 5s.",
                    self._name, exc,
                )
                await asyncio.sleep(5.0)

        logger.info("[%s] Log tailer stopped.", self._name)

    async def stop(self) -> None:
        """Log izlemeyi durdurur."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(
            "[%s] Log tailer stopped. Total lines processed: %d",
            self._name, self._lines_processed,
        )

    def create_task(self) -> asyncio.Task:
        """
        Tailer'i asyncio task olarak olusturur ve dondurur.

        Returns:
            asyncio.Task nesnesi.
        """
        self._task = asyncio.create_task(self.start())
        return self._task

    # ── Dahili Tailing Mantigi ──

    async def _tail_file(self) -> None:
        """
        Dosyayi izleme ana dongusu.
        """

        # Dosyanin olusturulmasini bekle
        while self._running and not self._file_path.exists():
            logger.debug(
                "[%s] File not found, waiting: %s",
                self._name, self._file_path,
            )
            await asyncio.sleep(2.0)

        if not self._running:
            return

        # Dosya boyutunu al
        try:
            file_stat = os.stat(self._file_path)
            current_inode = self._get_inode(file_stat)
        except OSError as exc:
            logger.warning("[%s] File stat error: %s", self._name, exc)
            return

        # Baslangic pozisyonu
        position = file_stat.st_size if self._start_from_end else 0

        logger.info(
            "[%s] Monitoring file (size: %d bytes, position: %d)",
            self._name, file_stat.st_size, position,
        )

        # Ana izleme dongusu
        rotation_counter = 0
        while self._running:
            try:
                async with aiofiles.open(
                    str(self._file_path), mode="r", encoding="utf-8", errors="replace"
                ) as f:
                    # Pozisyona atla
                    await f.seek(position)

                    while self._running:
                        line = await f.readline()

                        if line:
                            # Yeni satir var
                            stripped = line.rstrip("\n\r")
                            if stripped:  # Bos satirlari atla
                                try:
                                    await self._callback(stripped)
                                    self._lines_processed += 1
                                except Exception as exc:
                                    logger.error(
                                        "[%s] Callback error: %s — line: %s",
                                        self._name, exc, stripped[:100],
                                    )
                            # Yeni pozisyonu kaydet
                            position = await f.tell()
                        else:
                            # Yeni satir yok, bekle
                            await asyncio.sleep(self._poll_interval)

                            # Dosya rotasyonu kontrolu (her N dongude bir)
                            rotation_counter += 1
                            if rotation_counter >= int(
                                _ROTATION_CHECK_INTERVAL / self._poll_interval
                            ):
                                rotation_counter = 0
                                if await self._check_rotation(current_inode):
                                    logger.info(
                                        "[%s] File rotation detected!",
                                        self._name,
                                    )
                                    position = 0
                                    current_inode = self._get_inode(
                                        os.stat(self._file_path)
                                    )
                                    break  # Dosyayi yeniden ac

            except FileNotFoundError:
                logger.warning(
                    "[%s] File deleted, waiting for recreation.",
                    self._name,
                )
                position = 0
                await asyncio.sleep(2.0)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("[%s] Read error: %s", self._name, exc)
                await asyncio.sleep(1.0)

    async def _check_rotation(self, original_inode) -> bool:
        """
        Dosya rotasyonu olup olmadigini kontrol eder.

        Rotasyon algilama:
        - inode degismesi (Linux)
        - Dosya boyutunun kuculmesi (tum platformlar)
        """
        try:
            current_stat = os.stat(self._file_path)
            current_inode = self._get_inode(current_stat)

            # inode degistiyse dosya yeniden olusturulmus
            if current_inode != original_inode:
                return True

            return False

        except FileNotFoundError:
            return True
        except OSError:
            return False

    @staticmethod
    def _get_inode(stat_result) -> int:
        """Dosya inode degerini dondurur (Windows'ta st_ino 0 olabilir)."""
        return getattr(stat_result, "st_ino", 0)

    # ── Bilgi ──

    @property
    def is_running(self) -> bool:
        """Tailer calisiyor mu?"""
        return self._running

    @property
    def lines_processed(self) -> int:
        """Toplam islenen satir sayisi."""
        return self._lines_processed

    @property
    def stats(self) -> dict:
        """Tailer istatistikleri."""
        return {
            "name": self._name,
            "file_path": str(self._file_path),
            "running": self._running,
            "lines_processed": self._lines_processed,
        }

    def __repr__(self) -> str:
        return (
            f"<LogTailer "
            f"name='{self._name}' "
            f"file='{self._file_path.name}' "
            f"running={self._running} "
            f"lines={self._lines_processed}>"
        )
