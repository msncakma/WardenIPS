"""
WardenIPS - Merkezi Logging Yapılandırması
============================================

Tüm modeüller tarafından kullanılan async-safe loglama altyapısı.
Hem konsola hem dosyaya eşzamanlı yazar.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional


# Özel log formatı — tarih, modeül adı, seviye ve mesaj
_LOG_FORMAT = (
    "%(asctime)s | %(name)-25s | %(levelname)-8s | %(message)s"
)
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Ana logger adı — tüm alt modeüller 'wardenips.xxx' olarak çıkar
_ROOT_LOGGER_NAME = "wardenips"

# Modül seviyesinde tekil logger referansı
_configured: bool = False


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    WardenIPS loglama sistemini yapılandırır.

    Bu fonksiyon uygulama ömründe yalnızca bir kez çağrılmalıdır.
    Sonraki çağrılar mevcut yapılandırmayı döndürür.

    Args:
        level:    Log seviyesi (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Log dosyasının tam yolu. None ise sadece konsola yazar.

    Returns:
        Yapılandırılmış kök logger nesnesi.
    """
    global _configured

    logger = logging.getLogger(_ROOT_LOGGER_NAME)

    # Tekrar yapılandırmayı engelle
    if _configured:
        return logger

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    import colorama
    colorama.init(autoreset=True)

    class ColoredFormatter(logging.Formatter):
        """Custom formatter for colored console output."""
        COLORS = {
            'DEBUG': colorama.Fore.CYAN,
            'INFO': colorama.Fore.GREEN,
            'WARNING': colorama.Fore.YELLOW,
            'ERROR': colorama.Fore.RED,
            'CRITICAL': colorama.Fore.RED + colorama.Style.BRIGHT,
        }

        def format(self, record):
            log_color = self.COLORS.get(record.levelname, colorama.Fore.WHITE)
            
            # Colorize the levelname
            levelname_color = f"{log_color}{record.levelname:<8}{colorama.Style.RESET_ALL}"
            
            # Format the original string but replace the levelname with the colored one
            # and colorize the whole message slightly based on severity
            
            # We want to format the timestamp and module name properly
            asctime = self.formatTime(record, self.datefmt)
            name = f"{record.name:<25}"
            
            msg = record.getMessage()
            if record.levelname in ["ERROR", "CRITICAL"]:
                msg = f"{log_color}{msg}{colorama.Style.RESET_ALL}"
            elif record.levelname == "WARNING":
                msg = f"{colorama.Fore.LIGHTYELLOW_EX}{msg}{colorama.Style.RESET_ALL}"
            else:
                msg = f"{colorama.Style.DIM}{msg}{colorama.Style.RESET_ALL}"

            return f"{colorama.Fore.LIGHTBLACK_EX}{asctime}{colorama.Style.RESET_ALL} | {colorama.Fore.LIGHTBLUE_EX}{name}{colorama.Style.RESET_ALL} | {levelname_color} | {msg}"

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT)
    colored_formatter = ColoredFormatter(datefmt=_LOG_DATE_FORMAT)

    # ── Konsol Handler ──
    # Windows'ta cp1252 console encoding sorunu için UTF-8 stream kullanıyoruz
    import io
    utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    console_handler = logging.StreamHandler(utf8_stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(colored_formatter)
    logger.addHandler(console_handler)

    # ── Dosya Handler ──
    if log_file:
        log_path = Path(log_file)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(
                str(log_path), encoding="utf-8"
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except PermissionError:
            logger.warning(
                "Log dosyasına yazılamıyor (izin hatası): %s — "
                "Sadece konsola yazılacak.",
                log_file,
            )
        except OSError as exc:
            logger.warning(
                "Log dosyası oluşturulamadı: %s — %s",
                log_file,
                exc,
            )

    _configured = True
    logger.info("WardenIPS Logging sistemi başlatıldı. Seviye: %s", level)
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Alt modeüller için child logger döndürür.

    Kullanım:
        from wardenips.core.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Mesaj")

    Args:
        name: Modül adı (__name__ kullanılması önerilir).

    Returns:
        'wardenips' altında isimlendirilmiş logger.
    """
    if name.startswith(_ROOT_LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")
