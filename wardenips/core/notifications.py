"""
WardenIPS - Async Notification Manager (Telegram & Discord)
============================================================

Sends real-time ban/threat notifications via Telegram Bot API
and Discord Webhooks.

Usage:
    notifier = await NotificationManager.create(config)
    await notifier.notify_ban("203.0.113.50", reason="Brute-force", risk=85)
    await notifier.close()
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Optional

from wardenips import __author__, __version__
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False


class NotificationManager:
    """
    Asynchronous notification dispatcher for Telegram and Discord.

    Respects per-channel rate limits to avoid API throttling.
    Falls back gracefully when aiohttp is unavailable or channels
    are not configured.
    """

    def __init__(self) -> None:
        self._telegram_enabled: bool = False
        self._telegram_token: str = ""
        self._telegram_chat_id: str = ""
        self._discord_enabled: bool = False
        self._discord_webhook_url: str = ""
        self._session: Optional[aiohttp.ClientSession] = None
        # Simple rate limiting: max 20 notifications per minute
        self._rate_limit: int = 20
        self._send_times: deque = deque()
        self._lock: asyncio.Lock = asyncio.Lock()
        self._total_sent: int = 0
        self._total_failed: int = 0

    @classmethod
    async def create(cls, config) -> NotificationManager:
        instance = cls()
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        notif_section = config.get_section("notifications") if config.get("notifications", None) else {}
        if not notif_section:
            logger.debug("No 'notifications' section in config — notifications disabled.")
            return

        # Telegram
        tg = notif_section.get("telegram", {})
        if tg.get("enabled", False):
            self._telegram_token = tg.get("bot_token", "")
            self._telegram_chat_id = str(tg.get("chat_id", ""))
            if self._telegram_token and self._telegram_chat_id:
                self._telegram_enabled = True
                logger.info("Telegram notifications enabled.")
            else:
                logger.warning(
                    "Telegram enabled but bot_token or chat_id missing."
                )

        # Discord
        dc = notif_section.get("discord", {})
        if dc.get("enabled", False):
            self._discord_webhook_url = dc.get("webhook_url", "")
            if self._discord_webhook_url:
                self._discord_enabled = True
                logger.info("Discord notifications enabled.")
            else:
                logger.warning(
                    "Discord enabled but webhook_url missing."
                )

        self._rate_limit = notif_section.get("rate_limit_per_minute", 20)

        if (self._telegram_enabled or self._discord_enabled) and _AIOHTTP_AVAILABLE:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )

    @property
    def enabled(self) -> bool:
        return self._telegram_enabled or self._discord_enabled

    def _rate_limited(self) -> bool:
        """Returns True if we've exceeded rate limit."""
        now = time.monotonic()
        # Prune entries older than 60 seconds
        while self._send_times and self._send_times[0] < now - 60:
            self._send_times.popleft()
        return len(self._send_times) >= self._rate_limit

    async def notify_ban(
        self,
        ip: str,
        reason: str = "",
        risk: int = 0,
        duration: int = 0,
        plugin: str = "",
    ) -> None:
        """Send a ban notification to all configured channels."""
        if not self.enabled or not _AIOHTTP_AVAILABLE or not self._session:
            return

        if self._rate_limited():
            logger.debug("Notification rate limit reached, skipping.")
            return

        dur_str = f"{duration}s" if duration > 0 else "permanent"
        title = f"🚨 WardenIPS v{__version__} — IP Banned"
        body = (
            f"**IP:** `{ip}`\n"
            f"**Risk Score:** {risk}\n"
            f"**Duration:** {dur_str}\n"
            f"**Plugin:** {plugin}\n"
            f"**Reason:** {reason}\n"
            f"**Version:** v{__version__} ({__author__})"
        )

        tasks = []
        if self._telegram_enabled:
            tasks.append(self._send_telegram(title, body))
        if self._discord_enabled:
            tasks.append(self._send_discord(title, body))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.debug("Notification send error: %s", r)

    async def notify_burst(
        self,
        ip: str,
        event_count: int,
        window: int,
        plugin: str = "",
    ) -> None:
        """Send a burst-detection notification."""
        if not self.enabled or not _AIOHTTP_AVAILABLE or not self._session:
            return

        if self._rate_limited():
            return

        title = f"⚡ WardenIPS v{__version__} — Burst Flood Detected"
        body = (
            f"**IP:** `{ip}`\n"
            f"**Events:** {event_count} in {window}s\n"
            f"**Plugin:** {plugin}\n"
            f"Auto-banned immediately.\n"
            f"**Version:** v{__version__} ({__author__})"
        )

        tasks = []
        if self._telegram_enabled:
            tasks.append(self._send_telegram(title, body))
        if self._discord_enabled:
            tasks.append(self._send_discord(title, body))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def send_test_notification(self, channel: str = "all") -> dict[str, object]:
        """Send an operator-triggered test notification to one or more channels."""
        requested = str(channel or "all").strip().lower()
        if requested not in {"all", "telegram", "discord"}:
            raise ValueError("Unsupported notification channel.")

        if not _AIOHTTP_AVAILABLE or not self._session:
            raise RuntimeError("Notification transport is unavailable.")

        title = f"🧪 WardenIPS v{__version__} — Test Notification"
        body = (
            "**Trigger:** Admin dashboard manual test\n"
            "**Purpose:** Validate notification delivery and channel credentials\n"
            f"**Version:** v{__version__} ({__author__})"
        )

        results: dict[str, str] = {}
        targets: list[tuple[str, object, bool]] = []
        if requested in {"all", "telegram"}:
            targets.append(("telegram", self._send_telegram, self._telegram_enabled))
        if requested in {"all", "discord"}:
            targets.append(("discord", self._send_discord, self._discord_enabled))

        any_enabled = False
        for name, sender, enabled in targets:
            if not enabled:
                results[name] = "disabled"
                continue
            any_enabled = True
            sent = await sender(title, body)
            results[name] = "sent" if sent else "failed"

        if not any_enabled:
            raise RuntimeError("No matching notification channels are enabled.")

        return {"requested": requested, "results": results}

    # ── Telegram ──

    async def _send_telegram(self, title: str, body: str) -> bool:
        """Send a message via Telegram Bot API."""
        # Telegram uses HTML or Markdown — we'll use MarkdownV2 with fallback
        # to plain text if escaping is an issue.  For simplicity, use HTML.
        text = f"<b>{_escape_html(title)}</b>\n\n{_md_to_html(body)}"
        url = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
        payload = {
            "chat_id": self._telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        async with self._lock:
            try:
                async with self._session.post(url, json=payload) as resp:
                    self._send_times.append(time.monotonic())
                    if resp.status == 200:
                        self._total_sent += 1
                        return True
                    else:
                        self._total_failed += 1
                        body_text = await resp.text()
                        logger.warning(
                            "Telegram API error %d: %s",
                            resp.status, body_text[:200],
                        )
                        return False
            except Exception as exc:
                self._total_failed += 1
                logger.debug("Telegram send failed: %s", exc)
                return False

    # ── Discord ──

    async def _send_discord(self, title: str, body: str) -> bool:
        """Send a message via Discord Webhook."""
        # Discord Webhook accepts embeds or content
        embed = {
            "title": title,
            "description": body,
            "color": 0xFF4444,  # red
            "footer": {"text": f"WardenIPS v{__version__} • {__author__}"},
        }
        payload = {"embeds": [embed]}

        async with self._lock:
            try:
                async with self._session.post(
                    self._discord_webhook_url, json=payload
                ) as resp:
                    self._send_times.append(time.monotonic())
                    if resp.status in (200, 204):
                        self._total_sent += 1
                        return True
                    else:
                        self._total_failed += 1
                        body_text = await resp.text()
                        logger.warning(
                            "Discord webhook error %d: %s",
                            resp.status, body_text[:200],
                        )
                        return False
            except Exception as exc:
                self._total_failed += 1
                logger.debug("Discord send failed: %s", exc)
                return False

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    def __repr__(self) -> str:
        channels = []
        if self._telegram_enabled:
            channels.append("Telegram")
        if self._discord_enabled:
            channels.append("Discord")
        return (
            f"<NotificationManager channels={channels or 'none'} "
            f"sent={self._total_sent} failed={self._total_failed}>"
        )


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_to_html(text: str) -> str:
    """Minimal Markdown → HTML conversion for Telegram messages."""
    import re
    # Escape raw content first so user-controlled values cannot break HTML parse.
    text = _escape_html(text)
    # **bold** → <b>bold</b>
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    # `code` → <code>code</code>
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    return text
