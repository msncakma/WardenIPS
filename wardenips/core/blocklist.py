"""
WardenIPS - GitHub-Based Blocklist Manager
=============================================

Fetches known malicious IP blocklists from a configurable GitHub
repository and loads them into dedicated ipset sets for immediate
kernel-level blocking.

Two ipsets are managed:

  wardenips_first_setup
      Loaded once on first install with a 7-day or 14-day curated
      blocklist.  Automatically destroyed after the chosen period
      elapses to avoid stale false-positives.

  wardenips_active
      Refreshed every 24 hours at a user-configured local time.
      New unique IPs are added additively so historical threats
      remain blocked.

Config (config.yaml):
  blocklist:
    enabled: false
    timezone: "UTC"
    fetch_time: "04:00"
    first_setup:
      mode: "7d"
      url_7d: ""
      url_14d: ""
      installed_at: ""
      completed: false
    daily_url: ""
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Set

from wardenips.core.logger import get_logger

logger = get_logger(__name__)

try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False

try:
    from zoneinfo import ZoneInfo
except ImportError:
    # Python 3.8 fallback
    try:
        from backports.zoneinfo import ZoneInfo
    except ImportError:
        ZoneInfo = None  # type: ignore[misc,assignment]

# Default blocklist URLs (AbuseIPDB curated lists by borestad)
_DEFAULT_URL_7D = (
    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/"
    "main/abuseipdb-s100-7d.ipv4"
)
_DEFAULT_URL_14D = (
    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/"
    "main/abuseipdb-s100-14d.ipv4"
)
_DEFAULT_DAILY_URL = (
    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/"
    "main/abuseipdb-s100-1d.ipv4"
)

# ipset names used by the blocklist subsystem
FIRST_SETUP_SET = "wardenips_first_setup"
FIRST_SETUP_SET_V6 = "wardenips_first_setup_v6"
ACTIVE_SET = "wardenips_active"
ACTIVE_SET_V6 = "wardenips_active_v6"

# Maximum entries per ipset (must be large enough for big blocklists)
_IPSET_MAXELEM = 1_000_000

# Regex for a bare IP line (IPv4 or IPv6); ignores comments / blanks
_IP_LINE_RE = re.compile(
    r"^\s*([0-9a-fA-F.:]+)\s*(?:#.*)?$"
)


class BlocklistManager:
    """
    Manages GitHub-sourced IP blocklists with two-phase protection.

    Phase 1 (first_setup):
        On first run, downloads the chosen period blocklist (7d/14d)
        and bulk-loads it into the ``wardenips_first_setup`` ipset.
        After the period elapses, the set and its iptables rule are
        destroyed to avoid false-positives from stale data.

    Phase 2 (active):
        Every 24 hours at the configured local time, fetches the
        daily blocklist and adds unique IPs to ``wardenips_active``.
    """

    def __init__(self) -> None:
        self._enabled: bool = False
        self._timezone_name: str = "UTC"
        self._fetch_time: str = "04:00"  # HH:MM in 24h format

        # First-setup config
        self._first_setup_mode: str = "7d"
        self._first_setup_url_7d: str = ""
        self._first_setup_url_14d: str = ""
        self._installed_at: Optional[datetime] = None
        self._first_setup_completed: bool = False

        # Daily config
        self._daily_url: str = ""

        # Runtime state
        self._config = None
        self._firewall = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._scheduler_task: Optional[asyncio.Task] = None
        self._first_setup_active: bool = False

        # Stats
        self._total_first_setup_loaded: int = 0
        self._total_active_loaded: int = 0
        self._last_fetch_at: Optional[str] = None
        self._last_fetch_count: int = 0
        self._last_error: Optional[str] = None

    # ── Factory ──

    @classmethod
    async def create(cls, config, firewall) -> BlocklistManager:
        instance = cls()
        instance._config = config
        instance._firewall = firewall
        await instance._initialize(config)
        return instance

    async def _initialize(self, config) -> None:
        section = config.get("blocklist", None)
        if not section or not isinstance(section, dict):
            return

        self._enabled = section.get("enabled", False)
        if not self._enabled:
            return

        if not _AIOHTTP_AVAILABLE:
            logger.warning(
                "Blocklist requires aiohttp but it is not installed. "
                "Disabling blocklist."
            )
            self._enabled = False
            return

        self._timezone_name = section.get("timezone", "UTC")
        self._fetch_time = section.get("fetch_time", "04:00")

        first_setup = section.get("first_setup", {})
        self._first_setup_mode = first_setup.get("mode", "7d")
        self._first_setup_url_7d = first_setup.get("url_7d", "") or _DEFAULT_URL_7D
        self._first_setup_url_14d = first_setup.get("url_14d", "") or _DEFAULT_URL_14D
        self._first_setup_completed = first_setup.get("completed", False)

        installed_at_str = first_setup.get("installed_at", "")
        if installed_at_str:
            try:
                self._installed_at = datetime.fromisoformat(installed_at_str)
                if self._installed_at.tzinfo is None:
                    self._installed_at = self._installed_at.replace(
                        tzinfo=timezone.utc
                    )
            except (ValueError, TypeError):
                self._installed_at = None

        self._daily_url = section.get("daily_url", "") or _DEFAULT_DAILY_URL

    @property
    def enabled(self) -> bool:
        return self._enabled and _AIOHTTP_AVAILABLE

    # ── Lifecycle ──

    async def start(self) -> None:
        """Start blocklist manager: first-setup + daily scheduler."""
        if not self.enabled:
            return

        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=120)
        )

        # Phase 1: First-setup handling
        await self._handle_first_setup()

        # Phase 2: Start daily scheduler
        self._scheduler_task = asyncio.create_task(self._daily_scheduler())

        logger.info(
            "Blocklist manager started — mode=%s, timezone=%s, "
            "fetch_time=%s, first_setup_completed=%s",
            self._first_setup_mode,
            self._timezone_name,
            self._fetch_time,
            self._first_setup_completed,
        )

    async def stop(self) -> None:
        """Stop the scheduler and close HTTP session."""
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass

        if self._session:
            await self._session.close()

        logger.info(
            "Blocklist manager stopped. "
            "First-setup loaded: %d, Active loaded: %d",
            self._total_first_setup_loaded,
            self._total_active_loaded,
        )

    # ── First-Setup Phase ──

    async def _handle_first_setup(self) -> None:
        """Handle the first-setup ipset: create, load, or expire."""
        now = datetime.now(timezone.utc)

        # If first-setup is already completed, check if ipset needs cleanup
        if self._first_setup_completed:
            # Ensure ipset is destroyed if it somehow still exists
            await self._destroy_ipset(FIRST_SETUP_SET)
            await self._destroy_ipset(FIRST_SETUP_SET_V6)
            return

        # Determine the period in days
        period_days = 14 if self._first_setup_mode == "14d" else 7

        # First-ever run: record install time and load blocklist
        if self._installed_at is None:
            self._installed_at = now
            await self._persist_installed_at(now)
            logger.info(
                "First-setup: recording installation time %s, "
                "mode=%s (%d days)",
                now.isoformat(), self._first_setup_mode, period_days,
            )
            await self._load_first_setup_blocklist()
            self._first_setup_active = True
            return

        # Check if the period has expired
        expiry = self._installed_at + timedelta(days=period_days)
        if now >= expiry:
            logger.info(
                "First-setup period expired (installed_at=%s, "
                "period=%dd). Cleaning up ipset '%s'.",
                self._installed_at.isoformat(),
                period_days,
                FIRST_SETUP_SET,
            )
            await self._cleanup_first_setup()
            await self._persist_first_setup_completed()
            return

        # Period still active — make sure ipset + iptables rule exist
        remaining = expiry - now
        logger.info(
            "First-setup still active — %s remaining. "
            "Ensuring ipset '%s' exists.",
            str(remaining).split(".")[0],
            FIRST_SETUP_SET,
        )
        await self._ensure_first_setup_ipset()
        self._first_setup_active = True

    async def _load_first_setup_blocklist(self) -> None:
        """Download and load the chosen period blocklist into ipset."""
        url = (
            self._first_setup_url_7d
            if self._first_setup_mode == "7d"
            else self._first_setup_url_14d
        )
        if not url:
            logger.warning(
                "First-setup URL for mode '%s' is not configured. "
                "Skipping initial blocklist load.",
                self._first_setup_mode,
            )
            return

        ips = await self._fetch_ip_list(url)
        if not ips:
            logger.warning(
                "First-setup: no IPs fetched from %s", url
            )
            return

        # Create ipsets and load
        await self._create_blocklist_ipset(FIRST_SETUP_SET, "inet")
        ipv4, ipv6 = self._split_ip_families(ips)

        if ipv4:
            await self._bulk_load_ips(FIRST_SETUP_SET, ipv4)

        if ipv6 and self._firewall._ipv6_supported:
            await self._create_blocklist_ipset(
                FIRST_SETUP_SET_V6, "inet6"
            )
            await self._bulk_load_ips(FIRST_SETUP_SET_V6, ipv6)

        # Add iptables DROP rules
        await self._ensure_iptables_rule(FIRST_SETUP_SET, ipv6=False)
        if ipv6 and self._firewall._ipv6_supported:
            await self._ensure_iptables_rule(FIRST_SETUP_SET_V6, ipv6=True)

        total = len(ipv4) + len(ipv6)
        self._total_first_setup_loaded = total
        logger.info(
            "First-setup: loaded %d IPs into '%s' "
            "(IPv4: %d, IPv6: %d)",
            total, FIRST_SETUP_SET, len(ipv4), len(ipv6),
        )

    async def _ensure_first_setup_ipset(self) -> None:
        """Make sure the first-setup ipset and iptables rule exist."""
        await self._create_blocklist_ipset(FIRST_SETUP_SET, "inet")
        await self._ensure_iptables_rule(FIRST_SETUP_SET, ipv6=False)
        if self._firewall._ipv6_supported:
            await self._create_blocklist_ipset(
                FIRST_SETUP_SET_V6, "inet6"
            )
            await self._ensure_iptables_rule(
                FIRST_SETUP_SET_V6, ipv6=True
            )

    async def _cleanup_first_setup(self) -> None:
        """Remove the first-setup ipset and its iptables rule."""
        # Remove iptables rules first
        await self._remove_iptables_rule(FIRST_SETUP_SET, ipv6=False)
        if self._firewall._ipv6_supported:
            await self._remove_iptables_rule(
                FIRST_SETUP_SET_V6, ipv6=True
            )
        # Destroy ipsets
        await self._destroy_ipset(FIRST_SETUP_SET)
        await self._destroy_ipset(FIRST_SETUP_SET_V6)
        self._first_setup_active = False
        logger.info("First-setup ipset '%s' cleaned up.", FIRST_SETUP_SET)

    # ── Daily Active Phase ──

    async def _daily_scheduler(self) -> None:
        """Run the daily blocklist fetch at the configured local time."""
        # Perform an initial active fetch on startup
        await self._fetch_and_load_active()

        while True:
            sleep_secs = self._seconds_until_next_fetch()
            logger.debug(
                "Blocklist: next fetch in %d seconds (%.1f hours)",
                sleep_secs, sleep_secs / 3600,
            )
            await asyncio.sleep(sleep_secs)
            await self._fetch_and_load_active()

            # Also check first-setup expiry on each cycle
            if not self._first_setup_completed:
                await self._check_first_setup_expiry()

    async def _fetch_and_load_active(self) -> None:
        """Fetch the daily blocklist and add new IPs to wardenips_active."""
        if not self._daily_url:
            logger.debug(
                "Blocklist daily_url is not configured. "
                "Skipping active fetch."
            )
            return

        ips = await self._fetch_ip_list(self._daily_url)
        if not ips:
            return

        # Ensure ipsets exist
        await self._create_blocklist_ipset(ACTIVE_SET, "inet")
        ipv4, ipv6 = self._split_ip_families(ips)

        if ipv4:
            await self._bulk_load_ips(ACTIVE_SET, ipv4)

        if ipv6 and self._firewall._ipv6_supported:
            await self._create_blocklist_ipset(ACTIVE_SET_V6, "inet6")
            await self._bulk_load_ips(ACTIVE_SET_V6, ipv6)

        # Ensure iptables rules
        await self._ensure_iptables_rule(ACTIVE_SET, ipv6=False)
        if ipv6 and self._firewall._ipv6_supported:
            await self._ensure_iptables_rule(ACTIVE_SET_V6, ipv6=True)

        total = len(ipv4) + len(ipv6)
        self._total_active_loaded += total
        self._last_fetch_at = datetime.now(timezone.utc).isoformat()
        self._last_fetch_count = total
        self._last_error = None

        logger.info(
            "Active blocklist: loaded %d IPs into '%s' "
            "(IPv4: %d, IPv6: %d)",
            total, ACTIVE_SET, len(ipv4), len(ipv6),
        )

    async def _check_first_setup_expiry(self) -> None:
        """Check if the first-setup period has expired and clean up."""
        if self._first_setup_completed or self._installed_at is None:
            return

        period_days = 14 if self._first_setup_mode == "14d" else 7
        expiry = self._installed_at + timedelta(days=period_days)
        now = datetime.now(timezone.utc)

        if now >= expiry:
            logger.info("First-setup period has expired during runtime.")
            await self._cleanup_first_setup()
            await self._persist_first_setup_completed()

    # ── Network: Fetch IP List ──

    async def _fetch_ip_list(self, url: str) -> list[str]:
        """
        Download an IP blocklist from a URL.

        Expects a plain-text file with one IP per line.
        Lines starting with # are treated as comments.
        """
        try:
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    self._last_error = f"HTTP {resp.status} from {url}"
                    logger.warning(
                        "Blocklist fetch failed: %s", self._last_error
                    )
                    return []

                text = await resp.text()
                ips = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = _IP_LINE_RE.match(line)
                    if match:
                        ip_str = match.group(1)
                        if self._is_valid_ip(ip_str):
                            ips.append(ip_str)
                return ips

        except asyncio.TimeoutError:
            self._last_error = f"Timeout fetching {url}"
            logger.warning("Blocklist: %s", self._last_error)
            return []
        except Exception as exc:
            self._last_error = str(exc)
            logger.warning("Blocklist fetch error: %s", exc)
            return []

    # ── ipset Operations ──

    async def _create_blocklist_ipset(
        self, set_name: str, family: str = "inet"
    ) -> None:
        """Create an ipset hash:ip set if it doesn't already exist."""
        args = [
            self._firewall._ipset_cmd,
            "create", set_name, "hash:ip",
            "maxelem", str(_IPSET_MAXELEM),
            "-exist",
        ]
        if family == "inet6":
            args.insert(4, "family")
            args.insert(5, "inet6")
        await self._firewall._exec_command(*args)

    async def _bulk_load_ips(
        self, set_name: str, ips: list[str]
    ) -> None:
        """
        Bulk-load IPs into an ipset using 'ipset restore' for performance.

        This is *much* faster than individual 'ipset add' calls when
        loading thousands of IPs.
        """
        if self._firewall.simulation_mode:
            logger.debug(
                "[SIMULATION] Would bulk-load %d IPs into '%s'",
                len(ips), set_name,
            )
            return

        # Build restore payload: one "add <set> <ip> -exist" per line
        lines = [f"add {set_name} {ip} -exist" for ip in ips]
        payload = "\n".join(lines) + "\n"

        cmd = []
        if self._firewall._use_sudo:
            cmd = [self._firewall._sudo_cmd, "-n"]
        cmd += [self._firewall._ipset_cmd, "restore"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate(
                input=payload.encode("utf-8")
            )
            if proc.returncode != 0:
                err = stderr.decode(errors="replace").strip()
                logger.warning(
                    "ipset restore for '%s' returned %d: %s",
                    set_name, proc.returncode, err,
                )
        except Exception as exc:
            logger.error(
                "Failed to bulk-load IPs into '%s': %s",
                set_name, exc,
            )

    async def _destroy_ipset(self, set_name: str) -> None:
        """Destroy (delete) an ipset set entirely."""
        await self._firewall._exec_command(
            self._firewall._ipset_cmd, "destroy", set_name,
            ignore_errors=True,
        )

    async def _ensure_iptables_rule(
        self, set_name: str, ipv6: bool = False
    ) -> None:
        """Add an iptables DROP rule for the ipset if it doesn't exist."""
        ipt = (
            self._firewall._ip6tables_cmd
            if ipv6
            else self._firewall._iptables_cmd
        )
        # Check if rule already exists
        exists = await self._firewall._exec_command(
            ipt, "-C", "INPUT",
            "-m", "set", "--match-set", set_name, "src",
            "-j", "DROP",
            ignore_errors=True,
        )
        if not exists:
            await self._firewall._exec_command(
                ipt, "-I", "INPUT",
                "-m", "set", "--match-set", set_name, "src",
                "-j", "DROP",
            )

    async def _remove_iptables_rule(
        self, set_name: str, ipv6: bool = False
    ) -> None:
        """Remove the iptables DROP rule for the ipset."""
        ipt = (
            self._firewall._ip6tables_cmd
            if ipv6
            else self._firewall._iptables_cmd
        )
        await self._firewall._exec_command(
            ipt, "-D", "INPUT",
            "-m", "set", "--match-set", set_name, "src",
            "-j", "DROP",
            ignore_errors=True,
        )

    # ── Config Persistence ──

    async def _persist_installed_at(self, dt: datetime) -> None:
        """Write installed_at timestamp to config.yaml."""
        try:
            raw = self._config.raw
            blocklist = raw.setdefault("blocklist", {})
            first_setup = blocklist.setdefault("first_setup", {})
            first_setup["installed_at"] = dt.isoformat()
            await self._config.save(raw)
        except Exception as exc:
            logger.warning(
                "Could not persist installed_at to config: %s", exc
            )

    async def _persist_first_setup_completed(self) -> None:
        """Mark first_setup as completed in config.yaml."""
        self._first_setup_completed = True
        try:
            raw = self._config.raw
            blocklist = raw.setdefault("blocklist", {})
            first_setup = blocklist.setdefault("first_setup", {})
            first_setup["completed"] = True
            await self._config.save(raw)
        except Exception as exc:
            logger.warning(
                "Could not persist first_setup.completed to config: %s",
                exc,
            )

    # ── Scheduling ──

    def _seconds_until_next_fetch(self) -> int:
        """
        Calculate seconds until the next scheduled fetch time
        in the user's configured timezone.
        """
        tz = self._resolve_timezone()
        now = datetime.now(tz)

        # Parse fetch_time "HH:MM"
        try:
            parts = self._fetch_time.split(":")
            target_hour = int(parts[0])
            target_minute = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            target_hour, target_minute = 4, 0

        target = now.replace(
            hour=target_hour,
            minute=target_minute,
            second=0,
            microsecond=0,
        )

        # If target time has passed today, schedule for tomorrow
        if target <= now:
            target += timedelta(days=1)

        delta = (target - now).total_seconds()
        return max(int(delta), 60)  # Minimum 60s to avoid tight loops

    def _resolve_timezone(self):
        """Resolve the configured timezone to a tzinfo object."""
        if ZoneInfo is not None:
            try:
                return ZoneInfo(self._timezone_name)
            except (KeyError, Exception):
                logger.warning(
                    "Unknown timezone '%s', falling back to UTC.",
                    self._timezone_name,
                )
                return timezone.utc
        return timezone.utc

    # ── Helpers ──

    @staticmethod
    def _is_valid_ip(ip_str: str) -> bool:
        """Validate an IP address string (IPv4 or IPv6)."""
        try:
            addr = ipaddress.ip_address(ip_str)
            # Reject private/loopback/reserved addresses from blocklists
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return False
            return True
        except ValueError:
            return False

    @staticmethod
    def _split_ip_families(
        ips: list[str],
    ) -> tuple[list[str], list[str]]:
        """Split a list of IPs into IPv4 and IPv6 lists."""
        ipv4 = []
        ipv6 = []
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
                if isinstance(addr, ipaddress.IPv6Address):
                    ipv6.append(ip)
                else:
                    ipv4.append(ip)
            except ValueError:
                continue
        return ipv4, ipv6

    # ── Status API ──

    async def get_status(self) -> dict[str, Any]:
        """Return blocklist status for the dashboard API."""
        period_days = 14 if self._first_setup_mode == "14d" else 7
        first_setup_remaining = None

        if (
            not self._first_setup_completed
            and self._installed_at is not None
        ):
            expiry = self._installed_at + timedelta(days=period_days)
            remaining = expiry - datetime.now(timezone.utc)
            if remaining.total_seconds() > 0:
                first_setup_remaining = str(remaining).split(".")[0]

        return {
            "enabled": self.enabled,
            "mode": "github-blocklist",
            "description": (
                "Fetches curated IP blocklists from a GitHub repository. "
                "Two-phase protection: initial setup blocklist and daily "
                "active updates."
            ),
            "timezone": self._timezone_name,
            "fetch_time": self._fetch_time,
            "first_setup": {
                "mode": self._first_setup_mode,
                "period_days": period_days,
                "completed": self._first_setup_completed,
                "installed_at": (
                    self._installed_at.isoformat()
                    if self._installed_at
                    else None
                ),
                "remaining": first_setup_remaining,
                "ips_loaded": self._total_first_setup_loaded,
            },
            "active": {
                "total_ips_loaded": self._total_active_loaded,
                "last_fetch_at": self._last_fetch_at,
                "last_fetch_count": self._last_fetch_count,
            },
            "last_error": self._last_error,
        }

    def __repr__(self) -> str:
        return (
            f"<BlocklistManager enabled={self._enabled} "
            f"mode={self._first_setup_mode} "
            f"first_setup_completed={self._first_setup_completed} "
            f"active_loaded={self._total_active_loaded}>"
        )
