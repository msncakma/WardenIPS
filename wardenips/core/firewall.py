"""
WardenIPS - Async Firewall Module (ipset)
=====================================================

Blocks IP addresses with high performance using ipset + iptables.
Standard iptables rules are added to the set — even if there are
thousands of IP bans, the server load remains low.

Architecture:
  # 1. Initialize the ipset for blacklisted IPs
  # 2. Add a single iptables rule to DROP traffic matching the 'warden_blacklist' set
  # 3. Ban: Add IP to the set with an automated timeout
  # 4. Unban: Explicitly remove IP or let it expire
  NOT: This module requires root (sudo) permissions.
     Windows runs in simulation mode (commands are logged but not executed).
"""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import shutil
from typing import Optional

from wardenips.core.exceptions import WardenFirewallError
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

_IPSET_MAX_TIMEOUT_SECONDS = 2_147_483


class FirewallManager:
    """
    Asynchronous ipset-based firewall manager.

    Creates an 'ipset hash:ip' set, manages IP addition/removal, 
    and links a single 'iptables' DROP rule to the set.

    Features:
    - ipset hash:ip: O(1) lookup — constant performance even with thousands of IPs.
    - Automatic timeout: Ban expires automatically after a specified duration.
    - Whitelist protection: Performs a whitelist check before enforcing a ban.
    - Simulation mode: Skips real command execution if not root or running on Windows.

    Usage:
    fw = await FirewallManager.create(config, whitelist_manager)
    await fw.ban_ip("203.0.113.50", duration=3600, reason="Brute-force")
    await fw.unban_ip("203.0.113.50")
    await fw.shutdown()
    """

    def __init__(self) -> None:
        self._set_name: str = "warden_blacklist"
        self._set_name_v6: str = "warden_blacklist_v6"
        self._default_ban_duration: int = 3600
        self._simulation_mode: bool = False
        self._forced_simulation: bool = False
        self._whitelist = None
        self._initialized: bool = False
        # Resolved absolute paths for ipset/iptables/ip6tables so they work
        # regardless of whether /usr/sbin is in the current user's PATH
        # (common on Debian when running without sudo).
        self._ipset_cmd: str = "ipset"
        self._iptables_cmd: str = "iptables"
        self._ip6tables_cmd: str = "ip6tables"
        self._ipv6_supported: bool = False
        # When True, all firewall commands are prefixed with 'sudo -n'.
        # Activated automatically when the process is not root but the user has
        # configured passwordless sudo for ipset/iptables (NOPASSWD in sudoers).
        # In production (daemon via systemd User=root) this stays False.
        self._use_sudo: bool = False
        self._sudo_cmd: str = ""  # resolved once in _initialize
        self._direct_privileged: bool = False
        # In-memory set of currently banned IPs — prevents duplicate ban calls
        # for the same IP (important in simulation mode where ipset -exist has
        # no effect).
        self._banned_ips: set = set()

    # ── Factory ──

    @classmethod
    async def create(cls, config, whitelist_manager=None) -> FirewallManager:
        """
        Creates a FirewallManager instance and initializes the ipset set.

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
        Initializes the ipset set and iptables rule.
        """
        fw_section = config.get_section("firewall")
        self._forced_simulation = bool(fw_section.get("simulation_mode", False))
        ipset_section = fw_section.get("ipset", {})
        self._set_name = ipset_section.get("set_name", "warden_blacklist")
        self._default_ban_duration = ipset_section.get(
            "default_ban_duration", 3600
        )

        # Platform ve yetki kontrolu
        is_linux = platform.system() == "Linux"
        
        # Resolve absolute binary paths — on Debian, /usr/sbin is often absent
        # from a normal user's PATH.  We search the standard sbin locations so
        # the resolved path works both with and without sudo.
        if is_linux:
            import os
            extra = ["/sbin", "/usr/sbin", "/usr/local/sbin"]
            search_path = os.pathsep.join([os.environ.get("PATH", ""), *extra])
            ipset_path = shutil.which("ipset", path=search_path)
            iptables_path = shutil.which("iptables", path=search_path)
            ip6tables_path = shutil.which("ip6tables", path=search_path)
            if ipset_path:
                self._ipset_cmd = ipset_path
            if iptables_path:
                self._iptables_cmd = iptables_path
            if ip6tables_path:
                self._ip6tables_cmd = ip6tables_path
                self._ipv6_supported = True
            has_ipset = ipset_path is not None
            has_iptables = iptables_path is not None
        else:
            has_ipset = False
            has_iptables = False

        if self._forced_simulation:
            self._simulation_mode = True
            logger.warning(
                "Firewall is in SIMULATION mode! Reason: firewall.simulation_mode=true. "
                "Commands will be logged but not executed."
            )
        elif not is_linux or not has_ipset or not has_iptables:
            self._simulation_mode = True
            if not is_linux:
                reason = "Not Linux"
            else:
                missing = [
                    tool
                    for tool, ok in [("ipset", has_ipset), ("iptables", has_iptables)]
                    if not ok
                ]
                reason = f"Missing tools: {', '.join(missing)}"
            logger.warning(
                "Firewall is in SIMULATION mode! Reason: %s. "
                "Commands will be logged but not executed.",
                reason,
            )
        else:
            import os

            if os.geteuid() != 0:
                if await self._probe_direct_privileged():
                    self._direct_privileged = True
                    logger.info(
                        "Not root, but direct firewall access is available "
                        "(likely via Linux capabilities). Running without sudo."
                    )
                else:
                    sudo_path = shutil.which("sudo")
                    if sudo_path and await self._probe_sudo(sudo_path):
                        self._use_sudo = True
                        self._sudo_cmd = sudo_path
                        logger.info(
                            "Not root, but passwordless sudo is available — "
                            "firewall will run via 'sudo -n'. "
                            "(Production tip: use systemd with User=root instead.)"
                        )
                    else:
                        self._simulation_mode = True
                        logger.warning(
                            "Root permissions not found and usable sudo/direct "
                            "privileges are not available — firewall is in "
                            "SIMULATION mode!\n"
                            "  To fix for development/testing, run:\n"
                            "    echo '%s ALL=(root) NOPASSWD: %s, %s' "
                            "| sudo tee /etc/sudoers.d/wardenips",
                            os.environ.get("USER", "YOUR_USER"),
                            self._ipset_cmd,
                            self._iptables_cmd,
                        )

        # ipset setini olustur (IPv4)
        await self._exec_command(
            self._ipset_cmd,
            "create",
            self._set_name,
            "hash:ip",
            "timeout",
            str(self._default_ban_duration),
            "-exist",
        )

        # ipset setini olustur (IPv6) — only if ip6tables is available
        if self._ipv6_supported:
            await self._exec_command(
                self._ipset_cmd,
                "create",
                self._set_name_v6,
                "hash:ip",
                "family",
                "inet6",
                "timeout",
                str(self._default_ban_duration),
                "-exist",
            )

        # iptables DROP kuralini ekle — once kontrol et, duplike olmasini onle.
        rule_exists = await self._exec_command(
            self._iptables_cmd,
            "-C",
            "INPUT",
            "-m",
            "set",
            "--match-set",
            self._set_name,
            "src",
            "-j",
            "DROP",
            ignore_errors=True,
        )
        if not rule_exists:
            await self._exec_command(
                self._iptables_cmd,
                "-I",
                "INPUT",
                "-m",
                "set",
                "--match-set",
                self._set_name,
                "src",
                "-j",
                "DROP",
            )

        # ip6tables DROP rule for IPv6 set
        if self._ipv6_supported:
            rule6_exists = await self._exec_command(
                self._ip6tables_cmd,
                "-C",
                "INPUT",
                "-m",
                "set",
                "--match-set",
                self._set_name_v6,
                "src",
                "-j",
                "DROP",
                ignore_errors=True,
            )
            if not rule6_exists:
                await self._exec_command(
                    self._ip6tables_cmd,
                    "-I",
                    "INPUT",
                    "-m",
                    "set",
                    "--match-set",
                    self._set_name_v6,
                    "src",
                    "-j",
                    "DROP",
                )

        # Populate in-memory ban set from existing ipset entries so that
        # a restart does not lose track of already-banned IPs.
        if not self._simulation_mode:
            await self._load_existing_bans()

        self._initialized = True
        ipv6_str = "enabled" if self._ipv6_supported else "disabled"
        logger.info(
            "Firewall started. Set: '%s', IPv6: %s, "
            "Default ban duration: %ds, Simulation: %s",
            self._set_name,
            ipv6_str,
            self._default_ban_duration,
            self._simulation_mode,
        )

    # ── Helpers ──

    def _is_ipv6(self, ip_str: str) -> bool:
        """Returns True if the given IP string is an IPv6 address."""
        try:
            return isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv6Address)
        except ValueError:
            return False

    def _get_set_for_ip(self, ip_str: str) -> str:
        """Returns the ipset name appropriate for the IP address family."""
        if self._is_ipv6(ip_str) and self._ipv6_supported:
            return self._set_name_v6
        return self._set_name

    # ── Ana API ──

    async def ban_ip(
        self,
        ip_str: str,
        duration: Optional[int] = None,
        reason: str = "",
        force_reapply: bool = False,
    ) -> bool:
        """
        Bans an IP address (adds it to the ipset).

        Performs a whitelist check before banning — IP addresses in the whitelist
        are never banned (admin lock protection).

        Args:
            ip_str:   IP address to ban.
            duration: Ban duration (seconds). None = config default.
                      0 = permanent (no timeout).
            reason:   Ban reason (for logging).

        Returns:
            True if ban was successful, False if skipped (whitelist, etc.)
        """
        # Whitelist protection
        if self._whitelist:
            if await self._whitelist.is_whitelisted(ip_str):
                logger.warning(
                    "BAN BLOCKED! IP is in whitelist: %s — "
                    "Admin lock protection active.",
                    ip_str,
                )
                return False

        # Skip if already banned unless a forced replay was requested.
        # Forced replay is used when applying bans collected during simulation.
        if ip_str in self._banned_ips and not force_reapply:
            return True

        ban_duration = duration if duration is not None else self._default_ban_duration
        if ban_duration > _IPSET_MAX_TIMEOUT_SECONDS:
            logger.warning(
                "Requested ban duration %ss exceeds ipset max timeout %ss; clamping.",
                ban_duration,
                _IPSET_MAX_TIMEOUT_SECONDS,
            )
            ban_duration = _IPSET_MAX_TIMEOUT_SECONDS
        target_set = self._get_set_for_ip(ip_str)

        if ban_duration > 0:
            success = await self._exec_command(
                self._ipset_cmd, "add", target_set, ip_str,
                "timeout", str(ban_duration),
                "-exist",
            )
        else:
            # Kalici ban (timeout 0)
            success = await self._exec_command(
                self._ipset_cmd, "add", target_set, ip_str,
                "-exist",
            )

        if success:
            self._banned_ips.add(ip_str)
            dur_str = f"{ban_duration}s" if ban_duration > 0 else "KALICI"
            logger.info(
                "IP BANNED: %s | Duration: %s | Reason: %s",
                ip_str, dur_str, reason,
            )
        return success

    async def enforce_db_bans(self, items: list[dict[str, object]]) -> dict[str, int]:
        """Apply ban records to the real firewall even when simulation mode is enabled."""
        stats = {"requested": len(items), "applied": 0, "failed": 0, "skipped": 0}
        if not items:
            return stats

        previous_simulation = self._simulation_mode
        self._simulation_mode = False
        try:
            for item in items:
                ip_value = str(item.get("ip") or "").strip()
                if not ip_value:
                    stats["skipped"] += 1
                    continue

                duration_value = item.get("duration")
                try:
                    duration = int(duration_value) if duration_value is not None else 0
                except (TypeError, ValueError):
                    duration = 0

                reason = str(item.get("reason") or "simulation replay")
                success = await self.ban_ip(
                    ip_value,
                    duration=duration,
                    reason=f"{reason} [SimulationReplay]",
                    force_reapply=True,
                )
                if success:
                    stats["applied"] += 1
                else:
                    stats["failed"] += 1
        finally:
            self._simulation_mode = previous_simulation

        return stats

    async def unban_ip(self, ip_str: str) -> bool:
        """
        Unbans an IP address (removes it from the ipset).

        Args:
            ip_str: IP address to unban.

        Returns:
            True if unban was successful.
        """
        success = await self._exec_command(
            self._ipset_cmd, "del", self._get_set_for_ip(ip_str), ip_str,
            "-exist",
        )
        if success:
            self._banned_ips.discard(ip_str)
            logger.info("IP UNBANNED: %s", ip_str)
        return success

    async def is_banned(self, ip_str: str) -> bool:
        """
        Checks if an IP is banned (exists in the ipset).

        Args:
            ip_str: IP address to check.

        Returns:
            True if the IP is banned.
        """
        if ip_str in self._banned_ips:
            return True
        success = await self._exec_command(
            self._ipset_cmd, "test", self._get_set_for_ip(ip_str), ip_str,
            ignore_errors=True,
        )
        return success

    async def flush(self) -> bool:
        """
        Removes all bans (clears the ipset).

        WARNING: All active bans will be removed!

        Returns:
            True if flush was successful.
        """
        success = await self._exec_command(
            self._ipset_cmd, "flush", self._set_name
        )
        if self._ipv6_supported:
            await self._exec_command(
                self._ipset_cmd, "flush", self._set_name_v6
            )
        if success:
            self._banned_ips.clear()
            logger.warning("ALL BANS REMOVED! Sets '%s'/'%s' flushed.",
                           self._set_name, self._set_name_v6)
        return success

    async def get_banned_count(self) -> int:
        """
        Returns the number of active bans.

        Returns:
            Number of entries in the ipset set.
        """
        if self._simulation_mode:
            return 0

        total = 0
        for set_name in (self._set_name, self._set_name_v6):
            if set_name == self._set_name_v6 and not self._ipv6_supported:
                continue
            try:
                cmd = []
                if self._use_sudo:
                    cmd = [self._sudo_cmd, "-n"]
                cmd += [self._ipset_cmd, "list", set_name, "-t"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode("utf-8", errors="replace")

                for line in output.splitlines():
                    if line.strip().startswith("Number of entries:"):
                        total += int(line.split(":")[-1].strip())
            except Exception as exc:
                logger.debug("Failed to get ban count for %s: %s", set_name, exc)

        return total

    async def list_banned_ips(self, limit: int = 500) -> list[dict[str, str]]:
        """
        Returns raw IPs currently present in the firewall ipset(s).

        This is intended for operational/admin visibility. Database records
        remain hash-based for privacy, but the firewall necessarily holds
        currently blocked source IPs in plaintext.
        """
        if self._simulation_mode:
            return []

        items: list[dict[str, str]] = []
        sets_to_load = [(self._set_name, "ipv4")]
        if self._ipv6_supported:
            sets_to_load.append((self._set_name_v6, "ipv6"))

        for set_name, family in sets_to_load:
            try:
                cmd = []
                if self._use_sudo:
                    cmd = [self._sudo_cmd, "-n"]
                cmd += [self._ipset_cmd, "list", set_name]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode != 0:
                    continue

                in_members = False
                for line in stdout.decode(errors="replace").splitlines():
                    stripped = line.strip()
                    if stripped == "Members:":
                        in_members = True
                        continue
                    if in_members and stripped:
                        ip_value = stripped.split()[0]
                        items.append({"ip": ip_value, "family": family})
                        if len(items) >= limit:
                            return items
            except Exception as exc:
                logger.debug("Failed to list banned IPs for %s: %s", set_name, exc)

        return items

    # ── Sudo probe ──

    async def _probe_direct_privileged(self) -> bool:
        """Returns True if ipset can run directly without sudo."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._ipset_cmd, "list", "-n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    async def _probe_sudo(self, sudo_path: str) -> bool:
        """Returns True if 'sudo -n <ipset_cmd> list -n' succeeds without a password prompt."""
        try:
            proc = await asyncio.create_subprocess_exec(
                sudo_path, "-n", self._ipset_cmd, "list", "-n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True
            err = stderr.decode(errors="replace").lower()
            if "password" in err:
                return False
            if "no new privileges" in err:
                return False
            if "not permitted" in err or "permission denied" in err:
                return False
            return False
        except Exception:
            return False

    async def _load_existing_bans(self) -> None:
        """Populate _banned_ips from ipset entries that survived a previous run."""
        sets_to_load = [self._set_name]
        if self._ipv6_supported:
            sets_to_load.append(self._set_name_v6)
        for set_name in sets_to_load:
            try:
                cmd = []
                if self._use_sudo:
                    cmd = [self._sudo_cmd, "-n"]
                cmd += [self._ipset_cmd, "list", set_name]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode != 0:
                    continue
                in_members = False
                for line in stdout.decode(errors="replace").splitlines():
                    stripped = line.strip()
                    if stripped == "Members:":
                        in_members = True
                        continue
                    if in_members and stripped:
                        # Each member line is: "<ip> timeout <secs>" or just "<ip>"
                        self._banned_ips.add(stripped.split()[0])
            except Exception as exc:
                logger.debug("Could not load existing bans from ipset %s: %s", set_name, exc)
        if self._banned_ips:
            logger.info(
                "Loaded %d existing ban(s) from ipset.",
                len(self._banned_ips),
            )

    # ── Shutdown ──

    async def shutdown(self) -> None:
        """
        Called when the firewall module is shutting down.
        ipset set and iptables rules are preserved (bans continue).
        """
        logger.info(
            "Firewall module shutting down. "
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
        Asynchronously executes a system command.

        In simulation mode, the command is not executed, only logged.

        Args:
            *args:         Command and arguments.
            ignore_errors: True to return False on error (do not raise exception).

        Returns:
            True ise komut basarili.
        """
        # Prepend 'sudo -n' when running without root but NOPASSWD is configured.
        if self._use_sudo:
            args = (self._sudo_cmd, "-n") + args

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
        """Returns True if in simulation mode."""
        return self._simulation_mode

    def __repr__(self) -> str:
        mode = "simulation"
        if not self._simulation_mode:
            if self._use_sudo:
                mode = "sudo"
            elif self._direct_privileged:
                mode = "capabilities"
            else:
                mode = "root"
        return (
            f"<FirewallManager "
            f"set='{self._set_name}' "
            f"mode={mode}>"
        )
