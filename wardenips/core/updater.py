"""
WardenIPS - Auto-Updater
==========================

Checks for new releases on GitHub and warns the user in the logs.
Displays release notes and version information.
"""

import aiohttp
from typing import Optional
from wardenips.core.logger import get_logger

logger = get_logger(__name__)

class UpdateChecker:
    """
    Asynchronously checks GitHub REST API for newer releases
    and logs an update warning if necessary.
    """

    def __init__(self, current_version: str, repo_url: str = "msncakma/WardenIPS") -> None:
        self._current_version = current_version.lstrip("v")
        self._repo = repo_url
        self._api_url = f"https://api.github.com/repos/{self._repo}/releases/latest"

    async def check_for_updates(self) -> None:
        """
        Fetches the latest release from the GitHub repository API.
        """
        logger.debug("Checking for WardenIPS updates...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self._api_url, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        tag_name = data.get("tag_name", "").lstrip("v")
                        
                        if not tag_name:
                            return

                        if self._is_newer(self._current_version, tag_name):
                            notes = data.get("body", "No release notes provided.")
                            # Clean up notes for single line logging or short multi-lines
                            notes_short = notes.split('\n')[0] if notes else ""
                            
                            logger.warning("")
                            logger.warning("=" * 60)
                            logger.warning("  🚀 NEW UPDATE AVAILABLE! 🚀")
                            logger.warning("=" * 60)
                            logger.warning(f"  Current Version : v{self._current_version}")
                            logger.warning(f"  Latest Version  : v{tag_name}")
                            logger.warning(f"  Update Notes    : {notes_short}")
                            logger.warning("")
                            logger.warning("  Please update WardenIPS via 'git pull' or download the new release.")
                            logger.warning("  Report any issues on GitHub and consider supporting the project!")
                            logger.warning("  Ko-fi: https://ko-fi.com/msncakma")
                            logger.warning("=" * 60)
                            logger.warning("")
                    else:
                        logger.debug(f"GitHub API update check failed. HTTP {response.status}")
        except Exception as exc:
            logger.debug(f"Failed to check for updates: {exc}")

    def _is_newer(self, current: str, latest: str) -> bool:
        """Simple semantic version comparison."""
        try:
            cur_parts = [int(p) for p in current.split(".")]
            lat_parts = [int(p) for p in latest.split(".")]
            
            # Pad with zeros if necessary
            length = max(len(cur_parts), len(lat_parts))
            cur_parts.extend([0] * (length - len(cur_parts)))
            lat_parts.extend([0] * (length - len(lat_parts)))
            
            for c, l in zip(cur_parts, lat_parts):
                if l > c:
                    return True
                elif l < c:
                    return False
            return False
        except ValueError:
            # Fallback to simple string comparison if arbitrary tags are used
            return current != latest
