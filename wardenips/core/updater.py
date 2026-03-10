"""
WardenIPS - Auto-Updater
==========================

Checks for new releases on GitHub and exposes structured release metadata
for logs, dashboards, and installer/update flows.
"""

from __future__ import annotations

from typing import Any

import aiohttp

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

    async def get_status(self) -> dict[str, Any]:
        """Return structured update metadata for the current runtime."""
        logger.debug("Fetching WardenIPS release metadata...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self._api_url, timeout=5) as response:
                    if response.status != 200:
                        return {
                            "checked": False,
                            "current_version": self._current_version,
                            "update_available": False,
                            "error": f"GitHub API returned HTTP {response.status}.",
                        }

                    data = await response.json()
                    tag_name = str(data.get("tag_name", "")).lstrip("v")
                    release_notes = str(data.get("body", "") or "").strip()
                    preview = self._summarize_notes(release_notes)

                    if not tag_name:
                        return {
                            "checked": False,
                            "current_version": self._current_version,
                            "update_available": False,
                            "error": "GitHub release metadata did not contain a version tag.",
                        }

                    return {
                        "checked": True,
                        "current_version": self._current_version,
                        "latest_version": tag_name,
                        "update_available": self._is_newer(self._current_version, tag_name),
                        "release_notes": release_notes,
                        "release_notes_preview": preview,
                        "release_url": data.get("html_url", f"https://github.com/{self._repo}/releases"),
                        "published_at": data.get("published_at"),
                        "release_name": data.get("name") or f"v{tag_name}",
                    }
        except Exception as exc:
            logger.debug(f"Failed to fetch release metadata: {exc}")
            return {
                "checked": False,
                "current_version": self._current_version,
                "update_available": False,
                "error": str(exc),
            }

    async def check_for_updates(self) -> None:
        """
        Fetches the latest release from the GitHub repository API.
        """
        logger.debug("Checking for WardenIPS updates...")
        status = await self.get_status()
        if not status.get("checked"):
            logger.debug("Update check skipped: %s", status.get("error", "unknown error"))
            return
        if status.get("update_available"):
            notes_preview = status.get("release_notes_preview") or []
            notes_short = notes_preview[0] if notes_preview else "No release notes provided."
            logger.warning("")
            logger.warning("=" * 60)
            logger.warning("  NEW UPDATE AVAILABLE")
            logger.warning("=" * 60)
            logger.warning(f"  Current Version : v{status['current_version']}")
            logger.warning(f"  Latest Version  : v{status['latest_version']}")
            logger.warning(f"  Update Notes    : {notes_short}")
            logger.warning("  Release URL     : %s", status.get("release_url", "https://github.com/msncakma/WardenIPS/releases"))
            logger.warning("=" * 60)

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

    def _summarize_notes(self, notes: str, limit: int = 4) -> list[str]:
        """Extract short dashboard-friendly highlights from release notes."""
        lines: list[str] = []
        for raw_line in notes.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                line = line.lstrip("#").strip()
            if line.startswith(("- ", "* ")):
                line = line[2:].strip()
            if len(line) > 220:
                line = line[:217].rstrip() + "..."
            lines.append(line)
            if len(lines) >= limit:
                break
        return lines
