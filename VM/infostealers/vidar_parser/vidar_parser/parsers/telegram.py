"""Parser for Soft/Telegram/tdata/ — Telegram session files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class TelegramParser(BaseParser):
    """Parses Telegram session data from Vidar logs.

    Note: Telegram session files are encrypted. We only detect presence
    and record the session file structure for later analysis.
    """

    supported_file_pattern = "Soft/Telegram/tdata/*"

    def parse(self) -> dict[str, Any]:
        """Detect Telegram session presence and record structure."""
        tdata_dir = self.log_dir / "Soft" / "Telegram" / "tdata"

        if not tdata_dir.is_dir():
            return {}

        # Collect session file info
        session_files: list[str] = []
        user_hashes: set[str] = set()
        all_files = sorted(tdata_dir.rglob("*"))

        for f in all_files:
            if f.is_file():
                session_files.append(f.name)
                # User hashes are 16-char hex directories
                if f.is_dir() or re.match(r"^[0-9A-F]{16}s?$", f.name):
                    name = f.name.rstrip("s")
                    if len(name) == 16 and all(c in "0123456789ABCDEF" for c in name):
                        user_hashes.add(name)

        # Also check for user hash in directory structure
        for d in tdata_dir.iterdir():
            if d.is_dir():
                name = d.name
                if len(name) == 16 and all(c in "0123456789ABCDEF" for c in name):
                    user_hashes.add(name)

        return {
            "present": True,
            "user_hashes": sorted(user_hashes),
            "session_files": session_files[:50],  # Cap for size
            "total_files": len(session_files),
        }
