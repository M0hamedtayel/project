"""Parser for Telegram sessions — Applications/Telegram UWP/tdata/."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class TelegramParser(BaseParser):
    """Parses Telegram session data from Remus logs."""

    def parse(self) -> dict[str, Any]:
        """Detect Telegram session presence and record structure."""
        # Check multiple possible Telegram locations
        tdata_dirs = [
            self.log_dir / "Applications" / "Telegram UWP" / "tdata",
        ]

        user_hashes: set[str] = set()
        session_files: list[str] = []

        for tdata_dir in tdata_dirs:
            if not tdata_dir.is_dir():
                continue

            for f in sorted(tdata_dir.rglob("*")):
                if f.is_file():
                    session_files.append(f.name)
                    # User hashes are 16-char hex directories
                    name = f.name.rstrip("s")
                    if len(name) == 16 and all(c in "0123456789ABCDEF" for c in name):
                        user_hashes.add(name)

            # Also check for user hash in directory structure
            for d in tdata_dir.iterdir():
                if d.is_dir():
                    name = d.name
                    if len(name) == 16 and all(c in "0123456789ABCDEF" for c in name):
                        user_hashes.add(name)

        if not user_hashes:
            return {}

        return {
            "present": True,
            "user_hashes": sorted(user_hashes),
            "session_files": session_files[:50],
            "total_files": len(session_files),
        }
