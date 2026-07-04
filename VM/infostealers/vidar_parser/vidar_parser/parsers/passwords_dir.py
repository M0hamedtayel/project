"""Parser for Passwords/ directory — redundant per-browser password exports.

This is a secondary source that may contain additional entries not in passwords.txt.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class PasswordsDirParser(BaseParser):
    """Parses per-browser password export files from Vidar logs."""

    supported_file_pattern = "Passwords/*.txt"

    def parse(self) -> dict[str, Any]:
        """Parse per-browser password files.

        Returns summary only — actual credentials are from passwords.txt.
        """
        password_files = self.find_files("Passwords/*.txt")
        if not password_files:
            return {}

        file_count = len(password_files)
        browsers: set[str] = set()

        for pf in password_files:
            stem = pf.stem
            # e.g., "Google Chrome_Default_login_data_for_account" or "Google Chrome_Default_passwords"
            match = re.match(r"^(.+?)_", stem)
            if match:
                browsers.add(match.group(1).strip())

        return {
            "file_count": file_count,
            "browsers": sorted(browsers),
        }
