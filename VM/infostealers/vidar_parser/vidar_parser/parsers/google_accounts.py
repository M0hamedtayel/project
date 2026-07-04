"""Parser for GoogleAccounts/*.txt — Google OAuth tokens."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class GoogleAccountsParser(BaseParser):
    """Parses Google OAuth account tokens from Vidar logs."""

    supported_file_pattern = "GoogleAccounts/*.txt"

    def parse(self) -> dict[str, Any]:
        """Parse all Google account token files."""
        account_files = self.find_files("GoogleAccounts/*.txt")
        if not account_files:
            return {}

        tokens: list[dict[str, str]] = []

        for account_file in account_files:
            content = self.read_file_with_timeout(account_file)
            if content is None:
                continue

            # Extract browser and profile from filename
            stem = account_file.stem
            match = re.match(r"^(.+?)_(.+)$", stem)
            browser = match.group(1).strip() if match else "Unknown"
            profile = match.group(2).strip() if match else "Unknown"

            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and line != "@logstester":
                    tokens.append({
                        "browser": browser,
                        "profile": profile,
                        "token": line,
                    })

        return {
            "tokens": tokens,
            "total_count": len(tokens),
        }
