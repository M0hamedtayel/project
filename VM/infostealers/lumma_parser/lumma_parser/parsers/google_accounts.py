"""Parser for GoogleAccounts/ — Google OAuth tokens."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lumma_parser.parsers.base import BaseParser


class GoogleAccountsParser(BaseParser):
    """Parses Google OAuth account tokens from Lumma logs.

    Files are located in GoogleAccounts/ directory:
        Restore_Chrome_Default.txt
        Restore_Chrome_Profile 1.txt
        Restore_Edge_Default.txt

    Each file contains one or more OAuth2 access tokens, one per line.
    Token format: base64url_token:decimal_number
    """

    def parse(self) -> dict[str, Any]:
        """Parse all Google account token files."""
        account_files = self.log_dir / "GoogleAccounts"
        if not account_files.is_dir():
            return {"tokens": [], "total_count": 0}

        tokens: list[dict[str, str]] = []

        for account_file in sorted(account_files.iterdir()):
            if not account_file.is_file():
                continue

            # Extract browser and profile from filename
            # e.g., "Restore_Chrome_Default.txt" or "Restore_Edge_Profile 1.txt"
            stem = account_file.stem  # e.g., "Restore_Chrome_Default"
            browser, profile = self._parse_filename(stem)

            content = self.read_stripped(account_file)
            if content is None:
                continue

            for line in content.splitlines():
                line = line.strip()
                if line and line != "@logstester":
                    tokens.append({
                        "browser": browser,
                        "profile": profile,
                        "token": line,
                    })

        return {
            "tokens": tokens,
            "total_count": len(tokens),
        }

    @staticmethod
    def _parse_filename(stem: str) -> tuple[str, str]:
        """Extract browser name and profile from a GoogleAccounts filename.

        Format: "Restore_<Browser>_<Profile>.txt"
        """
        if stem.startswith("Restore_"):
            inner = stem[len("Restore_"):]
            last_underscore = inner.rfind("_")
            if last_underscore > 0:
                browser = inner[:last_underscore].strip()
                profile = inner[last_underscore + 1:].strip()
            else:
                browser = inner.strip()
                profile = "Default"
        else:
            browser = "Unknown"
            profile = "Unknown"

        return browser, profile
