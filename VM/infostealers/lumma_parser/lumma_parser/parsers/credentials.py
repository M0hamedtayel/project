"""Parser for credentials — All Passwords.txt and per-browser Passwords.txt."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lumma_parser.parsers.base import BaseParser


class CredentialsParser(BaseParser):
    """Parses credentials from All Passwords.txt and per-browser Passwords.txt.

    Lumma uses the format:
        SOFT: Chrome Default (147.0.7727.138)
        URL: https://example.com/
        USER: username_or_email
        PASS: password

    Entries are separated by blank lines. Files may have a watermark header.
    """

    def parse(self) -> dict[str, Any]:
        """Parse all credential files and return structured data."""
        entries: list[dict[str, str]] = []

        # Parse All Passwords.txt
        all_pwd_file = self.log_dir / "All Passwords.txt"
        all_content = self.read_stripped(all_pwd_file)
        if all_content:
            entries.extend(self._parse_password_block(all_content))

        # Parse per-browser Passwords.txt files
        for item in self.log_dir.iterdir():
            if not item.is_dir():
                continue

            browser_name = item.name

            # Skip non-browser directories
            if browser_name in ("Cookies", "GoogleAccounts", "Important",
                                "CreditCards", "Applications"):
                continue

            for profile_dir in item.iterdir():
                if not profile_dir.is_dir():
                    continue

                pwd_file = profile_dir / "Passwords.txt"
                if pwd_file.is_file():
                    content = self.read_stripped(pwd_file)
                    if content:
                        entries.extend(
                            self._parse_password_block(content)
                        )

        # Filter valid credentials
        valid = [e for e in entries if e.get("login") or e.get("password")]
        empty = [e for e in entries if not e.get("login") and not e.get("password")]

        # Extract domains and browsers
        domains: set[str] = set()
        browsers: set[str] = set()
        for e in valid:
            url = e.get("url", "")
            if url:
                dm = re.search(r"https?://([^/:]+)", url)
                if dm:
                    domains.add(dm.group(1))
            browsers.add(e.get("browser", ""))

        return {
            "accounts": valid,
            "total_entries": len(entries),
            "with_valid_credentials": len(valid),
            "empty_entries": len(empty),
            "unique_domains": len(domains),
            "unique_browsers": list(browsers),
        }

    def _parse_password_block(self, content: str) -> list[dict[str, str]]:
        """Parse credential blocks from text content.

        Handles the SOFT/URL/USER/PASS format with watermark stripping.
        """
        entries: list[dict[str, str]] = []
        current_entry: dict[str, str] = {}

        for line in content.splitlines():
            stripped = line.strip()

            # Detect new entry: "SOFT: Browser Name (version)"
            if stripped.startswith("SOFT:"):
                if current_entry and any(current_entry.values()):
                    entries.append(current_entry)
                    current_entry = {}

                # Extract browser name from SOFT line
                # e.g., "SOFT: Chrome Default (147.0.7727.138)"
                rest = stripped[len("SOFT:"):].strip()
                # Extract browser name before the version parentheses
                paren_match = re.search(r"^(.+?)\s+\(", rest)
                if paren_match:
                    browser_name = paren_match.group(1).strip()
                    version = rest[paren_match.end():].rstrip(")")
                    current_entry["browser"] = f"{browser_name} ({version})"
                else:
                    current_entry["browser"] = rest.strip()
                continue

            if not current_entry.get("browser"):
                continue

            if stripped.startswith("URL:"):
                current_entry["url"] = stripped[len("URL:"):].strip()
            elif stripped.startswith("USER:"):
                current_entry["login"] = stripped[len("USER:"):].strip()
            elif stripped.startswith("PASS:"):
                current_entry["password"] = stripped[len("PASS:"):].strip()
            elif not stripped and current_entry.get("browser"):
                # Empty line after a started entry = end of entry
                if any(current_entry.values()):
                    entries.append(current_entry)
                    current_entry = {}

        # Don't forget the last entry
        if current_entry and any(current_entry.values()):
            entries.append(current_entry)

        return entries
