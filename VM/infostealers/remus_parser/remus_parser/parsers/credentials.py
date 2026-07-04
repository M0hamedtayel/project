"""Parser for credentials — All Passwords.txt and per-browser Passwords.txt."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class CredentialsParser(BaseParser):
    """Parses credentials from All Passwords.txt and per-browser Passwords.txt."""

    def parse(self) -> dict[str, Any]:
        """Parse all credential files and return structured data."""
        entries: list[dict[str, str]] = []
        empty_count = 0

        # Parse All Passwords.txt
        all_pwd_file = self.log_dir / "All Passwords.txt"
        all_content = self.read_file_with_timeout(all_pwd_file)
        if all_content:
            entries.extend(self._parse_password_block(all_content, "All Passwords"))

        # Parse per-browser Passwords.txt files
        for browser_dir in self.log_dir.iterdir():
            if not browser_dir.is_dir():
                continue
            browser_name = browser_dir.name

            # Skip non-browser directories
            if browser_name in ("Cookies", "GoogleAccounts", "Applications", "Important", "Wallets"):
                continue

            for profile_dir in browser_dir.iterdir():
                if not profile_dir.is_dir():
                    continue

                pwd_file = profile_dir / "Passwords.txt"
                if pwd_file.is_file():
                    content = self.read_file_with_timeout(pwd_file)
                    if content:
                        entries.extend(
                            self._parse_password_block(content, browser_name, profile_dir.name)
                        )

        # Filter valid credentials
        valid = [e for e in entries if e.get("login") or e.get("password")]
        empty = [e for e in entries if not e.get("login") and not e.get("password")]

        # Extract domains
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

    def _parse_password_block(
        self, content: str, browser: str, profile: str | None = None,
    ) -> list[dict[str, str]]:
        """Parse a credential block from text content."""
        entries: list[dict[str, str]] = []

        # Skip header/banner lines
        lines = content.splitlines()
        # Find actual credential entries (after the ASCII art banner)
        in_entries = False
        current_entry: dict[str, str] = {}

        for line in lines:
            stripped = line.strip()

            # Detect credential entries: "Browser: <name>" or "Browser: <name> <version>"
            if stripped.startswith("Browser:"):
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}

                # Extract browser name and version
                rest = stripped[len("Browser:"):].strip()
                # e.g., "Edge 147.0.3912.86" or "Chrome 147.0.7727.138"
                parts = rest.split()
                browser_name = parts[0] if parts else browser
                version = parts[1] if len(parts) > 1 else ""
                full_browser = f"{browser_name} {version}".strip() if version else browser_name

                current_entry["browser"] = full_browser
                in_entries = True
                continue

            if not in_entries:
                continue

            if stripped.startswith("Url:"):
                current_entry["url"] = stripped[len("Url:"):].strip()
            elif stripped.startswith("Login:"):
                current_entry["login"] = stripped[len("Login:"):].strip()
            elif stripped.startswith("Password:"):
                current_entry["password"] = stripped[len("Password:"):].strip()
            elif stripped.startswith("Profile:"):
                current_entry["profile"] = stripped[len("Profile:"):].strip()
            elif stripped.startswith("Date:"):
                current_entry["date"] = stripped[len("Date:"):].strip()
            elif not stripped:
                # Empty line = end of entry
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                    in_entries = False

        if current_entry:
            entries.append(current_entry)

        return entries
