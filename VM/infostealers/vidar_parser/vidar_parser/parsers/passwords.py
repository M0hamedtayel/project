"""Parser for passwords.txt — browser credential entries."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class PasswordsParser(BaseParser):
    """Parses passwords.txt from Vidar logs."""

    supported_file_pattern = "passwords.txt"

    def parse(self) -> dict[str, Any]:
        """Parse passwords.txt and return structured credential data."""
        password_file = self.log_dir / "passwords.txt"
        content = self.read_file_with_timeout(password_file)
        if content is None:
            return {}

        entries: list[dict[str, str]] = []
        empty_count = 0

        # Split by the "-----" separator
        blocks = content.split("-----")

        for block in blocks:
            block = block.strip()
            if not block or block == "@logstester":
                continue

            entry: dict[str, str] = {}
            for line in block.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip().lower().replace(" ", "_")
                    value = value.strip()
                    if key in ("soft", "host", "login", "password"):
                        entry[key] = value

            if entry:
                # Map internal keys to output keys
                host = entry.get("host", "")
                entry["url"] = host

                # Determine credential type
                if host.startswith("android://"):
                    entry["credential_type"] = "android_app"
                elif host.startswith(("http://192.168.", "http://10.", "http://172.")):
                    entry["credential_type"] = "router"
                else:
                    entry["credential_type"] = "website"

                has_creds = bool(entry.get("login")) and bool(entry.get("password"))
                if has_creds:
                    entries.append(entry)
                else:
                    empty_count += 1

        # Extract browser sources
        browser_sources: dict[str, dict[str, Any]] = {}
        domains: set[str] = set()

        for entry in entries:
            soft = entry.get("soft", "")
            host = entry.get("host", "")

            # Parse "Soft: Google Chrome (Default)" → browser + profile
            browser = ""
            profile = ""
            match = re.match(r"^(.+?)\s*\((.+)\)$", soft)
            if match:
                browser = match.group(1).strip()
                profile = match.group(2).strip()
            else:
                browser = soft

            source_key = f"{browser}|{profile}"
            if source_key not in browser_sources:
                browser_sources[source_key] = {
                    "browser": browser,
                    "profile": profile,
                    "count": 0,
                }
            browser_sources[source_key]["count"] += 1

            # Extract domain from URL
            if host:
                domain_match = re.search(r"https?://([^/:]+)", host)
                if domain_match:
                    domains.add(domain_match.group(1))

        return {
            "accounts": entries,
            "browser_sources": list(browser_sources.values()),
            "total_entries": len(entries) + empty_count,
            "with_valid_credentials": len(entries),
            "empty_entries": empty_count,
            "unique_domains": len(domains),
        }
