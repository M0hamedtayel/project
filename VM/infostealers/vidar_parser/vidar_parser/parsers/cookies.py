"""Parser for Cookies/*.txt — Netscape-format browser cookies."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class CookiesParser(BaseParser):
    """Parses Netscape-format cookie files from Vidar logs."""

    supported_file_pattern = "Cookies/*.txt"

    def parse(self) -> dict[str, Any]:
        """Parse all cookie files and return structured data."""
        cookie_files = self.find_files("Cookies/*.txt")
        if not cookie_files:
            return {}

        cookies: list[dict[str, Any]] = []
        browser_summaries: dict[str, dict[str, Any]] = {}

        for cookie_file in cookie_files:
            content = self.read_file_with_timeout(cookie_file)
            if content is None:
                continue

            # Extract browser and profile from filename: "Google Chrome_Default.txt"
            stem = cookie_file.stem  # e.g., "Google Chrome_Default"
            match = re.match(r"^(.+?)_(.+)$", stem)
            browser = match.group(1).strip() if match else "Unknown"
            profile = match.group(2).strip() if match else "Unknown"

            source_key = f"{browser}|{profile}"
            browser_summaries[source_key] = {
                "browser": browser,
                "profile": profile,
                "count": 0,
                "domains": set(),
            }

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Netscape format (tab-separated):
                # domain  flag  path  secure  expiration  name  value
                parts = line.split("\t")
                if len(parts) < 7:
                    continue

                domain, flag, path, secure_str, expiry_str, name, value = (
                    parts[0], parts[1], parts[2],
                    parts[3], parts[4], parts[5], parts[6],
                )

                secure = secure_str == "TRUE"
                expiry_epoch: int | None = None
                try:
                    expiry_epoch = int(expiry_str)
                except ValueError:
                    pass

                cookies.append({
                    "browser": browser,
                    "profile": profile,
                    "domain": domain,
                    "name": name,
                    "value": value,
                    "path": path,
                    "expiry_epoch": expiry_epoch,
                    "secure": secure,
                })

                browser_summaries[source_key]["count"] += 1
                browser_summaries[source_key]["domains"].add(domain)

        # Convert domain sets to top domains (most frequent)
        cookie_summaries = []
        for key, summary in browser_summaries.items():
            domains_list = sorted(summary["domains"])[:20]  # Top 20 domains
            cookie_summaries.append({
                "browser": summary["browser"],
                "profile": summary["profile"],
                "count": summary["count"],
                "top_domains": domains_list,
            })

        return {
            "cookies": cookies,
            "cookie_summaries": cookie_summaries,
            "total_count": len(cookies),
        }
