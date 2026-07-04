"""Parser for browser cookies — Cookies/ and per-browser Cookies.txt files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class CookiesParser(BaseParser):
    """Parses Netscape-format cookie files from Remus logs."""

    def parse(self) -> dict[str, Any]:
        """Parse all cookie files and return structured data."""
        cookies: list[dict[str, Any]] = []
        browser_summaries: dict[str, dict[str, Any]] = {}

        # Parse Cookies/ directory (Netscape format)
        cookies_dir = self.log_dir / "Cookies"
        if cookies_dir.is_dir():
            for cookie_file in sorted(cookies_dir.iterdir()):
                if not cookie_file.is_file():
                    continue
                file_content = self.read_file_with_timeout(cookie_file)
                if file_content is None:
                    continue

                # Extract browser and profile from filename: "Cookies_Edge_Default.txt"
                stem = cookie_file.stem  # e.g., "Cookies_Edge_Default"
                if stem.startswith("Cookies_"):
                    inner = stem[len("Cookies_"):]
                    # Split on last underscore for "Browser_Profile"
                    last_underscore = inner.rfind("_")
                    if last_underscore > 0:
                        browser_raw = inner[:last_underscore].strip()
                        profile = inner[last_underscore + 1:].strip()
                    else:
                        browser_raw = inner.strip()
                        profile = "Default"
                else:
                    browser_raw = "Unknown"
                    profile = "Unknown"

                source_key = f"{browser_raw}|{profile}"
                browser_summaries[source_key] = {
                    "browser": browser_raw,
                    "profile": profile,
                    "count": 0,
                    "domains": set(),
                }

                for line in file_content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

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
                        "browser": browser_raw,
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

        # Parse per-browser Cookies.txt files
        for browser_dir in self.log_dir.iterdir():
            if not browser_dir.is_dir():
                continue
            browser_name = browser_dir.name

            if browser_name in ("Cookies", "GoogleAccounts", "Applications", "Important", "Wallets"):
                continue

            for profile_dir in browser_dir.iterdir():
                if not profile_dir.is_dir():
                    continue

                cookies_file = profile_dir / "Cookies.txt"
                if not cookies_file.is_file():
                    continue

                content = self.read_file_with_timeout(cookies_file)
                if content is None:
                    continue

                profile_name = profile_dir.name
                source_key = f"{browser_name}|{profile_name}"
                browser_summaries[source_key] = {
                    "browser": browser_name,
                    "profile": profile_name,
                    "count": 0,
                    "domains": set(),
                }

                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

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
                        "browser": browser_name,
                        "profile": profile_name,
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
            domains_list = sorted(summary["domains"])[:20]
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
