"""Parser for browser history — per-browser History.txt files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class HistoryParser(BaseParser):
    """Parses browser history files from Remus logs."""

    def parse(self) -> dict[str, Any]:
        """Parse all history files and return URL data."""
        all_urls: list[dict[str, str]] = []
        browser_summaries: dict[str, dict[str, Any]] = {}

        for browser_dir in self.log_dir.iterdir():
            if not browser_dir.is_dir():
                continue
            browser_name = browser_dir.name

            if browser_name in ("Cookies", "GoogleAccounts", "Applications", "Important", "Wallets"):
                continue

            for profile_dir in browser_dir.iterdir():
                if not profile_dir.is_dir():
                    continue

                history_file = profile_dir / "History.txt"
                if not history_file.is_file():
                    continue

                content = self.read_file_with_timeout(history_file)
                if content is None:
                    continue

                profile_name = profile_dir.name
                source_key = f"{browser_name}|{profile_name}"
                browser_summaries[source_key] = {
                    "browser": browser_name,
                    "profile": profile_name,
                    "url_count": 0,
                }

                in_entry = False
                current: dict[str, str] = {}

                for line in content.splitlines():
                    stripped = line.strip()

                    if stripped.startswith("Url:"):
                        if current:
                            all_urls.append(current)
                            browser_summaries[source_key]["url_count"] += 1
                            current = {}
                        current["url"] = stripped[len("Url:"):].strip()
                        in_entry = True
                    elif in_entry and stripped.startswith("Title:"):
                        current["title"] = stripped[len("Title:"):].strip()
                    elif in_entry and stripped.startswith("Time:"):
                        current["timestamp"] = stripped[len("Time:"):].strip()
                    elif in_entry and not stripped:
                        all_urls.append(current)
                        browser_summaries[source_key]["url_count"] += 1
                        current = {}
                        in_entry = False

                if current:
                    all_urls.append(current)
                    browser_summaries[source_key]["url_count"] += 1

        history_summaries = [
            {
                "browser": s["browser"],
                "profile": s["profile"],
                "url_count": s["url_count"],
            }
            for s in browser_summaries.values()
        ]

        return {
            "urls": all_urls,
            "history_summaries": history_summaries,
            "total_count": len(all_urls),
        }
