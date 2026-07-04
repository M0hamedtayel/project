"""Parser for History/*.txt — browser history URLs."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class HistoryParser(BaseParser):
    """Parses browser history files from Vidar logs."""

    supported_file_pattern = "History/*.txt"

    def parse(self) -> dict[str, Any]:
        """Parse all history files and return URL data."""
        history_files = self.find_files("History/*.txt")
        if not history_files:
            return {}

        all_urls: list[dict[str, str]] = []
        browser_summaries: dict[str, dict[str, Any]] = {}
        domain_counter: Counter = Counter()

        for history_file in history_files:
            content = self.read_file_with_timeout(history_file)
            if content is None:
                continue

            # Extract browser and profile from filename
            stem = history_file.stem
            match = re.match(r"^(.+?)_(.+)$", stem)
            browser = match.group(1).strip() if match else "Unknown"
            profile = match.group(2).strip() if match else "Unknown"

            source_key = f"{browser}|{profile}"
            browser_summaries[source_key] = {
                "browser": browser,
                "profile": profile,
                "url_count": 0,
            }

            for line in content.splitlines():
                url = line.strip()
                if not url or url.startswith("#"):
                    continue

                all_urls.append({
                    "browser": browser,
                    "profile": profile,
                    "url": url,
                })

                browser_summaries[source_key]["url_count"] += 1

                # Extract domain for counting
                domain_match = re.search(r"https?://([^/:]+)", url)
                if domain_match:
                    domain_counter[domain_match.group(1)] += 1

        # Convert summaries
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
            "top_domains": [domain for domain, _ in domain_counter.most_common(20)],
        }
