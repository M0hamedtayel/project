"""Parser for Autofill/*.txt — browser autofill and search queries."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class AutofillParser(BaseParser):
    """Parses browser autofill data from Vidar logs."""

    supported_file_pattern = "Autofill/*.txt"

    def parse(self) -> dict[str, Any]:
        """Parse autofill files and return entries."""
        autofill_files = self.find_files("Autofill/*.txt")
        if not autofill_files:
            return {}

        entries: list[dict[str, str]] = []

        for autofill_file in autofill_files:
            content = self.read_file_with_timeout(autofill_file)
            if content is None:
                continue

            stem = autofill_file.stem
            match = re.match(r"^(.+?)_(.+)$", stem)
            browser = match.group(1).strip() if match else "Unknown"
            profile = match.group(2).strip() if match else "Unknown"

            for line in content.splitlines():
                line = line.strip()
                if line and line != "@logstester":
                    entries.append({
                        "browser": browser,
                        "profile": profile,
                        "entry": line,
                    })

        return {
            "entries": entries,
            "total_count": len(entries),
        }
