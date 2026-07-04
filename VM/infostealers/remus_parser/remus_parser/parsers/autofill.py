"""Parser for browser autofill data — per-browser Autofills.txt files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class AutofillParser(BaseParser):
    """Parses browser autofill data from Remus logs."""

    def parse(self) -> dict[str, Any]:
        """Parse autofill files and return entries."""
        entries: list[dict[str, str]] = []

        for browser_dir in self.log_dir.iterdir():
            if not browser_dir.is_dir():
                continue
            browser_name = browser_dir.name

            if browser_name in ("Cookies", "GoogleAccounts", "Applications", "Important", "Wallets"):
                continue

            for profile_dir in browser_dir.iterdir():
                if not profile_dir.is_dir():
                    continue

                autofill_file = profile_dir / "Autofills.txt"
                if not autofill_file.is_file():
                    continue

                content = self.read_file_with_timeout(autofill_file)
                if content is None:
                    continue

                profile_name = profile_dir.name

                # Autofill format: Name: <field_name>\nValue: <value>
                lines = content.splitlines()
                i = 0
                while i < len(lines):
                    stripped = lines[i].strip()
                    if stripped.startswith("Name:"):
                        name_val = stripped[len("Name:"):].strip()
                        i += 1
                        if i < len(lines) and lines[i].strip().startswith("Value:"):
                            value_val = lines[i].strip()[len("Value:"):].strip()
                            entries.append({
                                "browser": browser_name,
                                "profile": profile_name,
                                "name": name_val,
                                "value": value_val,
                            })
                    i += 1

        return {
            "entries": entries,
            "total_count": len(entries),
        }
