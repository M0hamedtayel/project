"""Parser for browser autofill data — per-browser Autofills.txt files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lumma_parser.parsers.base import BaseParser


class AutofillParser(BaseParser):
    """Parses browser autofill data from Lumma logs.

    Files are located in browser profile directories:
        Chrome/Default/Autofills.txt
        Edge/Profile 1/Autofills.txt

    Format: alternating FORM:/VALUE: pairs:
        FORM: email
        VALUE: user@example.com

        FORM: first_name
        VALUE: John
    """

    def parse(self) -> dict[str, Any]:
        """Parse autofill files and return entries."""
        entries: list[dict[str, str]] = []

        for browser_dir in self.log_dir.iterdir():
            if not browser_dir.is_dir():
                continue
            browser_name = browser_dir.name

            if browser_name in ("Cookies", "GoogleAccounts", "Important",
                                "CreditCards", "Applications"):
                continue

            for profile_dir in browser_dir.iterdir():
                if not profile_dir.is_dir():
                    continue

                autofill_file = profile_dir / "Autofills.txt"
                if not autofill_file.is_file():
                    continue

                content = self.read_stripped(autofill_file)
                if content is None:
                    continue

                profile_name = profile_dir.name
                entries.extend(
                    self._parse_autofill_content(content, browser_name, profile_name)
                )

        return {
            "entries": entries,
            "total_count": len(entries),
        }

    @staticmethod
    def _parse_autofill_content(
        content: str, browser: str, profile: str,
    ) -> list[dict[str, str]]:
        """Parse FORM:/VALUE: pairs from autofill content."""
        entries: list[dict[str, str]] = []
        form_name: str | None = None

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("FORM:"):
                form_name = stripped[len("FORM:"):].strip()
            elif stripped.startswith("VALUE:") and form_name is not None:
                value_val = stripped[len("VALUE:"):].strip()
                entries.append({
                    "browser": browser,
                    "profile": profile,
                    "name": form_name,
                    "value": value_val,
                })
                form_name = None

        return entries
