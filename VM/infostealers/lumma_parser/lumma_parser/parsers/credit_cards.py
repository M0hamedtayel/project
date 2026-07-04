"""Parser for credit card data — CreditCards/ directory files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lumma_parser.parsers.base import BaseParser


class CreditCardsParser(BaseParser):
    """Parses credit card data from Lumma logs.

    Lumma stores credit cards in the dedicated CreditCards/ directory:
        CreditCards/CC_Chrome_Profile 15.txt
        CreditCards/CC_Edge_Default.txt

    File format (one or more cards per file, separated by blank lines):
        CN: 4377213381170055
        DATE: 11/2025
        NAME:
        TARGET:
        CVV: 906
    """

    # Pattern to match a single card record block
    _CARD_RE = re.compile(
        r"CN:\s*(.+?)\s*\n"
        r"DATE:\s*(.+?)\s*\n"
        r"NAME:\s*(.*?)\s*\n"
        r"TARGET:\s*\n?"
        r"CVV:\s*(.+?)(?:\n\n|\n*$)",
        re.MULTILINE,
    )

    def parse(self) -> dict[str, Any]:
        """Parse all credit card files and return entries."""
        cc_dir = self.log_dir / "CreditCards"
        if not cc_dir.is_dir():
            return {"credit_cards": [], "total_count": 0}

        entries: list[dict[str, str]] = []

        for cc_file in sorted(cc_dir.iterdir()):
            if not cc_file.is_file():
                continue

            content = self.read_stripped(cc_file)
            if content is None:
                continue

            # Derive browser and profile from filename
            browser, profile = self._parse_filename(cc_file.stem)

            for match in self._CARD_RE.finditer(content):
                card_number = match.group(1).strip()
                expiry_date = match.group(2).strip()
                cardholder_name = match.group(3).strip()
                cvc = match.group(4).strip()

                entries.append({
                    "card_number": card_number,
                    "cardholder_name": cardholder_name,
                    "expiry_date": expiry_date,
                    "cvc": cvc,
                    "browser": browser,
                    "profile": profile,
                })

        return {
            "credit_cards": entries,
            "total_count": len(entries),
        }

    @staticmethod
    def _parse_filename(stem: str) -> tuple[str, str]:
        """Derive browser name and profile from a CreditCards filename stem.

        Format: "CC_<Browser>_<Profile>"
        e.g., "CC_Chrome_Profile 15" -> browser="Chrome", profile="Profile 15"
        e.g., "CC_Edge_Default" -> browser="Edge", profile="Default"
        """
        if stem.startswith("CC_"):
            inner = stem[len("CC_"):]
            # Split on last underscore for "Browser_Profile"
            last_underscore = inner.rfind("_")
            if last_underscore > 0:
                browser = inner[:last_underscore].strip()
                profile = inner[last_underscore + 1:].strip()
            else:
                browser = inner.strip()
                profile = "Default"
        else:
            browser = "Unknown"
            profile = "Default"

        return browser, profile
