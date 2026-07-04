"""Parser for browser credit card data — Credit.txt files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class CreditCardsParser(BaseParser):
    """Parses credit card data from Remus logs.

    Remus stores credit card information in two locations:

    1. Browser profile directories:
       <Browser>/<Profile>/Credit.txt
       e.g. Chrome/Default/Credit.txt
            Edge/Profile 1/Credit.txt
            Opera GX/Default/Credit.txt

    2. Dedicated CreditCards/ directory:
       CreditCards/<Browser>-<Profile>-Credit.txt
       e.g. CreditCards/Chrome-Default-Credit.txt
            CreditCards/Edge-Profile 1-Credit.txt
            CreditCards/Opera GX-Default-Credit.txt

    File format (one or more cards per file, separated by blank lines):
        Number: 5163610251362677
        Date: 5/2030
        CVC: 595
        Name: hayden evans
        Origin:

    Each card record has exactly 5 lines (Number, Date, CVC, Name, Origin).
    Multiple records are separated by one or more blank lines.
    """

    # Pattern to match a single card record block
    _CARD_RE = re.compile(
        r"Number:\s*(.+?)\s*\n"
        r"Date:\s*(.+?)\s*\n"
        r"CVC:\s*(.+?)\s*\n"
        r"Name:\s*(.+?)\s*\n"
        r"Origin:\s*\n?",
        re.MULTILINE,
    )

    # Browser directories that may contain Credit.txt
    _BROWSER_DIRS: set[str] = {
        "Chrome",
        "Edge",
        "Brave-Browser",
        "Brave",
        "Opera",
        "Opera GX",
        "Firefox",
        "Mozilla Firefox",
        "Waterfox",
        "MicrosoftEdge",
        "Chromium",
        "OperaGx",
        "Chrome-portable",
    }

    def parse(self) -> dict[str, Any]:
        """Parse all credit card files and return entries.

        Remus may store the same card data in two locations:
        1. Browser profile directories: <Browser>/<Profile>/Credit.txt
        2. Dedicated CreditCards/ directory: CreditCards/<Browser>-<Profile>-Credit.txt

        To avoid duplicates, we parse both sources but deduplicate
        using a composite key of (card_number, cardholder_name, expiry_date, cvc).
        Browser profile Credit.txt files are preferred (they come first).
        """
        # Strategy 1: Scan browser profile directories for Credit.txt
        entries = self._parse_browser_credit_files()

        # Strategy 2: Scan the CreditCards/ directory
        cc_entries = self._parse_credit_cards_dir()

        # Deduplicate: only add entries not already seen
        seen: set[tuple[str, str, str, str]] = set()
        for entry in entries:
            key = (
                entry["card_number"],
                entry["cardholder_name"],
                entry["expiry_date"],
                entry["cvc"],
            )
            seen.add(key)

        for entry in cc_entries:
            key = (
                entry["card_number"],
                entry["cardholder_name"],
                entry["expiry_date"],
                entry["cvc"],
            )
            if key not in seen:
                entries.append(entry)
                seen.add(key)

        return {
            "credit_cards": entries,
            "total_count": len(entries),
        }

    def _parse_browser_credit_files(self) -> list[dict[str, str]]:
        """Find and parse Credit.txt files inside browser profile directories."""
        results: list[dict[str, str]] = []

        for browser_dir in self.log_dir.iterdir():
            if not browser_dir.is_dir():
                continue

            browser_name = browser_dir.name
            if browser_name not in self._BROWSER_DIRS:
                continue

            # Skip sub-directories that are not browser profile directories
            # e.g., "Cookies", "GoogleAccounts", "Applications", "Important", "Wallets"
            if browser_name in ("Cookies", "GoogleAccounts", "Applications",
                                "Important", "Wallets", "CreditCards"):
                continue

            for profile_dir in browser_dir.iterdir():
                if not profile_dir.is_dir():
                    continue

                credit_file = profile_dir / "Credit.txt"
                if not credit_file.is_file():
                    continue

                content = self.read_file_with_timeout(credit_file)
                if content is None:
                    continue

                profile_name = profile_dir.name

                for match in self._CARD_RE.finditer(content):
                    card_number = match.group(1).strip()
                    expiry_date = match.group(2).strip()
                    cvc = match.group(3).strip()
                    cardholder_name = match.group(4).strip()

                    results.append({
                        "card_number": card_number,
                        "cardholder_name": cardholder_name,
                        "expiry_date": expiry_date,
                        "cvc": cvc,
                        "browser": browser_name,
                        "profile": profile_name,
                    })

        return results

    def _parse_credit_cards_dir(self) -> list[dict[str, str]]:
        """Parse files in the dedicated CreditCards/ directory."""
        results: list[dict[str, str]] = []
        credit_cards_dir = self.log_dir / "CreditCards"

        if not credit_cards_dir.is_dir():
            return results

        for credit_file in sorted(credit_cards_dir.iterdir()):
            if not credit_file.is_file():
                continue

            content = self.read_file_with_timeout(credit_file)
            if content is None:
                continue

            # Derive browser and profile from filename.
            # e.g. "Chrome-Default-Credit.txt" -> browser="Chrome", profile="Default"
            # e.g. "Edge-Profile 1-Credit.txt" -> browser="Edge", profile="Profile 1"
            # e.g. "Opera GX-Default-Credit.txt" -> browser="Opera GX", profile="Default"
            stem = credit_file.stem  # e.g. "Chrome-Default-Credit"
            browser, profile = self._parse_filename(stem)

            for match in self._CARD_RE.finditer(content):
                card_number = match.group(1).strip()
                expiry_date = match.group(2).strip()
                cvc = match.group(3).strip()
                cardholder_name = match.group(4).strip()

                results.append({
                    "card_number": card_number,
                    "cardholder_name": cardholder_name,
                    "expiry_date": expiry_date,
                    "cvc": cvc,
                    "browser": browser,
                    "profile": profile,
                })

        return results

    @staticmethod
    def _parse_filename(stem: str) -> tuple[str, str]:
        """Derive browser name and profile from a CreditCards filename stem.

        Filename format: <Browser>-<Profile>-Credit
        Browser names may contain spaces (e.g. "Opera GX", "Brave-Browser").
        Profile names may contain spaces (e.g. "Profile 1").

        Strategy: try known browser names first, then fall back to splitting
        from the right using "-Credit" as the suffix and "-" as separator.
        """
        # Remove the trailing "-Credit" part
        if stem.endswith("-Credit"):
            prefix = stem[: -len("-Credit")]
        elif stem.endswith("-Credit-Card"):
            prefix = stem[: -len("-Credit-Card")]
        else:
            # Fallback: unknown format
            return ("Unknown", "Default")

        # Try to match known multi-word browser names
        known_browsers = ["Mozilla Firefox", "Brave-Browser", "Brave",
                          "MicrosoftEdge", "Chrome-portable", "Opera GX",
                          "OperaGx", "Waterfox", "Chromium"]
        for known in known_browsers:
            if prefix.startswith(known + "-"):
                return known, prefix[len(known) + 1:]

        # Fallback: split on the last dash
        last_dash = prefix.rfind("-")
        if last_dash > 0:
            return prefix[:last_dash], prefix[last_dash + 1:]

        return prefix, "Default"
