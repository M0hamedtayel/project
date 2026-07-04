"""Parser for Info.txt — system profile, hardware, antivirus."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lumma_parser.parsers.base import BaseParser


class InformationParser(BaseParser):
    """Parses Info.txt from Lumma logs.

    Lumma Info.txt uses a simple key-value format.
    The file may have a watermark/spam header at the top and ASCII art at the bottom.
    """

    def parse(self) -> dict[str, Any]:
        """Parse Info.txt and return structured data."""
        info_file = self.log_dir / "Info.txt"
        content = self.read_stripped(info_file)
        if content is None or not content.strip():
            return {}

        return {
            "build_date": self._extract_field(content, "Build Date"),
            "execution_path": self._extract_field(content, "Execution Path"),
            "elevated": self._extract_bool_field(content, "Elevated"),
            "computer_name": self._extract_field(content, "Computer Name"),
            "user_name": self._extract_field(content, "User Name"),
            "language": self._extract_field(content, "User Language"),
            "hostname": self._extract_field(content, "Netbios"),
            "os_version": self._extract_field(content, "Operation System"),
            "install_date": self._extract_field(content, "Install Date"),
            "local_date": self._extract_field(content, "System Date"),
            "time_zone": self._extract_field(content, "Time Zone"),
            "antivirus": self._extract_field(content, "Antivirus"),
            "hwid": self._extract_field(content, "HWID"),
            "processor": self._extract_field(content, "Processor"),
            "processor_threads": self._extract_field(content, "Processor Threads"),
            "processor_cores": self._extract_field(content, "Processor Cores"),
            "gpu": self._extract_field(content, "Graphics Card"),
            "ram": self._extract_field(content, "Installed RAM"),
            "display": self._extract_field(content, "Display Resolution"),
            "ip_address": self._extract_field(content, "IP Address"),
            "time": self._extract_field(content, "Time"),
            "country": self._extract_field(content, "Country"),
        }

    def _extract_field(self, content: str, field_name: str) -> str:
        """Extract a 'Field Name: value' line from the content.

        For fields like 'Graphics Card:' where the value is on the next
        line (tab-indented), this also checks the following line.
        """
        lines = content.splitlines()
        for i, line in enumerate(lines):
            # Check same line: "Field Name: value"
            pattern = rf"^\s*{re.escape(field_name)}\s*:\s*(.+)$"
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if value:
                    return value

            # Only for "Graphics Card:" — value is on next tab-indented line
            # e.g. "Graphics Card:\n\tAMD Radeon(TM) Graphics"
            if field_name == "Graphics Card":
                next_line = lines[i + 1] if i + 1 < len(lines) else ""
                next_stripped = next_line.strip()
                if next_line and next_stripped and next_line[0] in (" ", "\t"):
                    # Check it doesn't look like a new key (no leading word followed by colon)
                    if not re.match(r"^\s*[A-Za-z][\w\s]*\s*:", next_stripped):
                        return next_stripped

        return ""

    def _extract_bool_field(self, content: str, field_name: str) -> bool:
        """Extract a boolean field."""
        value = self._extract_field(content, field_name)
        return value.lower() == "yes" if value else False
