"""Parser for Info.txt — system profile, hardware, antivirus."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class InformationParser(BaseParser):
    """Parses Info.txt from Remus logs."""

    def parse(self) -> dict[str, Any]:
        """Parse Info.txt and return structured data."""
        info_file = self.log_dir / "Info.txt"
        content = self.read_file_with_timeout(info_file)
        if content is None:
            return {}

        return {
            "build_date": self._extract_field(content, "date", section="build"),
            "build_tag": self._extract_field(content, "tag", section="build"),
            "build_path": self._extract_field(content, "path", section="build"),
            "elevated": self._extract_bool_field(content, "elevated", section="build"),
            "ip_address": self._extract_field(content, "ip-address", section="build"),
            "country": self._extract_field(content, "country", section="build"),
            "time": self._extract_field(content, "time", section="build"),
            "os_version": self._extract_field(content, "version", section="os"),
            "time_zone": self._extract_field(content, "time-zone", section="os"),
            "local_date": self._extract_field(content, "local-date", section="os"),
            "install_date": self._extract_field(content, "install-date", section="os"),
            "language": self._extract_field(content, "language", section="os"),
            "computer_name": self._extract_field(content, "computer-name", section="os"),
            "user_name": self._extract_field(content, "user-name", section="os"),
            "netbios": self._extract_field(content, "netbios", section="os"),
            "domain": self._extract_field(content, "domain", section="os"),
            "hostname": self._extract_field(content, "hostname", section="os"),
            "antivirus": self._parse_antivirus(content),
            "hardware": self._parse_hardware(content),
        }

    def _extract_field(self, content: str, field_name: str, section: str | None = None) -> str:
        """Extract a key: value field from the content."""
        # Normalize field name: handle hyphens and underscores
        current_section = None
        known_fields = {
            "date", "tag", "path", "elevated", "ip-address", "country", "time",
            "version", "time-zone", "local-date", "install-date", "language",
            "computer-name", "user-name", "netbios", "domain", "hostname",
            "name", "state", "manufacturer", "product", "size", "core count",
            "core enabled", "thread count", "ip",
        }
        known_sections = {"build", "os", "hardware"}

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check if we entered a new top-level section
            if stripped.endswith(":") and not stripped.startswith("-") and not stripped.startswith("- "):
                section_name = stripped[:-1].lower()
                # Known top-level sections in Remus Info.txt
                if section_name in known_sections:
                    current_section = section_name
                    continue
                # Known fields should NOT be treated as sections
                if section_name in known_fields:
                    continue
                # Any other single-word section at top level
                if len(section_name) > 0:
                    current_section = section_name

            # If section filtering is active and we're not in the right section, skip
            if section is not None and current_section != section:
                continue

            # Match field name (handle hyphens/underscores)
            normalized = field_name.replace("-", "_").replace(" ", "_")
            pattern = rf"^\s*{re.escape(field_name)}:\s*(.+)$"
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if value == "":
                    return ""
                return value

        return ""

    def _extract_bool_field(self, content: str, field_name: str, section: str | None = None) -> bool:
        """Extract a boolean field."""
        value = self._extract_field(content, field_name, section)
        if value:
            return value.lower() == "true"
        return False

    def _parse_antivirus(self, content: str) -> list[dict[str, str]]:
        """Parse the anti-virus section."""
        av_list: list[dict[str, str]] = []
        current_av: dict[str, str] = {}
        in_av_section = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("anti-virus:"):
                in_av_section = True
                continue
            if in_av_section:
                if stripped.startswith("- name:"):
                    if current_av:
                        av_list.append(current_av)
                    current_av = {"name": stripped.split(":", 1)[1].strip()}
                elif stripped.startswith("  name:") or stripped.startswith("name:"):
                    pass  # already handled above
                elif stripped.startswith("    state:") or stripped.startswith("state:"):
                    current_av["state"] = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("  - name:") or (stripped.endswith(":") and not stripped.startswith("-") and not stripped.startswith("  ")):
                    if current_av:
                        av_list.append(current_av)
                        current_av = {}
                    in_av_section = False

        if current_av:
            av_list.append(current_av)

        return av_list

    def _parse_hardware(self, content: str) -> dict[str, Any]:
        """Parse the hardware section."""
        hardware: dict[str, list[dict[str, str]]] = {}
        current_type: str | None = None
        current_entry: dict[str, str] = {}
        in_hardware_section = False

        known_field_keys = {
            "manufacturer", "product", "size", "core count",
            "core enabled", "thread count", "display",
        }

        for line in content.splitlines():
            stripped = line.strip()

            if stripped.startswith("hardware:"):
                in_hardware_section = True
                continue

            if in_hardware_section:
                # Detect sub-section (motherboard, cpu, ram, gpu)
                if stripped.endswith(":") and not stripped.startswith("-") and not stripped.startswith("- "):
                    section_name = stripped[:-1].lower()
                    if section_name in ("motherboard", "cpu", "ram", "gpu"):
                        if current_entry and current_type:
                            hardware.setdefault(current_type, []).append(current_entry)
                            current_entry = {}
                        current_type = section_name
                        continue

                # Skip empty lines and section boundaries
                if not stripped:
                    continue

                # Detect bullet-point entry boundaries (new RAM/GPU/CPU entry)
                if stripped.startswith("- ") and current_type and current_entry:
                    hardware.setdefault(current_type, []).append(current_entry)
                    current_entry = {}

                # Parse key-value pairs within a hardware entry
                # Strip leading "- " if present (bullet point)
                parse_line = stripped.lstrip("- ").strip()
                if ":" in parse_line:
                    key, _, value = parse_line.partition(":")
                    key = key.strip()
                    value = value.strip()

                    if key in known_field_keys:
                        # Normalize key to use underscores
                        norm_key = key.replace(" ", "_")
                        if norm_key in ("core_count", "core_enabled", "thread_count"):
                            try:
                                current_entry[norm_key] = int(value)
                            except ValueError:
                                pass
                        else:
                            current_entry[norm_key] = value
                    else:
                        # Unknown key-value, store as product
                        current_entry["product"] = value
                # Handle GPU entries that are just product names (no colon)
                elif current_type == "gpu" and stripped and parse_line:
                    current_entry["product"] = parse_line

                # Detect new top-level section (non-hardware)
                elif stripped.endswith(":") and not stripped.startswith("-"):
                    section_name = stripped[:-1].lower()
                    if section_name not in known_field_keys and section_name not in ("motherboard", "cpu", "ram", "gpu"):
                        if current_entry and current_type:
                            hardware.setdefault(current_type, []).append(current_entry)
                            current_entry = {}
                            current_type = None
                        in_hardware_section = False

        if current_entry and current_type:
            hardware.setdefault(current_type, []).append(current_entry)

        return hardware
