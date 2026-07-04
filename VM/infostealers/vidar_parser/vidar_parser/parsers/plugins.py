"""Parser for Plugins/ — browser extension data (2FA authenticator)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


class PluginsParser(BaseParser):
    """Parses browser extension data from Vidar logs.

    Currently focused on Google Authenticator extension which stores
    TOTP secrets locally.
    """

    supported_file_pattern = "Plugins/*"

    def parse(self) -> dict[str, Any]:
        """Parse plugin data from Vidar logs."""
        plugins_dir = self.log_dir / "Plugins"

        if not plugins_dir.is_dir():
            return {}

        extensions: list[dict[str, Any]] = []

        # Walk one level deep within Plugins/
        for item in sorted(plugins_dir.iterdir()):
            if item.is_file():
                self._process_plugin_file(item, extensions)
            elif item.is_dir():
                for sub_item in sorted(item.iterdir()):
                    if sub_item.is_file():
                        self._process_plugin_file(sub_item, extensions)

        return {
            "extensions": extensions,
            "total_2fa_secrets": sum(e["stored_secrets_count"] for e in extensions),
        }

    def _process_plugin_file(self, file_path: Path, extensions: list) -> None:
        """Process a single plugin file."""
        parts = file_path.parts
        browser = "Unknown"
        profile = "Unknown"

        for i, part in enumerate(parts):
            if part.startswith("Google Chrome") or part.startswith("Brave") or part.startswith("Microsoft Edge"):
                browser = part
                if i + 1 < len(parts) and "_" in parts[i + 1]:
                    profile = parts[i + 1].split("_", 1)[1]

        content = self.read_file_with_timeout(file_path)
        if content:
            totp_matches = re.findall(r"otpauth://totp/[^\\\"'\s]+", content)
            if totp_matches:
                extensions.append({
                    "browser": browser,
                    "profile": profile,
                    "extension": "Google Authenticator",
                    "stored_secrets_count": len(totp_matches),
                })
