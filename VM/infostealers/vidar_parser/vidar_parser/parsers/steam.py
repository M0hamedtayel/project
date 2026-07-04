"""Parser for Soft/Steam/ — VDF files and tokens."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import vdf

from vidar_parser.parsers.base import BaseParser


class SteamParser(BaseParser):
    """Parses Steam account data from Vidar logs."""

    supported_file_pattern = "Soft/Steam/*.vdf"

    def parse(self) -> dict[str, Any]:
        """Parse Steam VDF files and tokens."""
        result: dict[str, Any] = {}

        # Parse loginusers.vdf
        login_file = self.log_dir / "Soft" / "Steam" / "loginusers.vdf"
        login_content = self.read_file_with_timeout(login_file)
        if login_content:
            result["accounts"] = self._parse_login_users(login_content)

        # Parse libraryfolders.vdf
        library_file = self.log_dir / "Soft" / "Steam" / "libraryfolders.vdf"
        library_content = self.read_file_with_timeout(library_file)
        if library_content:
            result["library_folders"] = self._parse_library_folders(library_content)

        # Parse steam_tokens.txt
        token_file = self.log_dir / "Soft" / "Steam" / "steam_tokens.txt"
        token_content = self.read_file_with_timeout(token_file)
        if token_content:
            result["tokens"] = self._parse_tokens(token_content)

        return result

    def _parse_login_users(self, content: str) -> list[dict[str, Any]]:
        """Parse loginusers.vdf for account info."""
        try:
            data = vdf.loads(content)
        except Exception:
            return []

        accounts: list[dict[str, Any]] = []
        users = data.get("users", {})

        for steam_id, user_data in users.items():
            if not isinstance(user_data, dict):
                continue
            accounts.append({
                "steam_id": steam_id,
                "account_name": user_data.get("AccountName", ""),
                "persona_name": user_data.get("PersonaName", ""),
                "remember_password": user_data.get("RememberPassword") == "1",
            })

        return accounts

    def _parse_library_folders(self, content: str) -> list[dict[str, Any]]:
        """Parse libraryfolders.vdf for library paths and game counts."""
        try:
            data = vdf.loads(content)
        except Exception:
            return []

        folders: list[dict[str, Any]] = []
        library = data.get("libraryfolders", {})

        for key, folder_data in library.items():
            if not isinstance(folder_data, dict):
                continue
            path = folder_data.get("path", "")
            totalsize = folder_data.get("totalsize", "0")
            try:
                total_size_gb = int(totalsize) / (1024**3)
            except (ValueError, TypeError):
                total_size_gb = 0

            apps = folder_data.get("apps", {})
            if isinstance(apps, dict):
                apps_count = len(apps)
            else:
                apps_count = 0

            folders.append({
                "path": path,
                "total_size_gb": round(total_size_gb, 1),
                "installed_games_count": apps_count,
            })

        return folders

    def _parse_tokens(self, content: str) -> list[dict[str, Any]]:
        """Parse steam_tokens.txt for JWT tokens."""
        tokens: list[dict[str, Any]] = []
        lines = content.splitlines()

        # Token lines start with the account name, contain a JWT token
        # Format: "# hussamjo1 | SteamID: 76561199220173435 | Persona: hussamjo90"
        #         "hussamjo1.eyJ..."
        current_info: dict[str, str] = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith("*") or line.startswith("#"):
                # Comment line with account info
                if line.startswith("#"):
                    match = re.match(
                        r"#\s*(\S+)\s*\|\s*SteamID:\s*(\S+)\s*\|\s*Persona:\s*(.+)",
                        line,
                    )
                    if match:
                        current_info = {
                            "account_name": match.group(1),
                            "steam_id": match.group(2),
                            "persona_name": match.group(3).strip(),
                        }
            elif line and not line.startswith("#") and current_info:
                # Token line
                tokens.append({
                    "account_name": current_info.get("account_name", ""),
                    "steam_id": current_info.get("steam_id", ""),
                    "persona_name": current_info.get("persona_name", ""),
                    "token": line,
                })
                current_info = {}

        return tokens
