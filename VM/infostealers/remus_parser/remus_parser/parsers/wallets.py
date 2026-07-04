"""Parser for Wallets/ — cryptocurrency wallet data."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class WalletsParser(BaseParser):
    """Parses cryptocurrency wallet data from Remus logs."""

    def parse(self) -> dict[str, Any]:
        """Scan Wallets/ directory and return wallet metadata."""
        wallets_dir = self.log_dir / "Wallets"

        if not wallets_dir.is_dir():
            return {"wallets": [], "total_wallets": 0}

        wallets: list[dict[str, Any]] = []

        for wallet_dir in sorted(wallets_dir.iterdir()):
            if not wallet_dir.is_dir():
                continue

            # Extract wallet name, browser, and profile from path
            # e.g., Wallets/MetaMask_Default/MetaMask/...
            # e.g., Wallets/Phantom_Chrome_Profile 1/Phantom/...
            wallet_name = wallet_dir.name  # e.g., "MetaMask_Default"
            wallet_parts = wallet_name.rsplit("_", 1)
            if len(wallet_parts) == 2:
                name = wallet_parts[0]
                browser_profile = wallet_parts[1]
            else:
                name = wallet_name
                browser_profile = "Unknown"

            # Split browser and profile from the second part
            # e.g., "Chrome_Default" -> browser="Chrome", profile="Default"
            # e.g., "Profile 1" -> browser="Profile 1" (no profile separator)
            browser = browser_profile
            profile = "Default"
            if "_" in browser_profile:
                bp_parts = browser_profile.split("_", 1)
                browser = bp_parts[0]
                profile = bp_parts[1]

            # Collect wallet files
            file_paths: list[str] = []
            for f in sorted(wallet_dir.rglob("*")):
                if f.is_file():
                    rel_path = str(f.relative_to(wallets_dir))
                    file_paths.append(rel_path)

            wallets.append({
                "wallet_name": name,
                "browser": browser,
                "profile": profile,
                "files": file_paths[:100],  # Cap for size
            })

        return {
            "wallets": wallets,
            "total_wallets": len(wallets),
        }
