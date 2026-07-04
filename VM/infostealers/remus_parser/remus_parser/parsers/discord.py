"""Parser for Discord tokens — Applications/Discord/Tokens.txt."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser


class DiscordParser(BaseParser):
    """Parses Discord authentication tokens from Remus logs."""

    def parse(self) -> dict[str, Any]:
        """Parse Discord tokens file."""
        token_file = self.log_dir / "Applications" / "Discord" / "Tokens.txt"
        content = self.read_file_with_timeout(token_file)
        if content is None:
            return {"tokens": [], "total_count": 0}

        tokens: list[dict[str, str]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Discord tokens look like: eyJ... (JWT format)
            if line.startswith("eyJ") or len(line) > 50:
                tokens.append({"token": line})

        return {
            "tokens": tokens,
            "total_count": len(tokens),
        }
