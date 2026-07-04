"""Parser for Files/ — scraped user files and screenshots."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser


SCREENSHOT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
FILE_TYPES_TO_TRACK = {".txt", ".log", ".json", ".xml", ".csv", ".xlsx", ".docx", ".pdf", ".zip", ".apk", ".7z", ".rar"}


class FilesParser(BaseParser):
    """Parses scraped files from Vidar logs.

    Records metadata only (file counts, types, screenshot counts).
    Does not extract actual file content.
    """

    supported_file_pattern = "Files/*"

    def parse(self) -> dict[str, Any]:
        """Scan Files/ directory and return metadata."""
        files_dir = self.log_dir / "Files"

        if not files_dir.is_dir():
            return {}

        file_types: set[str] = set()
        screenshot_count = 0
        total_count = 0

        for f in files_dir.rglob("*"):
            if f.is_file():
                total_count += 1
                ext = f.suffix.lower()
                if ext in SCREENSHOT_EXTENSIONS:
                    screenshot_count += 1
                if ext in FILE_TYPES_TO_TRACK:
                    file_types.add(ext)

        return {
            "scraped_count": total_count,
            "screenshots_count": screenshot_count,
            "file_types": sorted(file_types),
        }
