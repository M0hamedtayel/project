"""Parser for Important/ — scraped user files and sensitive data."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from remus_parser.parsers.base import BaseParser

# Patterns to detect sensitive data in scraped files
SENSITIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("password", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*(\S+)")),
    ("api_key", re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*(['\"][^'\"]+['\"]|\S{16,})")),
    ("access_token", re.compile(r"(?i)(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*(\S{20,})")),
    ("private_key", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
    ("wallet_address", re.compile(r"\b(0x[a-fA-F0-9]{40})\b")),
    ("mnemonic", re.compile(r"(?i)(?:mnemonic|seed|recovery)\s*[:=]\s*(\S+)")),
]


class ImportantFilesParser(BaseParser):
    """Parses scraped files from Important/ directory."""

    def parse(self) -> dict[str, Any]:
        """Scan Important/ directory and return file metadata."""
        important_dir = self.log_dir / "Important"

        if not important_dir.is_dir():
            return {
                "scraped_count": 0,
                "file_paths": [],
                "sensitive_data": [],
            }

        file_paths: list[str] = []
        sensitive_data: list[dict[str, str]] = []

        for f in sorted(important_dir.rglob("*")):
            if f.is_file():
                rel_path = str(f.relative_to(important_dir))
                file_paths.append(rel_path)

                # Read text files and scan for sensitive data
                content = self.read_file_with_timeout(f)
                if content is None:
                    continue

                for pattern_name, pattern in SENSITIVE_PATTERNS:
                    matches = pattern.findall(content)
                    for match in matches:
                        sensitive_data.append({
                            "file": rel_path,
                            "type": pattern_name,
                            "value": match if isinstance(match, str) else match[0],
                        })

        return {
            "scraped_count": len(file_paths),
            "file_paths": file_paths,
            "sensitive_data": sensitive_data,
        }
