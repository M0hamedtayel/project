"""Abstract base parser for Lumma file types."""

from __future__ import annotations

import gc
import logging
import os
import re
import shutil
import subprocess
import threading
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class RawLogData(Protocol):
    """Minimal interface for raw log content access."""

    def read_text(self, encoding: str = "utf-8") -> str: ...
    def read_bytes(self) -> bytes: ...
    @property
    def name(self) -> str: ...


class BaseParser(ABC):
    """Base class for all file-type parsers within a Lumma log."""

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir

    @abstractmethod
    def parse(self) -> dict[str, Any]:
        """Return parsed data as a dict ready for model validation."""

    def read_file(self, path: Path, encoding: str = "utf-8") -> str | None:
        """Read a text file, return None on failure."""
        try:
            return path.read_text(encoding=encoding)
        except Exception:
            logger.warning("Failed to read %s", path)
            return None

    def read_file_with_timeout(
        self, path: Path, timeout: float = 2.0, encoding: str = "utf-8",
    ) -> str | None:
        """Read a text file with a timeout to prevent hangs."""
        result: list[str | None] = [None]
        exception: list[Exception] = []

        def _read():
            try:
                result[0] = path.read_text(encoding=encoding)
            except Exception as e:
                exception.append(e)

        thread = threading.Thread(target=_read, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            logger.warning("File read timed out after %.1fs: %s", timeout, path)
            return None

        if exception:
            logger.warning("Failed to read %s: %s", path, exception[0])
            return None

        return result[0]

    def read_stripped(self, path: Path, encoding: str = "utf-8") -> str | None:
        """Read a text file and strip the Lumma watermark header.

        Lumma logs have a repeating watermark header (blank lines + Telegram
        spam banner + ASCII art separator) that may appear at the start of
        every file. This method returns the content with all watermark lines
        stripped, leaving only actual data.

        The watermark pattern:
        - Lines 1-19: blank
        - Lines 20-22: Telegram channel spam text
        - Lines 23+: repeated fancy Unicode handles
        - Line ~24: separator "==========..."
        - After separator: actual data begins
        - Near end: ASCII art logo + more spam

        Returns None if file cannot be read.
        """
        raw = self.read_file(path, encoding)
        if raw is None:
            return None

        return self._strip_watermark(raw)

    @staticmethod
    def _strip_watermark(text: str) -> str:
        """Strip Lumma watermark/spam from file content.

        Returns the cleaned text with watermark lines removed.
        If no watermark is detected, returns the original text.
        """
        lines = text.splitlines()

        # Find the separator line ("==========...")
        separator_pattern = re.compile(r"^={10,}$")
        sep_idx = -1
        for i, line in enumerate(lines):
            if separator_pattern.match(line.strip()):
                sep_idx = i
                break

        if sep_idx < 0:
            # No watermark found, return as-is
            return text

        # Find the next data line after the separator
        data_start = sep_idx + 1
        while data_start < len(lines) and not lines[data_start].strip():
            data_start += 1

        if data_start >= len(lines):
            return ""

        # Collect data lines after separator, stopping before the next
        # ASCII art block (which is spam at the end of the file)
        data_lines: list[str] = []
        for i in range(data_start, len(lines)):
            line = lines[i]
            stripped = line.strip()

            # Check if we hit the ASCII art logo block at end of file
            if BaseParser._is_ascii_art_block(stripped):
                break

            # Also skip fancy Unicode spam lines (channel handles)
            # These contain characters outside ASCII range repeated in patterns
            if BaseParser._is_spam_line(stripped) and not stripped.startswith(("SOFT:", "URL:", "USER:", "PASS:", "FORM:", "VALUE:", "CN:", "DATE:", "NAME:", "CVV:", "Build", "Configuration:", "Execution", "Elevated:", "Computer", "User ", "User Language:", "Netbios:", "Operation", "Install", "System Date:", "Time Zone:", "Antivirus:", "HWID:", "Processor", "Graphics", "Installed RAM:", "Display", "IP Address:", "Time:", "Country:", "E ")):
                continue

            data_lines.append(line)

        return "\n".join(data_lines)

    @staticmethod
    def _is_ascii_art_block(line: str) -> bool:
        """Check if a line looks like the ASCII art logo block."""
        # The logo uses box-drawing characters like █, ▀, ▄, etc.
        art_chars = {"█", "▐", "▄", "▀", "░"}
        art_count = sum(1 for c in line if c in art_chars)
        return art_count > 3

    @staticmethod
    def _is_spam_line(line: str) -> bool:
        """Check if a line is likely spam/watermark text.

        Spam lines typically contain:
        - Fancy Unicode math symbols (𝒌, 𝐤, 𝓴, etc.)
        - Telegram channel handles
        - Repeated patterns of non-ASCII characters
        """
        # Count non-ASCII characters
        non_ascii = sum(1 for c in line if ord(c) > 127)
        # If more than 50% of the line is non-ASCII, it's spam
        if len(line) > 0 and non_ascii / len(line) > 0.5:
            return True
        return False

    @staticmethod
    def safe_delete(path: Path) -> None:
        """Delete a directory tree, avoiding Windows file-lock hangs."""
        try:
            for item in path.rglob("*"):
                try:
                    item.chmod(0o777)
                except (AttributeError, OSError):
                    pass

            try:
                subprocess.run(
                    [
                        "robocopy", str(path), "NUL", "/MIR",
                        "/NFL", "/NDL", "/NJH", "/NJS", "/NDC", "/NEG",
                        "/R:0", "/W:0",
                    ],
                    timeout=10,
                    capture_output=True,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

            shutil.rmtree(path, ignore_errors=True)

            gc.collect()
            try:
                os.sync()
            except AttributeError:
                pass
        except Exception:
            pass

    @staticmethod
    def extract_zip_to_temp(zip_path: Path, prefix: str = "lumma_extract_") -> Path:
        """Extract a zip file to a temp directory and return the log dir."""
        import tempfile

        temp_dir = Path(tempfile.mkdtemp(prefix=prefix))

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_dir)
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ValueError(f"Failed to extract {zip_path}: {e}")

        # Find the directory containing Info.txt
        info_file = temp_dir / "Info.txt"
        if info_file.is_file():
            return temp_dir

        for child in sorted(temp_dir.iterdir()):
            if child.is_dir():
                nested_info = child / "Info.txt"
                if nested_info.is_file():
                    return child

        for child in sorted(temp_dir.iterdir()):
            if child.is_dir():
                return child

        shutil.rmtree(temp_dir, ignore_errors=True)
        raise FileNotFoundError(f"No log directory found in {zip_path}")
