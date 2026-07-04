"""
Abstract base class for all file parsers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Generator


@dataclass
class ParsedRecord:
    """Single parsed record from any source."""
    source_file: str
    breach_name: str
    line_number: int = 0
    raw_line: str = ""
    fields: dict = field(default_factory=dict)


class BaseParser(ABC):
    """Interface all parsers must implement."""

    def __init__(self, file_path: str, breach_name: str):
        self.file_path = file_path
        self.breach_name = breach_name
        self.failed_count = 0
        self.failed_samples = []

    def report_failure(self, line_num: int, raw_line: str, reason: str):
        """Record a failure, save raw line to the .failed file and keep a sample for logging."""
        self.failed_count += 1
        if len(self.failed_samples) < 10:
            self.failed_samples.append((line_num, raw_line, reason))
        
        failed_path = self.file_path + ".failed"
        try:
            with open(failed_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(raw_line + "\n")
        except Exception:
            pass

    @abstractmethod
    def parse(self) -> Generator[ParsedRecord, None, None]:
        """
        Yield ParsedRecord objects from the file.

        Each record should populate ``fields`` with raw key-value pairs
        extracted from the source. Normalization happens downstream.
        """
        raise NotImplementedError

    @staticmethod
    def detect_encoding(file_path: str) -> str:
        """
        Detect the character encoding of a file by examining the first 64KB.
        """
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(65536)
        except OSError:
            return "utf-8"
        if not chunk:
            return "utf-8"
        if chunk.startswith(b'\xef\xbb\xbf'):
            return "utf-8-sig"
        if chunk.startswith(b'\xff\xfe') or chunk.startswith(b'\xfe\xff'):
            return "utf-16"
        for enc in ["utf-8", "cp1256", "cp1252", "utf-16"]:
            try:
                chunk.decode(enc)
                return enc
            except UnicodeDecodeError:
                continue
        return "latin-1"

    @staticmethod
    def count_lines(file_path: str) -> int:
        """Count total lines in a file (for progress reporting)."""
        count = 0
        enc = BaseParser.detect_encoding(file_path)
        with open(file_path, "r", encoding=enc, errors="replace") as f:
            for _ in f:
                count += 1
        return count
