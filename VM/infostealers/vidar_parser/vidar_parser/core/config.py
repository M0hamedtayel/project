"""Configuration management for the parser."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    """Parser configuration.

    All settings are immutable once created.
    """

    # Input: directory containing the parent zip, or extracted log directories
    input_dir: Path
    # Output: directory for JSONL output
    output_dir: Path = field(default_factory=lambda: Path("output"))
    # Number of parallel workers for processing
    max_workers: int = 0  # 0 = auto-detect (cpu_count + 4)
    # Buffer size for JSONL writes (records per flush)
    batch_size: int = 100
    # Error log file
    error_log_path: Path | None = field(default=None)
    # Progress report interval (every N records)
    progress_interval: int = 500

    @property
    def effective_workers(self) -> int:
        """Return the effective worker count."""
        import os
        if self.max_workers <= 0:
            return min(32, os.cpu_count() + 4)
        return self.max_workers
