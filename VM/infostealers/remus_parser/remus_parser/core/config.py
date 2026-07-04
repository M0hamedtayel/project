"""Configuration management for the parser."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    """Parser configuration.

    All settings are immutable once created.
    """

    input_dir: Path
    output_dir: Path = field(default_factory=lambda: Path("remus_results"))
    max_workers: int = 0  # 0 = auto-detect (cpu_count + 4)
    batch_size: int = 100
    error_log_path: Path | None = field(default=None)
    progress_interval: int = 500

    @property
    def effective_workers(self) -> int:
        """Return the effective worker count."""
        import os
        if self.max_workers <= 0:
            return min(32, os.cpu_count() + 4)
        return self.max_workers
