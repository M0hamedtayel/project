"""Structured logging setup for the parser."""

from __future__ import annotations

import logging
import sys
from pathlib import Path


def setup_logger(
    log_dir: Path | None = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure and return the application logger.

    Sets up:
    - A console handler (stderr, INFO+)
    - An optional file handler (if log_dir is provided)
    """
    logger = logging.getLogger("remus_parser")
    logger.setLevel(level)

    # Avoid adding duplicate handlers
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "parser.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
