"""In-memory zip extraction for Vidar logs."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Iterator


def extract_zip_in_memory(zip_path: Path) -> list[tuple[str, str]]:
    """Extract all files from a zip into memory.

    Returns a list of (relative_path, text_content) tuples.
    Skips binary files and directories.
    """
    entries: list[tuple[str, str]] = []

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                # Skip directories
                if name.endswith("/"):
                    continue
                try:
                    content = zf.read(name).decode("utf-8")
                    entries.append((name, content))
                except (UnicodeDecodeError, KeyError):
                    # Skip binary files (images, encrypted files, etc.)
                    pass
    except (zipfile.BadZipFile, OSError) as e:
        raise ValueError(f"Failed to extract zip {zip_path}: {e}")

    return entries


def extract_to_temp_dir(zip_path: Path, target_dir: Path) -> Path:
    """Extract a zip to a temp directory and return the log directory path.

    Each zip contains a top-level directory matching the zip name.
    Returns the path to that inner directory.
    """
    log_dir_name = zip_path.stem  # e.g., "vidar_20260518_AE_183.155.148.125"
    log_dir = target_dir / log_dir_name

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(target_dir)
    except (zipfile.BadZipFile, OSError) as e:
        raise ValueError(f"Failed to extract zip {zip_path}: {e}")

    if not log_dir.is_dir():
        # Fallback: first entry might be the directory
        with zipfile.ZipFile(zip_path, "r") as zf:
            first_entry = zf.namelist()[0] if zf.namelist() else ""
            first_part = Path(first_entry).parts[0] if first_entry else log_dir_name
            log_dir = target_dir / first_part

    return log_dir
