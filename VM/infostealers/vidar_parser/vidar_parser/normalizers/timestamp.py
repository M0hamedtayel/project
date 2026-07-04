"""Timestamp normalization for Vidar logs."""

from __future__ import annotations

import re
from datetime import datetime


def normalize_timestamp(date_str: str) -> str | None:
    """Convert DD.MM.YYYY HH:MM:SS to ISO 8601 format.

    Example: "18.05.2026 21:12:43" → "2026-05-18T21:12:43"
    Returns None if the format is unrecognized.
    """
    if not date_str:
        return None

    match = re.match(r"(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}:\d{2}:\d{2})", date_str)
    if match:
        day, month, year, time = match.groups()
        try:
            dt = datetime(int(year), int(month), int(day),
                          int(time[:2]), int(time[3:5]), int(time[6:8]))
            return dt.isoformat()
        except ValueError:
            return None

    return None


def parse_timestamp_epoch(epoch_str: str) -> datetime | None:
    """Convert a Unix epoch timestamp to datetime."""
    try:
        return datetime.fromtimestamp(int(epoch_str))
    except (ValueError, OSError, OverflowError):
        return None
