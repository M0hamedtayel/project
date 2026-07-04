"""Timestamp normalization for Remus logs."""

from __future__ import annotations

import re


def normalize_timestamp(date_str: str) -> str | None:
    """Convert DD.MM.YYYY HH:MM:SS to ISO 8601 format.

    Example: "18.05.2026 21:12:43" -> "2026-05-18T21:12:43"
    """
    if not date_str:
        return None

    match = re.match(r"(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}:\d{2}:\d{2})", date_str)
    if match:
        day, month, year, time = match.groups()
        try:
            from datetime import datetime as dt
            d = dt(int(year), int(month), int(day),
                   int(time[:2]), int(time[3:5]), int(time[6:8]))
            return d.isoformat()
        except ValueError:
            return None

    return None


def parse_timestamp_epoch(epoch_str: str):
    """Convert a Unix epoch timestamp to datetime."""
    try:
        from datetime import datetime as dt
        return dt.fromtimestamp(int(epoch_str))
    except (ValueError, OSError, OverflowError):
        return None
