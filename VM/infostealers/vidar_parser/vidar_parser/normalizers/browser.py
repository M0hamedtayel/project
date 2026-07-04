"""Browser name normalization."""

from __future__ import annotations

# Map raw browser names to canonical names
BROWSER_MAP: dict[str, str] = {
    "Google Chrome": "Google Chrome",
    "Chrome": "Google Chrome",
    "Chromium": "Google Chrome",
    "Microsoft Edge": "Microsoft Edge",
    "Edge": "Microsoft Edge",
    "Mozilla Firefox": "Mozilla Firefox",
    "Firefox": "Mozilla Firefox",
    "Brave": "Brave",
    "Opera": "Opera",
    "Safari": "Safari",
}


def normalize_browser(raw_name: str) -> str:
    """Normalize a browser name to its canonical form."""
    for key, canonical in BROWSER_MAP.items():
        if key.lower() in raw_name.lower():
            return canonical
    return raw_name or "Unknown"
