"""Browser name normalization."""

from __future__ import annotations

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
    "Opera GX": "Opera GX",
    "Opera GX Stable": "Opera GX",
    "Safari": "Safari",
    "Arc Browser": "Arc Browser",
    "Wave Browser": "Wave Browser",
    "Vivaldi": "Vivaldi",
    "Waterfox": "Waterfox",
    "Zen Browser": "Zen Browser",
    "Floorp Browser": "Floorp Browser",
    "Maxthon": "Maxthon",
    "CocCoc Browser": "CocCoc Browser",
    "Comet Browser": "Comet Browser",
    "Chrome Beta": "Chrome Beta",
    "AVG Secure Browser": "AVG Secure Browser",
    "Brave-Browser": "Brave",
}


def normalize_browser(raw_name: str) -> str:
    """Normalize a browser name to its canonical form.

    Checks longer keys first to avoid partial matches
    (e.g. "Opera GX" before "Opera").
    """
    # Sort by key length descending so longer matches take priority
    for key, canonical in sorted(BROWSER_MAP.items(), key=lambda x: len(x[0]), reverse=True):
        if key.lower() in raw_name.lower():
            return canonical
    return raw_name or "Unknown"
