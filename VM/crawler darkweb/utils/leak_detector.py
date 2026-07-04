import os
import re

_KEYWORDS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keywords.txt")
_keywords = None


def load_keywords() -> list[str]:
    global _keywords
    if _keywords is not None:
        return _keywords
    if not os.path.exists(_KEYWORDS_FILE):
        _keywords = []
        return _keywords
    with open(_KEYWORDS_FILE) as f:
        _keywords = [
            line.strip().lower()
            for line in f
            if line.strip() and not line.startswith("#")
        ]
    return _keywords


def _contains_keyword(text: str, keyword: str) -> bool:
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
    return bool(pattern.search(text))


def check_thread(title: str, content: str) -> list[str]:
    keywords = load_keywords()
    if not keywords:
        return []
    text = f"{title or ''} {content or ''}"
    return [kw for kw in keywords if _contains_keyword(text, kw)]
