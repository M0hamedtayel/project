import os
import json
import logging

logger = logging.getLogger(__name__)

COOKIES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cookies")


def _domain_to_filename(domain: str) -> str:
    return domain.replace(".", "_").replace(":", "_") + ".json"


def load_cookies(domain: str) -> list[dict] | None:
    filename = _domain_to_filename(domain)
    path = os.path.join(COOKIES_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        cookies = json.load(f)
    logger.info("Loaded %d cookies for %s", len(cookies), domain)
    return cookies


def save_cookies(domain: str, cookies: list[dict]):
    os.makedirs(COOKIES_DIR, exist_ok=True)
    filename = _domain_to_filename(domain)
    path = os.path.join(COOKIES_DIR, filename)
    with open(path, "w") as f:
        json.dump(cookies, f, indent=2)
    logger.info("Saved %d cookies for %s", len(cookies), domain)
