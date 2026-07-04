import os
import logging
from itertools import cycle

logger = logging.getLogger(__name__)

PROXY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "proxies.txt")


class SimpleProxyRotator:
    def __init__(self, proxies: list[str]):
        self.proxies = proxies
        self._cycle = cycle(proxies)

    def get_proxy(self) -> str:
        return next(self._cycle)


def load_proxies() -> list[str]:
    if not os.path.exists(PROXY_FILE):
        return []

    with open(PROXY_FILE) as f:
        lines = [
            line.strip() for line in f if line.strip() and not line.startswith("#")
        ]

    formatted = []
    for p in lines:
        if p.startswith("http://") or p.startswith("socks"):
            formatted.append(p)
        else:
            formatted.append(f"http://{p}")
    return formatted


def get_proxy_rotator() -> SimpleProxyRotator | None:
    proxies = load_proxies()
    if not proxies:
        logger.info("No proxies found, running without proxy rotation")
        return None
    logger.info("Loaded %d proxies for rotation", len(proxies))
    return SimpleProxyRotator(proxies)
