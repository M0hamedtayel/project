import time
import logging
from playwright.sync_api import sync_playwright
from scrapling.parser import Selector
from crawlers.base import BaseCrawler
from utils.tor_manager import renew_tor_circuit
from utils.dedup import compute_dedup_hash
from db.queries import thread_exists_by_hash, insert_thread
from config import TOR_SOCKS_PORT, PAGE_TIMEOUT, REQUEST_DELAY, MAX_RETRIES

logger = logging.getLogger(__name__)


class DnaForumCrawler(BaseCrawler):
    def __init__(self, forum_id: int, base_url: str):
        super().__init__(forum_id, base_url, source_type="onion")

    def fetch_page(self, url: str):
        if self._request_count > 0 and self._request_count % 10 == 0:
            renew_tor_circuit()
            time.sleep(REQUEST_DELAY)

        with sync_playwright() as p:
            browser = p.chromium.launch(
                proxy={"server": f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"}
            )
            page = browser.new_page()
            page.goto(url, timeout=PAGE_TIMEOUT)
            html = page.content()
            browser.close()
        return Selector(html)

    def extract_categories(self, page) -> list[str]:
        return []

    def _fetch_with_retry_browser(self, url: str, scroll: bool = False):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._request_count += 1
                with sync_playwright() as p:
                    browser = p.chromium.launch(
                        proxy={"server": f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"}
                    )
                    ctx = browser.new_context()
                    page = ctx.new_page()
                    page.goto(url, timeout=PAGE_TIMEOUT)
                    time.sleep(3)

                    if scroll:
                        prev = 0
                        for s in range(50):
                            page.evaluate(
                                "window.scrollTo(0, document.body.scrollHeight)"
                            )
                            time.sleep(2.5)
                            current = page.locator("div.structItem").count()
                            if current == prev:
                                break
                            prev = current

                    html = page.content()
                    ctx.close()
                    browser.close()

                time.sleep(REQUEST_DELAY)
                return Selector(html)

            except Exception as e:
                logger.warning(
                    "Attempt %d failed for %s: %s", attempt, url, e
                )
                if attempt < MAX_RETRIES:
                    time.sleep(REQUEST_DELAY)
        logger.error("All %d attempts failed for %s. Skipping.", MAX_RETRIES, url)
        return None

    def _crawl_category(self, cat_url: str):
        logger.info("Crawling category (scroll): %s", cat_url)

        page = self._fetch_with_retry_browser(cat_url, scroll=True)
        if not page:
            return

        threads = self.extract_threads_from_listing(page)
        logger.info("Found %d threads after scroll", len(threads))

        for thread in threads:
            dedup_hash = compute_dedup_hash(thread["title"], self.forum_id)
            if thread_exists_by_hash(dedup_hash):
                logger.info("[DUPLICATE] %s", thread["title"][:60])
                continue

            thread_page = self.fetch_with_retry(thread["url"])
            if not thread_page:
                continue

            thread["first_post_content"] = self.extract_first_post(thread_page)
            self._save_thread(thread)
            logger.info("[NEW] %s", thread["title"][:60])

    def run(self):
        logger.info(
            "Starting DNA forum crawler for forum_id=%s", self.forum_id
        )
        self._crawl_category(self.base_url)

    def extract_threads_from_listing(self, page) -> list[dict]:
        threads = []
        for item in page.css("div.structItem"):
            title_el = item.find("div.structItem-title a:not(.labelLink)")
            if not title_el:
                title_el = item.find("a.structItem-title a")
            if not title_el:
                title_el = item.find("a[href*='/threads/']")
            if not title_el:
                continue

            href = title_el.attrib.get("href", "")
            url = self._abs_url(href).split("?")[0]

            author_el = item.find("a.username")
            date_el = item.find("time, span.u-dt")

            threads.append(
                {
                    "url": url,
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "author": author_el.get_all_text().strip() if author_el else "",
                    "post_date": date_el.get_all_text().strip() if date_el else None,
                }
            )
        return threads

    def extract_first_post(self, page) -> str:
        for sel in [
            "div.message-body",
            "article.message-body",
            "div.message-content",
            "div.post_body",
            "div.bbWrapper",
        ]:
            el = page.find(sel)
            if el:
                return el.get_all_text().strip()
        return ""

    def has_next_page(self, page) -> str | None:
        return None
