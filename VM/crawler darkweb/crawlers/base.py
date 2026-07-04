import time
import logging
from urllib.parse import urlsplit
from abc import ABC, abstractmethod
from config import REQUEST_DELAY, MAX_RETRIES, MAX_PAGES
from utils.dedup import compute_dedup_hash
from db.queries import thread_exists_by_hash, insert_thread

logger = logging.getLogger(__name__)


class BaseCrawler(ABC):
    def __init__(
        self, forum_id: int, base_url: str, source_type: str, max_pages: int = MAX_PAGES
    ):
        self.forum_id = forum_id
        self.base_url = base_url.rstrip("/")
        self.source_type = source_type
        self.max_pages = max_pages
        self._request_count = 0
        parts = urlsplit(self.base_url)
        self.root_url = f"{parts.scheme}://{parts.netloc}"

    def _abs_url(self, href: str) -> str:
        if href.startswith("http"):
            return href
        return f"{self.root_url}/{href.lstrip('/')}"

    @abstractmethod
    def fetch_page(self, url: str):
        pass

    @abstractmethod
    def extract_categories(self, page) -> list[str]:
        pass

    @abstractmethod
    def extract_threads_from_listing(self, page) -> list[dict]:
        pass

    @abstractmethod
    def extract_first_post(self, page) -> str:
        pass

    @abstractmethod
    def has_next_page(self, page) -> str | None:
        pass

    def fetch_with_retry(self, url: str):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._request_count += 1
                page = self.fetch_page(url)
                time.sleep(REQUEST_DELAY)
                return page
            except Exception as e:
                logger.warning("Attempt %d failed for %s: %s", attempt, url, e)
                if attempt < MAX_RETRIES:
                    time.sleep(REQUEST_DELAY)
        logger.error("All %d attempts failed for %s. Skipping.", MAX_RETRIES, url)
        return None

    def _is_duplicate(self, title: str) -> bool:
        h = compute_dedup_hash(title, self.forum_id)
        return thread_exists_by_hash(h)

    def _save_thread(self, thread_data: dict) -> bool:
        thread_data["dedup_hash"] = compute_dedup_hash(
            thread_data["title"], self.forum_id
        )
        thread_data["forum_id"] = self.forum_id
        thread_data["source_type"] = self.source_type
        return insert_thread(thread_data)

    def _crawl_category(self, cat_url: str):
        logger.info("Crawling category: %s", cat_url)
        page = self.fetch_with_retry(cat_url)
        if not page:
            return

        page_num = 0
        while page_num < self.max_pages:
            page_num += 1
            threads = self.extract_threads_from_listing(page)
            logger.info("Page %d: found %d threads", page_num, len(threads))

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

            next_url = self.has_next_page(page)
            if not next_url:
                break
            page = self.fetch_with_retry(next_url)
            if not page:
                break

    def run(self):
        logger.info(
            "Starting %s crawler for forum_id=%s", self.source_type, self.forum_id
        )
        page = self.fetch_with_retry(self.base_url)
        if not page:
            return

        categories = self.extract_categories(page)
        if categories:
            logger.info("Found %d categories", len(categories))
            for cat_url in categories:
                self._crawl_category(cat_url)
        else:
            logger.info("No categories found, crawling base URL as single listing")
            self._crawl_category(self.base_url)
