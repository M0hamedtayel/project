import time
from playwright.sync_api import sync_playwright
from scrapling.parser import Selector
from crawlers.base import BaseCrawler
from utils.tor_manager import renew_tor_circuit
from config import TOR_SOCKS_PORT, PAGE_TIMEOUT, REQUEST_DELAY


class OnionCrawler(BaseCrawler):
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
        cats = []
        for table in page.css("table.forums__bit"):
            for a in table.css("a[href*='Forum-']"):
                href = a.attrib.get("href", "")
                if href:
                    cats.append(self._abs_url(href))
        return list(dict.fromkeys(cats))

    def extract_threads_from_listing(self, page) -> list[dict]:
        threads = []
        for row in page.css("tr.inline_row"):
            title_el = row.find("a.forum-display__thread-name")
            if not title_el:
                continue
            href = title_el.attrib.get("href", "")
            url = self._abs_url(href).split("?")[0]

            author_el = row.find("span.author.smalltext a")
            date_el = row.find("span.forum-display__thread-date")

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
        body = page.find("div.post_body")
        return body.get_all_text().strip() if body else ""

    def has_next_page(self, page) -> str | None:
        pagination = page.find(
            ".pagination, .pagination-links, .pagenav, div[class*='pagination']"
        )
        if not pagination:
            pagination = page
        for a in pagination.css("a[href*='page=']"):
            text = (a.text or "").strip()
            if "next" in text.lower() or text in ("»", "›"):
                return self._abs_url(a.attrib.get("href", ""))
        last_link = None
        for a in pagination.css("a[href*='page=']"):
            last_link = a
        if last_link:
            return self._abs_url(last_link.attrib.get("href", ""))
        return None
