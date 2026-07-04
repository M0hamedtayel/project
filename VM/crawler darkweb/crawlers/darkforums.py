from crawlers.base import BaseCrawler
from config import PROXY_URL
from utils.cookie_manager import load_cookies


class DarkForumsCrawler(BaseCrawler):
    def __init__(self, forum_id: int, base_url: str):
        super().__init__(forum_id, base_url, source_type="clearnet")
        self._cookies = load_cookies("darkforums.su")

    def fetch_page(self, url: str):
        from scrapling.fetchers import StealthyFetcher
        kwargs = {"url": url}
        if PROXY_URL:
            kwargs["proxy"] = PROXY_URL
        if self._cookies:
            kwargs["cookies"] = self._cookies
        return StealthyFetcher.fetch(**kwargs)

    def extract_categories(self, page) -> list[str]:
        cats = set()
        for table in page.css("table.tborder"):
            for a in table.css("a[href*='Forum-']"):
                href = a.attrib.get("href", "")
                if href and href.startswith("Forum-"):
                    clean = href.split("?")[0]
                    cats.add(self._abs_url(clean))
        return list(cats)

    def extract_threads_from_listing(self, page) -> list[dict]:
        threads = []
        for row in page.css("tr.inline_row"):
            title_el = row.find("span.subject_new a")
            if not title_el:
                title_el = row.find("a[href*='Thread-']")
            if not title_el:
                continue
            href = title_el.attrib.get("href", "")
            url = self._abs_url(href).split("?")[0]

            author_el = row.find("span.author.smalltext a")
            date_el = row.find("span.forum-display__thread-date")

            threads.append({
                "url": url,
                "title": title_el.get_all_text().strip() if title_el else "",
                "author": author_el.get_all_text().strip() if author_el else "",
                "post_date": date_el.get_all_text().strip() if date_el else None,
            })
        return threads

    def extract_first_post(self, page) -> str:
        body = page.find("div.post_body")
        return body.get_all_text().strip() if body else ""

    def has_next_page(self, page) -> str | None:
        pagination = page.find(".pagination")
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
