import time
import logging
import re
from abc import ABC, abstractmethod
from urllib.parse import urljoin, urlparse
from crawlers.base import BaseCrawler
from utils.tor_manager import renew_tor_circuit
from config import TOR_SOCKS_PORT, PAGE_TIMEOUT, REQUEST_DELAY, MAX_RETRIES, PROXY_URL

logger = logging.getLogger(__name__)


class LeakBlogCrawler(ABC):
    def __init__(self, forum_id: int, base_url: str):
        self.forum_id = forum_id
        self.base_url = base_url.rstrip("/")
        self.source_type = "onion" if ".onion" in base_url else "clearnet"
        self._request_count = 0
        parsed = urlparse(self.base_url)
        self.root_url = f"{parsed.scheme}://{parsed.netloc}"

    def _abs_url(self, href: str) -> str:
        if href.startswith("http"):
            return href
        return f"{self.root_url}/{href.lstrip('/')}"

    @abstractmethod
    def extract_entries(self, page) -> list[dict]:
        pass

    @abstractmethod
    def extract_content(self, page) -> str:
        pass

    def has_next_page(self, page) -> str | None:
        return None

    def _onion_fetch(self, url: str):
        if self._request_count > 0 and self._request_count % 10 == 0:
            renew_tor_circuit()
            time.sleep(REQUEST_DELAY)
        from playwright.sync_api import sync_playwright
        from scrapling.parser import Selector

        with sync_playwright() as p:
            browser = p.chromium.launch(
                proxy={"server": f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"}
            )
            page = browser.new_page()
            page.goto(url, timeout=PAGE_TIMEOUT)
            html = page.content()
            browser.close()
        return Selector(html)

    def _clearnet_fetch(self, url: str):
        from scrapling.fetchers import StealthyFetcher

        kwargs = {"url": url}
        if PROXY_URL:
            kwargs["proxy"] = PROXY_URL
        return StealthyFetcher.fetch(**kwargs)

    def fetch_page(self, url: str):
        self._request_count += 1
        fn = self._onion_fetch if self.source_type == "onion" else self._clearnet_fetch
        return fn(url)

    def fetch_with_retry(self, url: str):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                page = self.fetch_page(url)
                time.sleep(REQUEST_DELAY)
                return page
            except Exception as e:
                logger.warning("Attempt %d failed for %s: %s", attempt, url, e)
                if attempt < MAX_RETRIES:
                    time.sleep(REQUEST_DELAY)
        logger.error("All %d attempts failed for %s", MAX_RETRIES, url)
        return None

    def run(self):
        self.crawl()

    def crawl(self):
        logger.info("Starting leak blog crawler for %s", self.base_url)
        page = self.fetch_with_retry(self.base_url)
        if not page:
            return

        seen = set()
        page_num = 0
        while page:
            page_num += 1
            entries = self.extract_entries(page)
            logger.info("Page %d: found %d entries", page_num, len(entries))

            for entry in entries:
                title = entry.get("title", "").strip()
                if not title or title.lower() in seen:
                    continue
                seen.add(title.lower())

                detail_url = entry.get("url")
                content_text = entry.get("content", "")
                if detail_url and not content_text:
                    detail_page = self.fetch_with_retry(detail_url)
                    if detail_page:
                        content_text = self.extract_content(detail_page)

                from db.queries import insert_thread
                from utils.dedup import compute_dedup_hash

                dedup_hash = compute_dedup_hash(title, self.forum_id)
                saved = insert_thread(
                    {
                        "url": detail_url or self.base_url,
                        "title": title,
                        "dedup_hash": dedup_hash,
                        "author": entry.get("author", ""),
                        "post_date": entry.get("date", ""),
                        "first_post_content": content_text,
                        "forum_id": self.forum_id,
                        "source_type": self.source_type,
                    }
                )
                if saved:
                    logger.info("[NEW] %s", title[:60])
                else:
                    logger.info("[DUPLICATE] %s", title[:60])

            next_url = self.has_next_page(page)
            if not next_url or page_num >= 200:
                break
            page = self.fetch_with_retry(next_url)


class TIMCCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='rounded'], div[class*='border']"):
            title_el = card.find("h2, h3, a[href*='http']")
            desc_el = card.find("p")
            link_el = card.find("a[href*='http']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("main, article, div[class*='content']")
        return body.get_all_text().strip() if body else ""


class MoneymessageCrawler(LeakBlogCrawler):
    def __init__(self, forum_id: int, base_url: str):
        super().__init__(forum_id, base_url)
        self._page = 1

    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='MuiCard'], div[class*='MuiPaper']"):
            title_el = card.find("h5, h6, span[class*='MuiTypography']")
            desc_el = card.find("p")
            link_el = card.find("a[href]")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": self._abs_url(href) if href else "",
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("main, article, div[class*='content']")
        return body.get_all_text().strip() if body else ""

    def has_next_page(self, page) -> str | None:
        self._page += 1
        if self._page > 3:
            return None
        return f"{self.base_url.rstrip('/')}/news.php?page={self._page}"


class BasheCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css(
            "div[class*='segment'], div[class*='offer'], div[class*='card'], div[class*='box']"
        ):
            title_el = card.find("h2, h3, strong, a[href]")
            desc_el = card.find("p, div[class*='dsc'], div[class*='text']")
            link_el = card.find("a[href*='http']")
            href = link_el.attrib.get("href", "") if link_el else ""
            title = title_el.get_all_text().strip() if title_el else ""
            if title and title not in ("Prices", "Mirrors", "Press about us"):
                entries.append(
                    {
                        "title": title,
                        "url": href,
                        "content": desc_el.get_all_text().strip() if desc_el else "",
                    }
                )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("main, div[class*='main']")
        return body.get_all_text().strip() if body else ""


class PlayNewsCrawler(LeakBlogCrawler):
    def __init__(self, forum_id: int, base_url: str):
        base = base_url.rstrip("/")
        if "/index.php" not in base:
            base = base + "/index.php"
        super().__init__(forum_id, base)
        self._page = 1

    def extract_entries(self, page) -> list[dict]:
        entries = []
        for row in page.css("tr"):
            title_el = row.find("th[class*='News'], th[onclick*='viewtopic']")
            if not title_el:
                continue
            onclick = title_el.attrib.get("onclick", "")
            m = re.search(r"viewtopic\('([^']+)'\)", onclick)
            url = ""
            if m:
                url = self._abs_url(f"../topic.php?id={m.group(1)}")
            title_text = title_el.get_all_text().strip()
            if title_text:
                entries.append(
                    {
                        "title": title_text.split("\n")[0].strip()[:100],
                        "url": url,
                        "content": title_el.get_all_text().strip(),
                    }
                )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("body, main, article")
        return body.get_all_text().strip()[:5000] if body else ""

    def has_next_page(self, page) -> str | None:
        self._page += 1
        if self._page > 24:
            return None
        base = self.base_url.split("?")[0]
        return f"{base}?page={self._page}"


class PearCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("tr"):
            title_el = card.find("p strong")
            desc_el = card.find("p")
            link_el = card.find("a[href*='/Companies/']")
            href = link_el.attrib.get("href", "") if link_el else ""
            title = title_el.get_all_text().strip() if title_el else ""
            if title and len(title) > 3:
                entries.append(
                    {
                        "title": title,
                        "url": self._abs_url(href) if href else "",
                        "content": desc_el.get_all_text().strip() if desc_el else "",
                    }
                )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("body")
        return body.get_all_text().strip()[:5000] if body else ""

    def has_next_page(self, page) -> str | None:
        next_el = page.find("a:has-text('Next'), a:has-text('next'), a:has-text('»')")
        if next_el:
            return self._abs_url(next_el.attrib.get("href", ""))
        return None


class NitrogenCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='w3-card']"):
            title_el = card.find("h3 b")
            desc_el = card.find("p[class*='about']")
            link_el = card.find("a[href*='/posts/']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": self._abs_url(href) if href else "",
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("div[class*='w3-card'], div[class*='content'], article, main")
        return body.get_all_text().strip()[:5000] if body else ""


class DataExposureCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='card']"):
            title_el = card.find("div[class*='title']")
            desc = card.find(
                "div[class*='meta'], div[class*='card-bottom'], span[class*='status']"
            )
            link_el = card.find("[onclick*='/entity/']")
            onclick = link_el.attrib.get("onclick", "") if link_el else ""
            m = re.search(r"window\.open\('([^']+)'", onclick)
            href = m.group(1) if m else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": self._abs_url(href) if href else "",
                    "content": desc.get_all_text().strip() if desc else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("body")
        return body.get_all_text().strip()[:5000] if body else ""


class FileManagerCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("a[class*='card']"):
            name_el = card.find("div[class*='card-name']")
            desc_el = card.find("div[class*='card-desc']")
            price_el = card.find("div[class*='card-stub-label']")
            href = card.attrib.get("href", "")
            content = desc_el.get_all_text().strip() if desc_el else ""
            price = price_el.get_all_text().strip() if price_el else ""
            if price:
                content = f"{content} | Price: {price}"
            entries.append(
                {
                    "title": name_el.get_all_text().strip() if name_el else "",
                    "url": self._abs_url(href) if href else "",
                    "content": content,
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("main, div[class*='content'], body")
        return body.get_all_text().strip()[:5000] if body else ""


class BjorkaCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for item in page.css("li"):
            title_el = item.find("h2")
            price_el = item.find("span[class*='text-blue']")
            author_el = item.find("span[class*='text-gray']")
            date_el = item.find("time")
            link_el = item.find("a[href*='/blog/']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href
                    if href.startswith("http")
                    else f"https://netleaks.net{href}",
                    "author": author_el.get_all_text().strip()
                    if author_el
                    else "Bjorka",
                    "date": date_el.attrib.get("datetime", "") if date_el else "",
                    "content": price_el.get_all_text().strip() if price_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("article, main, div[class*='prose']")
        return body.get_all_text().strip()[:5000] if body else ""


class CmdofficialCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='auction-card']"):
            title_el = card.find("h2 a, h2")
            desc_el = card.find("div[class*='auction-description']")
            price_el = card.find("span[class*='price-value']")
            href = (
                title_el.attrib.get("href", "")
                if title_el and hasattr(title_el, "attrib")
                else ""
            )
            content = desc_el.get_all_text().strip() if desc_el else ""
            price = price_el.get_all_text().strip() if price_el else ""
            if price:
                content = f"{content}\nPrice: {price}"
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": content,
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("main, div[class*='content']")
        return body.get_all_text().strip()[:5000] if body else ""


class KrybitCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css(
            "div[class*='container'] div[style*='background'], div[class*='card']"
        ):
            title_el = card.find("h2, h3, strong")
            desc_el = card.find("p")
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": "",
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("main, body")
        return body.get_all_text().strip()[:5000] if body else ""


class BlackwaterCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for post in page.css("div[class*='post'], article, div[class*='blog']"):
            title_el = post.find("h2, h3, h4, a[href*='http']")
            desc_el = post.find("p")
            link_el = post.find("a[href*='http']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("article, main, div[class*='content'], body")
        return body.get_all_text().strip()[:5000] if body else ""


class Ms13089Crawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for post in page.css("div[class*='post']"):
            title_el = post.find(
                "div[class*='post-title'] div, div[class*='post-top'] div"
            )
            desc_el = post.find("div[class*='post-text']")
            link_el = post.find("a[onclick*='location']")
            onclick = link_el.attrib.get("onclick", "") if link_el else ""
            m = re.search(r"location\.href='([^']+)'", onclick)
            href = m.group(1) if m else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("div[class*='post-body'], main, article")
        return body.get_all_text().strip()[:5000] if body else ""


class NspireCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='team-card'], div[class*='database']"):
            name_el = card.find("a[class*='team-name']")
            desc_el = card.find("p[class*='team-bio']")
            price_el = card.find(
                "span[class*='countdown'], div[style*='background-color']"
            )
            date_el = card.find("p:has-text('🧭')")
            href = (
                name_el.attrib.get("href", "")
                if name_el and hasattr(name_el, "attrib")
                else ""
            )
            content = desc_el.get_all_text().strip() if desc_el else ""
            price = price_el.get_all_text().strip() if price_el else ""
            if price:
                content = f"{content}\n{price}"
            entries.append(
                {
                    "title": name_el.get_all_text().strip() if name_el else "",
                    "url": href,
                    "content": content,
                    "date": date_el.get_all_text().strip() if date_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("body")
        return body.get_all_text().strip()[:5000] if body else ""


class OdayCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='card'], div[class*='post'], article"):
            title_el = card.find("h2, h3, strong, a")
            desc_el = card.find("p")
            link_el = card.find("a[href*='http']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("article, main, body")
        return body.get_all_text().strip()[:5000] if body else ""


class AtomsiloCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='card'], div[class*='post'], li, tr"):
            title_el = card.find("h2, h3, strong, a, td")
            desc_el = card.find("p, div[class*='desc']")
            link_el = card.find("a[href*='http']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("body")
        return body.get_all_text().strip()[:5000] if body else ""


class BoobaCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css(
            "div[class*='card'], div[class*='post'], li, div[class*='leak']"
        ):
            title_el = card.find("h2, h3, strong, a")
            desc_el = card.find("p, div[class*='desc']")
            link_el = card.find("a[href*='http']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("body")
        return body.get_all_text().strip()[:5000] if body else ""


class CardmafiaCrawler(LeakBlogCrawler):
    def extract_entries(self, page) -> list[dict]:
        entries = []
        for card in page.css("div[class*='card'], div[class*='post'], article, tr"):
            title_el = card.find("h2, h3, strong, a, td")
            desc_el = card.find("p, div[class*='desc']")
            link_el = card.find("a[href*='http']")
            href = link_el.attrib.get("href", "") if link_el else ""
            entries.append(
                {
                    "title": title_el.get_all_text().strip() if title_el else "",
                    "url": href,
                    "content": desc_el.get_all_text().strip() if desc_el else "",
                }
            )
        return entries

    def extract_content(self, page) -> str:
        body = page.find("body")
        return body.get_all_text().strip()[:5000] if body else ""


LEAK_BLOG_SITES = {
    "rzzfiwoop67jrxadngcy7nvjm7suwtrjznview63ooowqfsm5sq7gmqd": (
        "TIMC Leak List",
        TIMCCrawler,
    ),
    "blogvl7tjyjvsfthobttze52w36wwiz34hrfcmorgvdzb6hikucb7aqd": (
        "MONEYMESSAGE Leak Blog",
        MoneymessageCrawler,
    ),
    "basheqtvzqwz4vp6ks5lm2ocq7i6tozqgf6vjcasj4ezmsy4bkpshhyd": (
        "BASHE Leak List",
        BasheCrawler,
    ),
    "j75o7xvvsm4lpsjhkjvb4wl2q6ajegvabe6oswthuaubbykk4xkzgpid": (
        "PLAY NEWS Leak Blog",
        PlayNewsCrawler,
    ),
    "peargxn3oki34c4savcbcfqofjjwjnnyrlrbszfv6ujlx36mhrh57did": (
        "PEAR Leak List",
        PearCrawler,
    ),
    "nitrogenczslprh3xyw6lh5xyjvmsz7ciljoqxxknd7uymkfetfhgvqd": (
        "Nitrogen Ransomware Blog",
        NitrogenCrawler,
    ),
    "6tdqqaxftvradka5d2frzgwixis7fmro7rfh4ettzcx7jfapkebe6jad": (
        "DATA EXPOSURE Terminal",
        DataExposureCrawler,
    ),
    "t33zoj4qwv455fog7qnb2azi5xcdxkixughmmduzbw2rtdgryqfbh6id": (
        "File Manager Leaks",
        FileManagerCrawler,
    ),
    "netleaks.net": ("Bjorka Databases", BjorkaCrawler),
    "cmdofficial.com": ("CMD Official Auctions", CmdofficialCrawler),
    "krybitx3fh5krdnhegyp2ob3lhizsaiadturtio3ginf7it5gsdgu2yd": (
        "KRYBIT Leak List",
        KrybitCrawler,
    ),
    "ejzl7cjxmkx7lzhiqwidmrwtfjv45pkczbc4fnyaut3t7gll3yaiq5id": (
        "BLACKWATER Leak Blog",
        BlackwaterCrawler,
    ),
    "msleakjir7pxbe6onlqe5uwgvdmy6nq4mnwfy7ojswbhnleenm77vgad": (
        "MS13-089 Leak Blog",
        Ms13089Crawler,
    ),
    "nspirep7orjq73k2x2fwh2mxgh74vm2now6cdbnnxjk2f5wn34bmdxad": (
        "NSPIRE RaaS Leaks",
        NspireCrawler,
    ),
    "odaygplp3zhyx7zl45egetl6dzc4reduisnoyym34rjdmaryfaz5doqd": (
        "0day Leak List",
        OdayCrawler,
    ),
    "npmh5ahrgakbniuntyc7io4adm6ietbdbuejrfonowqtyqn24or556qd": (
        "Atomsilo Leak List",
        AtomsiloCrawler,
    ),
    "7t3zi3e7ki6iseun77ofqtr6wmbpgnpc2ada6gstcxp54lw6q2zb7jad": (
        "Booba Team Leaks",
        BoobaCrawler,
    ),
    "cardmafia.net": ("CardMafia Leaks", CardmafiaCrawler),
}


def get_leak_blog_crawler(base_url: str):
    domain = urlparse(base_url).netloc.lower()
    for key, (name, cls) in LEAK_BLOG_SITES.items():
        if key in domain:
            logger.info("Matched leak blog site: %s (%s)", name, domain)
            return cls
    return None
