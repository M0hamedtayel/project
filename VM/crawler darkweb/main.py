import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
from datetime import datetime, timezone
from db.connection import get_db, close_connection
from db.queries import get_all_active_forums, create_crawl_log, update_crawl_log
from crawlers.clearnet import ClearnetCrawler
from crawlers.onion import OnionCrawler
from crawlers.darkforums import DarkForumsCrawler
from crawlers.dnaforum import DnaForumCrawler
from crawlers.leakblogs import get_leak_blog_crawler
from config import MAX_WORKERS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("logs/crawler.log"),
        logging.StreamHandler(),
    ],
)

logging.getLogger("scrapling").handlers.clear()
logging.getLogger("scrapling").propagate = False

logger = logging.getLogger(__name__)

CRAWLER_MAP = {
    "clearnet": ClearnetCrawler,
    "onion": OnionCrawler,
}


def _get_crawler(source_type: str, base_url: str):
    domain = urlsplit(base_url).netloc
    if "darkforums" in domain:
        return DarkForumsCrawler
    if "dna" in domain and ".onion" in domain:
        return DnaForumCrawler
    leak_cls = get_leak_blog_crawler(base_url)
    if leak_cls:
        return leak_cls
    return CRAWLER_MAP.get(source_type)


def run_crawler(forum: dict):
    forum_id = forum["_id"]
    source_type = forum.get("forum_type", "clearnet")
    base_url = forum["base_url"]

    crawler_cls = _get_crawler(source_type, base_url)
    if not crawler_cls:
        logger.error("Unknown forum type: %s for forum %s", source_type, base_url)
        return

    log_entry = {
        "forum_id": forum_id,
        "started_at": datetime.now(timezone.utc),
        "status": "running",
        "threads_found": 0,
        "threads_new": 0,
        "threads_skipped": 0,
    }
    log_result = create_crawl_log(log_entry)
    log_id = log_result.inserted_id

    try:
        crawler = crawler_cls(forum_id, base_url)
        crawler.run()
        update_crawl_log(
            log_id,
            {
                "status": "done",
                "finished_at": datetime.now(timezone.utc),
            },
        )
        logger.info("Finished crawling %s (%s)", base_url, source_type)
    except Exception as e:
        logger.error("Crawler failed for %s: %s", base_url, e)
        update_crawl_log(
            log_id,
            {
                "status": "failed",
                "error_msg": str(e),
                "finished_at": datetime.now(timezone.utc),
            },
        )


def ensure_indexes():
    db = get_db()
    db.threads.create_index("dedup_hash", unique=True, sparse=True)
    db.threads.create_index("url", unique=True, sparse=True)
    db.threads.create_index("forum_id")
    db.threads.create_index("crawled_at")
    db.forums.create_index("base_url", unique=True)
    db.crawl_logs.create_index("forum_id")


def main():
    parser = argparse.ArgumentParser(description="Dark Web Monitor Crawler")
    parser.add_argument(
        "--crawler",
        choices=["clearnet", "onion", "all"],
        default="all",
    )
    args = parser.parse_args()

    ensure_indexes()

    forums = get_all_active_forums()
    if not forums:
        logger.warning("No active forums found in database.")
        close_connection()
        return

    filtered = [
        f
        for f in forums
        if args.crawler == "all" or args.crawler == f.get("forum_type", "clearnet")
    ]

    clearnet = [f for f in filtered if f.get("forum_type") != "onion"]
    onion = [f for f in filtered if f.get("forum_type") == "onion"]

    if clearnet:
        workers = min(len(clearnet), MAX_WORKERS)
        logger.info(
            "Starting %d clearnet crawlers (%d workers)", len(clearnet), workers
        )
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(run_crawler, f): f for f in clearnet}
            for future in as_completed(futures):
                future.result()

    if onion:
        logger.info("Starting %d onion crawlers sequentially (1 worker)", len(onion))
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(run_crawler, f): f for f in onion}
            for future in as_completed(futures):
                future.result()

    close_connection()


if __name__ == "__main__":
    main()
