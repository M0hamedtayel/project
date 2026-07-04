import logging
from datetime import datetime, timezone
from db.connection import get_db, close_connection
from db.leaks_connection import get_leaks_db, close_leaks_connection
from utils.leak_detector import check_thread

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def ensure_indexes():
    ldb = get_leaks_db()
    ldb.flagged_threads.create_index("dedup_hash", unique=True, sparse=True)
    ldb.flagged_threads.create_index("reviewed")


def main():
    ensure_indexes()

    src_db = get_db()
    dst_db = get_leaks_db()

    total = src_db.threads.count_documents({})
    already = dst_db.flagged_threads.count_documents({})
    new_count = 0
    skipped = 0

    logger.info("Scanning %d threads for leaked data...", total)

    for thread in src_db.threads.find().sort("_id", 1):
        dedup = thread.get("dedup_hash")
        if not dedup:
            skipped += 1
            continue

        if dst_db.flagged_threads.find_one({"dedup_hash": dedup}):
            continue

        title = thread.get("title", "")
        content = thread.get("first_post_content", "")
        matched = check_thread(title, content)

        if not matched:
            continue

        flagged = {
            "dedup_hash": dedup,
            "original_id": thread["_id"],
            "forum_id": thread.get("forum_id"),
            "url": thread.get("url"),
            "title": title,
            "author": thread.get("author"),
            "post_date": thread.get("post_date"),
            "first_post_content": content,
            "source_type": thread.get("source_type"),
            "crawled_at": thread.get("crawled_at"),
            "matched_keywords": matched,
            "flagged_at": datetime.now(timezone.utc),
            "reviewed": False,
        }

        try:
            dst_db.flagged_threads.insert_one(flagged)
            new_count += 1
        except Exception:
            skipped += 1

    close_connection()
    close_leaks_connection()

    logger.info("")
    logger.info("Done — %d total, %d already flagged, %d new, %d skipped",
                total, already, new_count, skipped)


if __name__ == "__main__":
    main()
