from db.connection import get_db


def get_forum_by_url(url: str) -> dict | None:
    db = get_db()
    return db.forums.find_one({"base_url": url})


def get_all_active_forums() -> list[dict]:
    db = get_db()
    return list(db.forums.find({"is_active": True}))


def insert_thread(thread_data: dict) -> bool:
    db = get_db()
    try:
        db.threads.insert_one(thread_data)
        return True
    except Exception:
        return False


def thread_exists_by_hash(dedup_hash: str) -> bool:
    db = get_db()
    return db.threads.find_one({"dedup_hash": dedup_hash}) is not None


def create_crawl_log(log_data: dict) -> object:
    db = get_db()
    return db.crawl_logs.insert_one(log_data)


def update_crawl_log(log_id: object, update: dict):
    db = get_db()
    db.crawl_logs.update_one({"_id": log_id}, {"$set": update})
