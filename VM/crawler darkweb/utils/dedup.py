import hashlib


def compute_dedup_hash(title: str, forum_id: int) -> str:
    raw = f"{title.lower().strip()}|{forum_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
