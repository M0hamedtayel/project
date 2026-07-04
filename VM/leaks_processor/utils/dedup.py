"""
Deduplication utilities.

Uses an in-memory set + optional Elasticsearch-backed registry to prevent
reprocessing the same file twice.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from config.settings import ARCHIVE_ROOT, ELASTICSEARCH_URL, INDEX_PREFIX

logger = logging.getLogger(__name__)

_DEDUP_INDEX = "leaks-dedup-registry"


class DedupRegistry:
    """
    Two-layer dedup:
      1. In-memory set for fast repeat checks within the same daemon session.
      2. Elasticsearch registry for cross-session persistence.
    """

    def __init__(self):
        self._seen: set[str] = set()
        self._es = None
        self._es_available = False
        self._init_es()

    def _init_es(self):
        """Try connecting to Elasticsearch for persistent dedup registry."""
        try:
            import requests
            resp = requests.get(f"{ELASTICSEARCH_URL}/_cluster/health", timeout=3)
            if resp.status_code == 200:
                self._es_available = True
                # Ensure the dedup index exists
                self._ensure_index()
        except Exception:
            logger.warning("Elasticsearch not reachable — dedup will be in-memory only")

    def _ensure_index(self):
        """Create the dedup registry index if it doesn't exist."""
        import requests
        mapping = {
            "mappings": {
                "properties": {
                    "sha256":       {"type": "keyword"},
                    "file_path":    {"type": "keyword"},
                    "breach_name":  {"type": "keyword"},
                    "processed_at": {"type": "date"},
                }
            }
        }
        requests.put(f"{ELASTICSEARCH_URL}/{_DEDUP_INDEX}", json=mapping, timeout=5)

    # ------------------------------------------------------------------
    def is_duplicate(self, sha256_hex: str) -> bool:
        """Check if a file hash has already been processed."""
        # Memory check (fast path)
        if sha256_hex in self._seen:
            return True
        # ES check (slow path — only if in-memory miss)
        if self._es_available:
            import requests
            try:
                resp = requests.get(
                    f"{ELASTICSEARCH_URL}/{_DEDUP_INDEX}/_search",
                    json={
                        "query": {"term": {"sha256": sha256_hex}},
                        "_source": False,
                        "size": 1,
                    },
                    timeout=3,
                )
                if resp.status_code == 200 and resp.json().get("hits", {}).get("total", {}).get("value", 0) > 0:
                    self._seen.add(sha256_hex)
                    return True
            except Exception as exc:
                logger.warning("ES dedup check failed: %s", exc)
        return False

    def mark_processed(self, sha256_hex: str, file_path: str, breach_name: str):
        """Register a file hash as processed."""
        self._seen.add(sha256_hex)
        if self._es_available:
            import requests
            doc = {
                "sha256": sha256_hex,
                "file_path": file_path,
                "breach_name": breach_name,
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                requests.post(
                    f"{ELASTICSEARCH_URL}/{_DEDUP_INDEX}/_doc/{sha256_hex}",
                    json=doc,
                    timeout=5,
                )
            except Exception as exc:
                logger.warning("Failed to persist dedup entry to ES: %s", exc)

    def count(self) -> int:
        """Return number of hashes tracked in memory."""
        return len(self._seen)
