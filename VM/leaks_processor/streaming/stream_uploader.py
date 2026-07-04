"""
Stream uploader — real-time Elasticsearch uploader with internal buffer.

Designed for the live streaming pipeline:
  - Buffers records in memory (max STREAM_BUFFER_SIZE)
  - Flushes on buffer full OR time interval elapsed
  - Uses ES _bulk API for efficiency
  - Retry with exponential backoff on ES errors
  - Spill-to-disk on persistent ES failure (at-least-once delivery)
  - Spill file recovery on startup

Spill file location: /vols/archive_leaks/spill/{index}/{timestamp}.jsonl
"""

import json
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests

from config.settings import (
    STREAM_BUFFER_SIZE, STREAM_FLUSH_INTERVAL_SECS,
    STREAM_RETRY_ATTEMPTS, STREAM_RETRY_BACKOFF_BASE,
    STREAM_SPILL_DIR, ELASTICSEARCH_URL,
)
from utils.index_utils import ensure_index, TRANSACTION_INDEX_MAPPING, IDENTITY_INDEX_MAPPING

logger = logging.getLogger(__name__)


class StreamUploader:
    """
    Real-time ES uploader with buffer, flush, retry, and spill-to-disk.

    Usage:
        uploader = StreamUploader("leaks-udemy-transactions-live")
        uploader.add(doc)          # buffer
        # auto-flush when buffer full or time elapsed
        uploader.flush()           # manual final flush
    """

    def __init__(self, index_name: str, mapping_type: str = "transaction"):
        self.index_name = index_name
        self.mapping_type = mapping_type
        self._buffer: deque = deque(maxlen=STREAM_BUFFER_SIZE)
        self._last_flush_time: float = time.time()
        self._total_uploaded: int = 0
        self._total_failed: int = 0
        self._upload_callbacks: list[Callable] = []

        # Ensure index exists
        mapping = TRANSACTION_INDEX_MAPPING if mapping_type == "transaction" else IDENTITY_INDEX_MAPPING
        ensure_index(index_name, mapping)

        # Ensure spill directory exists
        os.makedirs(STREAM_SPILL_DIR, exist_ok=True)

        # Recover any existing spill files before starting
        self._recover_spill_files()

    def add_upload_callback(self, callback: Callable):
        """Register a callback to be called after each successful flush."""
        self._upload_callbacks.append(callback)

    def add(self, doc: dict):
        """
        Add a document to the buffer.
        Auto-flushes if buffer is full or flush interval has elapsed.
        """
        self._buffer.append(doc)

        # Check flush triggers
        should_flush = False

        # Trigger 1: Buffer full
        if len(self._buffer) >= STREAM_BUFFER_SIZE:
            should_flush = True

        # Trigger 2: Time interval elapsed
        if time.time() - self._last_flush_time >= STREAM_FLUSH_INTERVAL_SECS:
            should_flush = True

        if should_flush:
            self.flush()

    def flush(self) -> tuple[int, int]:
        """
        Flush all buffered documents to Elasticsearch.

        Returns:
            Tuple of (ok_count, fail_count) for this flush.
        """
        if not self._buffer:
            return 0, 0

        docs = list(self._buffer)
        self._buffer.clear()
        self._last_flush_time = time.time()

        # Build NDJSON bulk payload
        ndjson_lines = []
        for doc in docs:
            # Use purchase_reference_id as _id for dedup if available
            doc_id = doc.get("extra_data", {}).get("purchase_ref")
            action = {"index": {"_index": self.index_name}}
            if doc_id:
                action["index"]["_id"] = str(doc_id)

            ndjson_lines.append(json.dumps(action))
            ndjson_lines.append(json.dumps(doc, default=str))

        payload = "\n".join(ndjson_lines) + "\n"

        # Upload with retry
        ok, fail = self._upload_with_retry(payload, docs)

        self._total_uploaded += ok
        self._total_failed += fail

        if ok > 0:
            logger.debug("Stream flush: %d ok, %d fail → %s", ok, fail, self.index_name)

        # Notify callbacks
        for callback in self._upload_callbacks:
            try:
                callback(ok, fail)
            except Exception as exc:
                logger.warning("Upload callback error: %s", exc)

        return ok, fail

    def _upload_with_retry(self, payload: str, docs: list[dict]) -> tuple[int, int]:
        """
        Upload to ES with exponential backoff retry.
        On persistent failure, spill to disk.
        """
        for attempt in range(STREAM_RETRY_ATTEMPTS):
            try:
                resp = requests.post(
                    f"{ELASTICSEARCH_URL}/_bulk",
                    data=payload,
                    headers={"Content-Type": "application/x-ndjson"},
                    timeout=10,
                )

                if resp.status_code == 200:
                    result = resp.json()
                    ok, fail = _parse_bulk_response(result)
                    return ok, fail

                # ES returned non-200 — retry
                logger.warning(
                    "ES bulk error (attempt %d/%d): HTTP %d",
                    attempt + 1, STREAM_RETRY_ATTEMPTS, resp.status_code,
                )

            except requests.exceptions.ConnectionError:
                logger.warning(
                    "ES connection failed (attempt %d/%d)",
                    attempt + 1, STREAM_RETRY_ATTEMPTS,
                )
            except requests.exceptions.Timeout:
                logger.warning(
                    "ES timeout (attempt %d/%d)",
                    attempt + 1, STREAM_RETRY_ATTEMPTS,
                )
            except Exception as exc:
                logger.error(
                    "Unexpected upload error (attempt %d/%d): %s",
                    attempt + 1, STREAM_RETRY_ATTEMPTS, exc,
                )

            # Exponential backoff
            backoff = STREAM_RETRY_BACKOFF_BASE * (2 ** attempt)
            time.sleep(backoff)

        # All retries failed — spill to disk
        self._spill_to_disk(docs)
        return 0, len(docs)

    def _spill_to_disk(self, docs: list[dict]):
        """
        Write failed documents to a spill file for later recovery.
        """
        spill_index_dir = os.path.join(STREAM_SPILL_DIR, self.index_name)
        os.makedirs(spill_index_dir, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        spill_file = os.path.join(spill_index_dir, f"{timestamp}.jsonl")

        try:
            with open(spill_file, "w", encoding="utf-8") as f:
                for doc in docs:
                    f.write(json.dumps(doc, default=str) + "\n")
            logger.warning(
                "Spilled %d docs to %s (ES unreachable)",
                len(docs), spill_file,
            )
        except Exception as exc:
            logger.error("Failed to write spill file %s: %s", spill_file, exc)

    def _recover_spill_files(self):
        """
        Scan for and re-upload any existing spill files from previous sessions.
        Files are deleted only after confirmed ES upload.
        """
        spill_index_dir = os.path.join(STREAM_SPILL_DIR, self.index_name)
        if not os.path.exists(spill_index_dir):
            return

        spill_files = sorted(Path(spill_index_dir).glob("*.jsonl"))
        if not spill_files:
            return

        logger.info("Recovering %d spill file(s) for %s", len(spill_files), self.index_name)

        for spill_file in spill_files:
            try:
                with open(spill_file, "r", encoding="utf-8") as f:
                    docs = [json.loads(line) for line in f if line.strip()]

                if not docs:
                    spill_file.unlink()
                    continue

                # Build bulk payload
                ndjson_lines = []
                for doc in docs:
                    doc_id = doc.get("extra_data", {}).get("purchase_ref")
                    action = {"index": {"_index": self.index_name}}
                    if doc_id:
                        action["index"]["_id"] = str(doc_id)
                    ndjson_lines.append(json.dumps(action))
                    ndjson_lines.append(json.dumps(doc, default=str))

                payload = "\n".join(ndjson_lines) + "\n"

                resp = requests.post(
                    f"{ELASTICSEARCH_URL}/_bulk",
                    data=payload,
                    headers={"Content-Type": "application/x-ndjson"},
                    timeout=30,
                )

                if resp.status_code == 200:
                    ok, fail = _parse_bulk_response(resp.json())
                    logger.info(
                        "Spill recovery: %s → %d ok, %d fail",
                        spill_file.name, ok, fail,
                    )
                    # Delete spill file on successful upload
                    spill_file.unlink()
                else:
                    logger.warning(
                        "Spill recovery failed for %s: HTTP %d",
                        spill_file.name, resp.status_code,
                    )

            except Exception as exc:
                logger.error("Spill recovery error for %s: %s", spill_file.name, exc)

    @property
    def stats(self) -> dict:
        """Return current uploader statistics."""
        return {
            "total_uploaded": self._total_uploaded,
            "total_failed": self._total_failed,
            "buffer_size": len(self._buffer),
            "index_name": self.index_name,
        }


def _parse_bulk_response(result: dict) -> tuple[int, int]:
    """Parse an ES bulk response and count ok/fail items."""
    ok = 0
    fail = 0
    for item in result.get("items", []):
        status = list(item.values())[0].get("status", 0)
        if 200 <= status < 300:
            ok += 1
        else:
            fail += 1
    return ok, fail
