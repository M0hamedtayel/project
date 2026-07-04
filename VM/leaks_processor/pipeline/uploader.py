"""
Batch Elasticsearch uploader.

Buffers normalized documents and flushes them to ES in bulk batches.
Ensures the target index exists with the correct mapping before uploading.
Reports success/failure counts and patches structural docs on completion.
"""

import logging
import time
from typing import Any

from utils.index_utils import (
    ensure_index, bulk_upload, patch_structural_status,
    TRANSACTION_INDEX_MAPPING, STRUCTURAL_INDEX_MAPPING,
    IDENTITY_INDEX_MAPPING, MAPPING_REGISTRY,
)
from config.settings import INDEX_PREFIX, BULK_BATCH_SIZE

logger = logging.getLogger(__name__)



class BatchUploader:
    """
    Buffers normalized documents and uploads them to Elasticsearch in bulk.
    """

    def __init__(self, index_name: str, mapping_type: str = "identity",
                 id_field: str | None = None):
        """
        Args:
            index_name: Target Elasticsearch index name.
            mapping_type: Key into MAPPING_REGISTRY ("identity", "transaction", "structural").
            id_field: Field name to use as ES _id for dedup/upsert.
        """
        self.index_name = index_name
        self.mapping_type = mapping_type
        self.id_field = id_field
        self._buffer: list[dict] = []
        self._total_sent = 0
        self._total_ok = 0
        self._total_fail = 0

    def add(self, doc: dict):
        """Add a document to the buffer. Auto-flushes when buffer reaches BULK_BATCH_SIZE."""
        # Strip the _index hint from doc (we pass index separately to bulk_upload)
        doc_copy = {k: v for k, v in doc.items() if k != "_index"}
        self._buffer.append(doc_copy)

        if len(self._buffer) >= BULK_BATCH_SIZE:
            self.flush()

    def flush(self) -> tuple[int, int]:
        """
        Upload all buffered documents to ES.

        Returns:
            Tuple of (ok_count, fail_count) for this flush.
        """
        if not self._buffer:
            return 0, 0

        # Ensure index exists
        mapping = MAPPING_REGISTRY.get(self.mapping_type)
        ensure_index(self.index_name, mapping)

        ok, fail = bulk_upload(
            self.index_name, self._buffer,
            id_field=self.id_field, timeout=120,
        )

        self._total_sent += len(self._buffer)
        self._total_ok += ok
        self._total_fail += fail

        logger.info(
            "Flushed %d docs to %s: %d ok, %d fail (total: %d sent, %d ok, %d fail)",
            len(self._buffer), self.index_name, ok, fail,
            self._total_sent, self._total_ok, self._total_fail,
        )

        self._buffer.clear()
        return ok, fail

    def flush_final(self) -> tuple[int, int]:
        """Final flush — upload any remaining buffered docs."""
        return self.flush()

    @property
    def stats(self) -> dict[str, int]:
        """Return upload statistics."""
        return {
            "total_sent": self._total_sent,
            "total_ok": self._total_ok,
            "total_fail": self._total_fail,
            "buffer_remaining": len(self._buffer),
        }

    def patch_status(self, relative_path: str, status: str):
        """
        Update the processing_status of a structural document for this file.
        """
        structural_index = self.index_name.replace(
            f"{INDEX_PREFIX}", f"{INDEX_PREFIX}structure-"
        )
        patch_structural_status(structural_index, relative_path, status)


def upload_batch(documents: list[dict], index_name: str,
                 mapping_type: str = "identity",
                 id_field: str | None = None) -> dict[str, int]:
    """
    Convenience function: upload a list of documents in one call.

    Args:
        documents: List of ES-ready dicts (may contain _index hints).
        index_name: Target ES index.
        mapping_type: Mapping type key.
        id_field: Field to use as _id.

    Returns:
        Stats dict with total_sent, total_ok, total_fail.
    """
    uploader = BatchUploader(index_name, mapping_type, id_field)
    for doc in documents:
        uploader.add(doc)
    uploader.flush_final()
    return uploader.stats
