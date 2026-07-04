"""
Forensic asset handler — metadata-only indexer for binary files.

For files that cannot be text-parsed (PDFs, images, DOCXs, XLSXs, etc.),
this handler creates a structural document containing only file metadata
(filename, size, path, extension) and indexes it into Elasticsearch.

No content extraction, no OCR, no image opening — metadata only.
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from utils.index_utils import ensure_index, bulk_upload, STRUCTURAL_INDEX_MAPPING

logger = logging.getLogger(__name__)


def handle_forensic_asset(file_path: str, breach_name: str,
                          city_region: str | None = None,
                          parent_index: str | None = None) -> dict:
    """
    Index a forensic/binary file as a metadata-only document.

    Args:
        file_path: Absolute path to the binary file.
        breach_name: Sanitized breach source name.
        city_region: Optional region/city name (for паспорта RU).
        parent_index: Override index name (default: ``leaks-assets-{breach_name}```).

    Returns:
        Dict with status and indexed document info.
    """
    path = Path(file_path)
    index_name = parent_index or f"leaks-assets-{breach_name}"

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0

    doc = {
        "asset_id": str(uuid.uuid4()),
        "breach_source": breach_name,
        "relative_path": path.name,
        "absolute_path": file_path,
        "filename": path.name,
        "extension": path.suffix.lower(),
        "file_size_bytes": file_size,
        "parent_directory": str(path.parent.name),
        "depth_level": len(path.parts) - 1,
        "is_directory": False,
        "estimated_type": path.suffix.lower().lstrip("."),
        "processing_status": "forensic_asset",
        "indexed_at": datetime.now(timezone.utc).isoformat(),
    }

    if city_region:
        doc["city_region"] = city_region

    # Ensure index and upload
    ensure_index(index_name, STRUCTURAL_INDEX_MAPPING)
    ok, fail = bulk_upload(index_name, [doc], id_field="asset_id")

    if ok > 0:
        logger.info(
            "Forensic asset indexed: %s → %s (%s bytes)",
            path.name, index_name, file_size,
        )
        return {"status": "ok", "doc_id": doc["asset_id"], "index": index_name}
    else:
        logger.error("Failed to index forensic asset: %s", path.name)
        return {"status": "failed", "reason": "bulk_upload_error"}


def handle_forensic_batch(file_paths: list[str], breach_name: str,
                          city_region: str | None = None,
                          index_name: str | None = None) -> dict:
    """
    Index multiple forensic files in one bulk call.

    Args:
        file_paths: List of absolute file paths.
        breach_name: Sanitized breach source name.
        city_region: Optional region/city name.
        index_name: Override index name.

    Returns:
        Stats dict with total, ok, fail counts.
    """
    index_name = index_name or f"leaks-assets-{breach_name}"
    docs = []

    for file_path in file_paths:
        path = Path(file_path)
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            file_size = 0

        doc = {
            "asset_id": str(uuid.uuid4()),
            "breach_source": breach_name,
            "relative_path": path.name,
            "absolute_path": file_path,
            "filename": path.name,
            "extension": path.suffix.lower(),
            "file_size_bytes": file_size,
            "parent_directory": str(path.parent.name),
            "depth_level": len(path.parts) - 1,
            "is_directory": False,
            "estimated_type": path.suffix.lower().lstrip("."),
            "processing_status": "forensic_asset",
            "indexed_at": datetime.now(timezone.utc).isoformat(),
        }
        if city_region:
            doc["city_region"] = city_region
        docs.append(doc)

    ensure_index(index_name, STRUCTURAL_INDEX_MAPPING)
    ok, fail = bulk_upload(index_name, docs, id_field="asset_id")

    logger.info(
        "Forensic batch: %d files → %s (%d ok, %d fail)",
        len(file_paths), index_name, ok, fail,
    )
    return {"total": len(file_paths), "ok": ok, "fail": fail}
