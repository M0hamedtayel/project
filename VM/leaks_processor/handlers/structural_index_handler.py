"""
Structural index handler — indexes breach directory trees into Elasticsearch.

For complex multi-file breaches (Udemy, паспорта RU, sample), this module walks
the entire directory tree **before** file-level parsing and indexes the structure.

This enables forensic investigators to understand the full scope of a leak
even before all files are processed.
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from config.settings import STRUCTURAL_SKIP_DIRS, ARCHIVE_ROOT
from utils.index_utils import ensure_index, bulk_upload, STRUCTURAL_INDEX_MAPPING

logger = logging.getLogger(__name__)

BULK_BATCH_SIZE = 500


def walk_and_index(breach_root: str, breach_name: str,
                   pasporta_mode: bool = False) -> dict:
    """
    Walk a breach directory tree and index every file and subdirectory.

    Args:
        breach_root: Absolute path to the breach root directory.
        breach_name: Sanitized breach name for the index.
        pasporta_mode: If True, extract city_region from parent directory name
                        and use simplified indexing (passports RU).

    Returns:
        Stats dict with file_count, dir_count, total_indexed, ok, fail.
    """
    index_name = f"leaks-structure-{breach_name}"
    ensure_index(index_name, STRUCTURAL_INDEX_MAPPING)

    root_path = Path(breach_root)
    now = datetime.now(timezone.utc).isoformat()

    if root_path.is_file():
        # Single-file mode: strictly restrict scope to this file only (Scope Lock)
        try:
            file_size = os.path.getsize(root_path)
        except OSError:
            file_size = 0
            
        doc = {
            "structural_id": str(uuid.uuid4()),
            "breach_source": breach_name,
            "relative_path": root_path.name,
            "filename": root_path.name,
            "extension": root_path.suffix.lower(),
            "file_size_bytes": file_size,
            "parent_directory": str(root_path.parent.name),
            "depth_level": 0,
            "is_directory": False,
            "estimated_type": root_path.suffix.lower().lstrip("."),
            "processing_status": "pending",
            "indexed_at": now,
        }
        bulk_upload(index_name, [doc], id_field="structural_id")
        logger.info("Structural index for single file '%s' complete: %s", root_path.name, index_name)
        return {
            "breach_name": breach_name,
            "index_name": index_name,
            "file_count": 1,
            "dir_count": 0,
            "total_indexed": 1,
            "pasporta_mode": pasporta_mode,
        }

    if not root_path.is_dir():
        logger.error("Breach root not found or is invalid: %s", breach_root)
        return {"error": "breach_root_not_found", "path": breach_root}

    docs = []
    file_count = 0
    dir_count = 0
    now = datetime.now(timezone.utc).isoformat()

    for entry in root_path.rglob("*"):
        # Skip symlink cycles and unreadable entries
        if entry.is_symlink():
            continue

        # Skip configured directories
        if any(skip in entry.parts for skip in STRUCTURAL_SKIP_DIRS):
            continue

        try:
            is_dir = entry.is_dir()
        except OSError:
            continue

        # Calculate relative path from breach root
        try:
            relative_path = str(entry.relative_to(root_path))
        except ValueError:
            continue

        # Extract city_region for паспорта mode
        city_region = None
        if pasporta_mode and not is_dir:
            # city_region = immediate parent directory name
            city_region = entry.parent.name

        # Calculate depth level (0 = breach root itself)
        depth_level = len(entry.relative_to(root_path).parts)
        if is_dir:
            depth_level -= 1  # directory itself counts as one level less

        # Get file size
        file_size = 0
        if not is_dir:
            try:
                file_size = os.path.getsize(entry)
            except OSError:
                file_size = 0

        # Count children for directories
        child_count = 0
        total_size = 0
        if is_dir:
            try:
                children = list(entry.iterdir())
                child_count = len(children)
                total_size = sum(
                    os.path.getsize(c) for c in children
                    if c.is_file()
                )
            except OSError:
                child_count = 0

        doc = {
            "structural_id": str(uuid.uuid4()),
            "breach_source": breach_name,
            "relative_path": relative_path,
            "filename": entry.name,
            "extension": entry.suffix.lower() if not is_dir else None,
            "file_size_bytes": file_size if not is_dir else total_size,
            "parent_directory": str(entry.parent.name),
            "depth_level": depth_level,
            "is_directory": is_dir,
            "estimated_type": entry.suffix.lower().lstrip(".") if not is_dir else None,
            "processing_status": "pending",
            "indexed_at": now,
        }

        if city_region:
            doc["city_region"] = city_region
        if is_dir:
            doc["child_count"] = child_count

        docs.append(doc)

        if is_dir:
            dir_count += 1
        else:
            file_count += 1

        # Bulk upload in batches
        if len(docs) >= BULK_BATCH_SIZE:
            ok, fail = bulk_upload(index_name, docs, id_field="structural_id")
            docs.clear()

    # Flush remaining docs
    if docs:
        ok, fail = bulk_upload(index_name, docs, id_field="structural_id")
        docs.clear()
    else:
        ok, fail = 0, 0

    total = file_count + dir_count
    logger.info(
        "Structural index for '%s' complete: %d files, %d dirs → %s",
        breach_name, file_count, dir_count, index_name,
    )

    return {
        "breach_name": breach_name,
        "index_name": index_name,
        "file_count": file_count,
        "dir_count": dir_count,
        "total_indexed": total,
        "pasporta_mode": pasporta_mode,
    }


def walk_pasporta(breach_root: str) -> dict:
    """
    Convenience wrapper for паспорта RU datasets.
    Uses pasporta_mode=True for city_region extraction.
    """
    return walk_and_index(
        breach_root, "ru-pasporta", pasporta_mode=True,
    )
