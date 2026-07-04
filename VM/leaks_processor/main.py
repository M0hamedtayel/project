#!/usr/bin/env python3
"""
Breach Processing Engine — Main Entry Point

RabbitMQ consumer daemon that orchestrates the full ingestion pipeline:
  1. Receive message from ingest_queue
  2. Structural index pass (first time per breach)
  3. SHA-256 dedup check
  4. Classify file type → route to correct parser
  5. Parse → Normalize → Upload to Elasticsearch
  6. Handle archives (extract, re-queue, forensic asset)
  7. Handle forensic/binary files (metadata-only index)

Usage:
    python main.py                    # Start daemon (RabbitMQ consumer)
    python main.py --scan <path>      # One-shot scan of a directory
    python main.py --file <path>      # One-shot process a single file
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (
    RABBITMQ_URL, INGEST_QUEUE, DEAD_LETTER_QUEUE,
    ARCHIVE_ROOT, INDEX_PREFIX,
    SQL_CHUNK_SIZE, SQL_MAX_ROW_BYTES, SQL_MAX_ROWS_PER_TABLE,
    SQL_TABLE_INDEX_ROUTING,
)
from utils.hash_utils import file_sha256
from utils.dedup import DedupRegistry
from utils.index_utils import ensure_index, patch_structural_status
from pipeline.classifier import classify, ClassificationResult
from pipeline.normalizer import normalize_batch, normalize_single
from pipeline.uploader import BatchUploader
from handlers.forensic_asset_handler import handle_forensic_asset
from handlers.structural_index_handler import walk_and_index, walk_pasporta
from extractors.archive_extractor import extract

logger = logging.getLogger("breach_processor")

# Track which breaches have had structural indexing done
_structured_breaches: set[str] = set()

# Dedup registry (shared across all workers)
_dedup = DedupRegistry()

# ======================================================================
# Auto-recovery configuration
# ======================================================================

# If the ratio of skipped records exceeds this threshold after a first pass,
# the schema agent is invoked to learn column mappings and the file is
# re-processed exactly once with the updated aliases.
_SKIP_RATE_THRESHOLD = 0.60   # 60 % skipped → trigger recovery
_MAX_RECOVERY_ATTEMPTS = 1    # never loop more than once per file


def _skip_rate(parsed: int, skipped: int) -> float:
    """Return the fraction of parsed records that were dropped by the normalizer."""
    return skipped / parsed if parsed > 0 else 0.0


def clean_breach_name(name: str) -> str:
    """
    Clean the breach name to be a safe, Elasticsearch-compatible index name.
    """
    import re
    # Remove file extensions completely
    stem = Path(name).name
    while '.' in stem:
        stem = stem.rsplit('.', 1)[0]
    
    # Strip [HASH] / [NOHASH] tags
    stem = re.sub(r"\[.*?\]", "", stem)
    
    # Lowercase
    cleaned = stem.lower()
    
    # Replace non-alphanumeric/hyphen/underscore with hyphens
    cleaned = re.sub(r"[^a-z0-9_-]", "-", cleaned)
    
    # Replace underscores with hyphens to be cleaner
    cleaned = cleaned.replace("_", "-")
    
    # Deduplicate hyphens
    cleaned = re.sub(r"-+", "-", cleaned)
    
    # Strip leading/trailing hyphens/underscores
    cleaned = cleaned.strip("-").strip("_")
    
    if not cleaned:
        cleaned = "general"
        
    return cleaned


# ======================================================================
# Core processing function
# ======================================================================

def process_file(file_path: str, breach_name: str,
                 options: dict | None = None) -> dict:
    """
    Process a single file through the full pipeline.

    Args:
        file_path: Absolute path to the file.
        breach_name: Sanitized breach source name.
        options: Optional dict with processing hints
                 (from_archive, archive, depth, needs_ai).

    Returns:
        Result dict with status, counts, and timing info.
    """
    breach_name = clean_breach_name(breach_name)
    options = options or {}
    start_time = time.time()
    result = {
        "file_path": file_path,
        "breach_name": breach_name,
        "status": "unknown",
        "records_parsed": 0,
        "records_indexed": 0,
        "records_failed": 0,
        "processing_time_ms": 0,
    }

    path = Path(file_path)

    # Validate file exists
    if not path.exists():
        result["status"] = "file_not_found"
        return result

    # ------------------------------------------------------------------
    # Step 0: Structural index pass (first time per breach only)
    # ------------------------------------------------------------------
    if breach_name not in _structured_breaches:
        logger.info("First time seeing breach '%s' — running structural index", breach_name)
        try:
            # Determine breach root (the file itself, or directory specified in options)
            breach_root = options.get("breach_root", file_path)

            # Special handling for паспорта RU
            if "pasport" in breach_name.lower():
                walk_pasporta(breach_root)
            else:
                walk_and_index(breach_root, breach_name)

            _structured_breaches.add(breach_name)
        except Exception as exc:
            logger.error("Structural index failed for %s: %s", breach_name, exc)
            # Don't block processing — structural index is best-effort

    # If the target path is a directory, scan and process all nested files
    if path.is_dir():
        logger.info("%s is a directory — scanning and processing all files inside", path.name)
        total_parsed = 0
        total_indexed = 0
        total_failed = 0
        skipped_dirs = []

        def _on_walk_error(exc: OSError) -> None:
            logger.warning("Permission denied — skipping inaccessible path: %s", exc.filename)
            skipped_dirs.append(str(exc.filename))

        for dirpath, _dirnames, filenames in os.walk(file_path, onerror=_on_walk_error):
            for filename in filenames:
                entry = Path(dirpath) / filename
                if filename.startswith(".") or filename.startswith("~"):
                    continue
                if any(skip in entry.parts for skip in ("__MACOSX", ".DS_Store")):
                    continue
                
                try:
                    if entry.is_symlink():
                        continue
                except PermissionError:
                    continue

                try:
                    sub_opts = dict(options)
                    sub_opts["breach_root"] = options.get("breach_root", file_path)
                    sub_res = process_file(str(entry), breach_name, sub_opts)
                    total_parsed += sub_res.get("records_parsed", 0)
                    total_indexed += sub_res.get("records_indexed", 0)
                    total_failed += sub_res.get("records_failed", 0)
                except PermissionError as exc:
                    logger.warning("Permission denied reading file — skipping: %s (%s)", entry, exc)
                    total_failed += 1
                except Exception as exc:
                    logger.error("Failed to process file %s: %s", entry, exc)
                    total_failed += 1

        result["status"] = "ok"
        result["records_parsed"] = total_parsed
        result["records_indexed"] = total_indexed
        result["records_failed"] = total_failed
        result["processing_time_ms"] = int((time.time() - start_time) * 1000)
        return result

    # ------------------------------------------------------------------
    # Step 1: Dedup check (skip for archives — they'll be extracted)
    # ------------------------------------------------------------------
    force = options.get("force", False)
    if not options.get("archive") and not force:
        try:
            sha = file_sha256(file_path)
            if _dedup.is_duplicate(sha):
                result["status"] = "duplicate"
                logger.info("Duplicate file skipped: %s (sha256: %s...)", path.name, sha[:16])
                return result
        except Exception as exc:
            logger.warning("Dedup check failed for %s: %s", path.name, exc)
    elif force:
        logger.debug("[force] Dedup check bypassed for %s", path.name)

    # ------------------------------------------------------------------
    # Step 2: Classify the file
    # ------------------------------------------------------------------
    try:
        classification = classify(file_path, breach_name)
    except Exception as exc:
        logger.error("Classification failed for %s: %s", path.name, exc)
        result["status"] = "classification_error"
        return result

    logger.info(
        "Classified: %s → type=%s, index=%s, mode=%s",
        path.name, classification.parser_type, classification.index_name,
        classification.mode,
    )

    # ------------------------------------------------------------------
    # Step 3a: Archive → Extract → Re-queue
    # ------------------------------------------------------------------
    if classification.is_archive:
        return _handle_archive(file_path, breach_name, classification, options, start_time)

    # ------------------------------------------------------------------
    # Step 3b: Forensic/binary → Metadata-only index
    # ------------------------------------------------------------------
    if classification.is_forensic:
        return _handle_forensic(file_path, breach_name, classification, start_time)

    # ------------------------------------------------------------------
    # Step 3c: Stream mode → Live stream consumer
    # ------------------------------------------------------------------
    if classification.is_stream:
        return _handle_stream(file_path, breach_name, classification, options, start_time)

    # ------------------------------------------------------------------
    # Step 3d: Standard batch → Parse → Normalize → Upload
    # ------------------------------------------------------------------
    return _handle_batch(file_path, breach_name, classification, options, start_time)


# ======================================================================
# Handlers
# ======================================================================

def _handle_archive(file_path: str, breach_name: str,
                    classification: ClassificationResult,
                    options: dict, start_time: float) -> dict:
    """Handle archive extraction and re-queuing."""
    result = {
        "file_path": file_path,
        "breach_name": breach_name,
        "status": "archive_extraction",
        "records_parsed": 0,
        "records_indexed": 0,
        "records_failed": 0,
    }

    depth = options.get("depth", 0)

    def requeue_callback(extracted_path: str, bname: str, opts: dict):
        """Re-queue extracted file for pipeline processing."""
        logger.info("Re-queuing extracted file: %s", extracted_path)
        # In daemon mode, this would publish to RabbitMQ
        # In standalone mode, process directly
        try:
            inner_result = process_file(extracted_path, bname, opts)
            result["records_indexed"] += inner_result.get("records_indexed", 0)
        except Exception as exc:
            logger.error("Re-queue processing error: %s", exc)
            result["records_failed"] += 1

    extraction = extract(
        archive_path=file_path,
        breach_name=breach_name,
        depth=depth,
        requeue_callback=requeue_callback,
    )

    # Register original archive as forensic asset
    handle_forensic_asset(file_path, breach_name)

    result["status"] = "ok" if extraction.success else f"extraction_{extraction.error}"
    result["extracted_files"] = len(extraction.extracted_files)
    result["skipped_members"] = len(extraction.skipped_members)
    result["total_extracted_bytes"] = extraction.total_extracted_bytes
    result["processing_time_ms"] = int((time.time() - start_time) * 1000)

    # Mark dedup
    try:
        _dedup.mark_processed(file_sha256(file_path), file_path, breach_name)
    except Exception:
        pass

    return result


def _handle_forensic(file_path: str, breach_name: str,
                     classification: ClassificationResult,
                     start_time: float) -> dict:
    """Handle forensic/binary file indexing."""
    result = handle_forensic_asset(file_path, breach_name)
    result["processing_time_ms"] = int((time.time() - start_time) * 1000)

    # Mark dedup
    try:
        _dedup.mark_processed(file_sha256(file_path), file_path, breach_name)
    except Exception:
        pass

    return result


def _handle_stream(file_path: str, breach_name: str,
                   classification: ClassificationResult,
                   options: dict, start_time: float) -> dict:
    """Handle live stream file tailing."""
    from streaming.live_stream_consumer import consume_stream

    delimiter = classification.parser_kwargs.get("delimiter", ",")
    index_name = classification.index_name

    stats = consume_stream(
        file_path=file_path,
        breach_name=breach_name,
        index_name=index_name,
        delimiter=delimiter,
    )

    stats["processing_time_ms"] = int((time.time() - start_time) * 1000)
    return stats


def _pre_flight_schema(file_path: str, breach_name: str,
                       use_ai: bool = True) -> None:
    """
    Invoke the schema agent BEFORE parsing begins so the normalizer alias
    table is fully populated.  Errors here are non-fatal — worst case the
    pipeline falls back to its existing alias set.
    """
    try:
        from schema_agent import pre_flight_discover
        pre_flight_discover(file_path, use_ai=use_ai, breach_name=breach_name)
    except Exception as exc:
        logger.warning(
            "[pre-flight] Schema discovery skipped for %s: %s",
            Path(file_path).name, exc,
        )


def _handle_batch(file_path: str, breach_name: str,
                  classification: ClassificationResult,
                  options: dict, start_time: float,
                  _recovery_attempt: int = 0) -> dict:
    """
    Handle standard batch file processing.

    Memory is kept flat and bounded (O(1)) regardless of file size by processing
    the parser generator as a stream, rather than loading all rows into a list.

    Auto-recovery:
        Instead of loading the whole file to check the skip rate, we read and
        test a canary prefix (first 20,000 rows). If the skip rate exceeds
        _SKIP_RATE_THRESHOLD, auto-recovery triggers schema discovery, reloads
        aliases, and retries. This ensures fast, memory-safe, and proactive
        auto-healing even on multi-gigabyte files.
    """
    # SQL dumps need streaming + per-table index routing — delegate to a
    # dedicated handler so they never get materialized into a list.
    if classification.parser_type == "sql_dump":
        return _handle_sql_dump(file_path, breach_name, classification,
                                options, start_time)

    result = {
        "file_path": file_path,
        "breach_name": breach_name,
        "status": "processing",
        "records_parsed": 0,
        "records_indexed": 0,
        "records_failed": 0,
        "recovery_attempts": _recovery_attempt,
    }

    # Clean up any pre-existing .failed companion file
    failed_path = file_path + ".failed"
    if os.path.exists(failed_path):
        try:
            os.remove(failed_path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Pre-flight: learn column mappings before we parse a single record.
    # This is proactive (runs always on first attempt), whereas the
    # auto-recovery is reactive (runs only when skip rate is high).
    # ------------------------------------------------------------------
    if _recovery_attempt == 0:
        _pre_flight_schema(file_path, breach_name, use_ai=True)

    # ------------------------------------------------------------------
    # Parse & Canary prefix check
    # ------------------------------------------------------------------
    try:
        parser = _get_parser(classification)
        record_iterator = parser.parse()
    except Exception as exc:
        logger.error("Parse error for %s: %s", file_path, exc)
        result["status"] = "parse_error"
        return result

    canary_records = []
    canary_limit = 20000
    for _ in range(canary_limit):
        try:
            rec = next(record_iterator)
            canary_records.append(rec)
        except StopIteration:
            break
        except Exception as exc:
            logger.error("Parse error during canary read for %s: %s", file_path, exc)
            result["status"] = "parse_error"
            return result

    parsed_canary_count = len(canary_records)
    if parsed_canary_count == 0:
        result["status"] = "no_records"
        return result

    # ------------------------------------------------------------------
    # Normalize canary prefix to measure skip rate
    # ------------------------------------------------------------------
    mode = "transaction" if classification.parser_kwargs.get("transaction_mode") else "identity"
    if classification.parser_kwargs.get("needs_ai", False):
        mode = "ai"

    canary_docs = []
    skipped_canary = 0
    for rec in canary_records:
        doc = normalize_single(rec, mode=mode, breach_source=breach_name)
        if doc:
            doc["_index"] = classification.index_name
            canary_docs.append(doc)
        else:
            skipped_canary += 1

    rate = _skip_rate(parsed_canary_count, skipped_canary)

    # ------------------------------------------------------------------
    # Auto-recovery: high skip rate on canary → schema agent → reload aliases → retry
    # ------------------------------------------------------------------
    if (
        rate >= _SKIP_RATE_THRESHOLD
        and _recovery_attempt < _MAX_RECOVERY_ATTEMPTS
        and mode == "identity"
    ):
        logger.warning(
            "[auto-recovery] High skip rate %.0f%% on canary prefix of %s (%d/%d records dropped). "
            "Invoking schema agent…",
            rate * 100, Path(file_path).name, skipped_canary, parsed_canary_count,
        )
        try:
            from schema_agent import discover_file_schema
            from pipeline.normalizer import reload_aliases

            new_mappings = discover_file_schema(file_path, use_ai=True)
            learned = len(new_mappings.get("column_aliases", {}))
            logger.info(
                "[auto-recovery] Schema agent learned %d column aliases — "
                "reloading normalizer and re-processing %s",
                learned, Path(file_path).name,
            )
            reload_aliases()

            recovery_result = _handle_batch(
                file_path, breach_name, classification,
                options, start_time,
                _recovery_attempt=_recovery_attempt + 1,
            )
            recovery_result["recovery_attempts"] = _recovery_attempt + 1
            recovery_result["pre_recovery_skip_rate"] = round(rate, 4)
            return recovery_result

        except Exception as exc:
            logger.error(
                "[auto-recovery] Schema agent failed for %s: %s — "
                "continuing with original (partial) result",
                Path(file_path).name, exc,
            )
    elif rate >= _SKIP_RATE_THRESHOLD and _recovery_attempt >= _MAX_RECOVERY_ATTEMPTS:
        logger.info(
            "[auto-recovery] Skip rate still %.0f%% after %d recovery attempt(s) "
            "on %s — accepting result as-is",
            rate * 100, _recovery_attempt, Path(file_path).name,
        )

    # ------------------------------------------------------------------
    # Stream-upload remaining records
    # ------------------------------------------------------------------
    mapping_type = "transaction" if mode == "transaction" else "identity"
    id_field = "extra_data.purchase_ref" if mode == "transaction" else None

    total_parsed = parsed_canary_count
    total_skipped = skipped_canary

    try:
        uploader = BatchUploader(classification.index_name, mapping_type, id_field)

        # Upload canary documents
        for doc in canary_docs:
            uploader.add(doc)

        # Stream and upload remainder of the file
        log_every = 50000
        last_logged = total_parsed

        for rec in record_iterator:
            total_parsed += 1
            doc = normalize_single(rec, mode=mode, breach_source=breach_name)
            if doc:
                doc["_index"] = classification.index_name
                uploader.add(doc)
            else:
                total_skipped += 1

            if total_parsed - last_logged >= log_every:
                last_logged = total_parsed
                logger.info(
                    "  %s: %d parsed, %d indexed, %d skipped",
                    Path(file_path).name, total_parsed,
                    uploader.stats["total_ok"] + uploader.stats["buffer_remaining"],
                    total_skipped,
                )

        # Final flush
        uploader.flush_final()
        stats = uploader.stats

        result["records_indexed"] = stats["total_ok"]
        result["records_failed"] = stats["total_fail"] + parser.failed_count + total_skipped
        result["records_parsed"] = total_parsed + parser.failed_count
        result["status"] = "ok" if stats["total_ok"] > 0 else "normalization_filtered"

    except Exception as exc:
        logger.error("Upload/Stream error for %s: %s", file_path, exc)
        result["status"] = "upload_error"
        result["records_parsed"] = total_parsed + parser.failed_count
        result["records_failed"] = parser.failed_count + total_skipped
        return result

    logger.info(
        "Uploaded %d/%d docs to %s",
        result["records_indexed"], total_parsed - total_skipped, classification.index_name,
    )

    if parser.failed_samples:
        logger.warning(
            "Parser failed to process %d lines. Samples of failed lines:\n%s",
            parser.failed_count,
            "\n".join(f"  Line {ln}: {rl!r} (Reason: {reason})" for ln, rl, reason in parser.failed_samples)
        )
        logger.warning("All failed lines have been written to: %s.failed", file_path)

    # ------------------------------------------------------------------
    # Post-processing: patch structural doc status
    # ------------------------------------------------------------------
    try:
        relative = str(Path(file_path).name)
        status = "done" if result["records_indexed"] > 0 else "skipped"
        uploader.patch_status(relative, status)
    except Exception:
        pass  # non-critical

    # Mark dedup
    try:
        _dedup.mark_processed(file_sha256(file_path), file_path, breach_name)
    except Exception:
        pass

    result["skip_rate"] = round(rate, 4)
    result["processing_time_ms"] = int((time.time() - start_time) * 1000)
    return result



def _handle_sql_dump(file_path: str, breach_name: str,
                     classification: ClassificationResult,
                     options: dict, start_time: float,
                     _recovery_attempt: int = 0) -> dict:
    """
    Stream a SQL dump: parse → normalize → upload one record (or small batch)
    at a time, routing each row to the index selected by its source table.

    Memory stays flat regardless of file size because nothing is ever fully
    materialized — each normalized doc is pushed into a per-index uploader's
    buffer and flushed in bulk batches.

    Auto-recovery:
        If the normalizer drops more than _SKIP_RATE_THRESHOLD of all parsed
        rows (identity pillars not found), the schema agent is called to learn
        the file's column layout, aliases are hot-reloaded, and the file is
        re-processed once.  At most _MAX_RECOVERY_ATTEMPTS retries are made so
        a legitimately empty file cannot cause an infinite loop.
    """
    result = {
        "file_path": file_path,
        "breach_name": breach_name,
        "status": "processing",
        "records_parsed": 0,
        "records_indexed": 0,
        "records_failed": 0,
        "tables": {},
        "recovery_attempts": _recovery_attempt,
    }

    # Pre-flight schema discovery for SQL dumps — reads CREATE TABLE blocks
    # before streaming rows, so all column aliases are ready in the normalizer.
    if _recovery_attempt == 0:
        _pre_flight_schema(file_path, breach_name, use_ai=True)

    # Load mappings to see if we have whitelisted important tables
    from schema_agent import load_mappings
    mappings = load_mappings()
    source_info = mappings.get("_sources", {}).get(file_path, {})
    important_tables = source_info.get("important_tables")
    if important_tables:
        logger.info(
            "Applying whitelist of %d important tables for %s: %s",
            len(important_tables), Path(file_path).name, important_tables
        )
        classification.parser_kwargs["tables"] = important_tables
    else:
        logger.info("No important tables whitelisted for %s — parsing all tables.", Path(file_path).name)
        classification.parser_kwargs["tables"] = None

    parser = _get_parser(classification)

    # One uploader per target index — lazily created on first use.
    uploaders: dict[str, BatchUploader] = {}
    primary_index = classification.index_name

    def _uploader_for(index_name: str) -> BatchUploader:
        if index_name not in uploaders:
            uploaders[index_name] = BatchUploader(index_name, "identity", None)
        return uploaders[index_name]

    parsed = 0
    indexed = 0
    failed = 0
    skipped = 0
    log_every = 50_000
    last_logged = 0

    try:
        for record in parser.parse():
            parsed += 1
            result["tables"] = parser.tables_seen  # live progress

            doc = normalize_single(record, mode="identity",
                                   breach_source=breach_name)
            if not doc:
                skipped += 1
            else:
                # Route by source table → dedicated index when configured (case-insensitive lookup).
                src_table = record.fields.get("_source_table", "").lower()
                suffix = None
                for k, v in SQL_TABLE_INDEX_ROUTING.items():
                    if k.lower() == src_table:
                        suffix = v
                        break
                index_name = (
                    f"{primary_index}-{suffix}"
                    if suffix else primary_index
                )
                _uploader_for(index_name).add(doc)
                indexed += 1

            # Progress log at most every log_every records
            if parsed - last_logged >= log_every:
                last_logged = parsed
                logger.info(
                    "  %s: %d parsed, %d indexed, %d skipped, %d tables seen",
                    Path(file_path).name, parsed, indexed, skipped,
                    len(parser.tables_seen),
                )
    except Exception as exc:
        logger.error("SQL parse error for %s: %s", file_path, exc, exc_info=True)
        result["status"] = "parse_error"
        result["records_parsed"] = parsed
        # still flush whatever we got before the error
    else:
        result["records_parsed"] = parsed

    # Flush all per-index uploaders
    total_ok = 0
    total_fail = 0
    for idx, uploader in uploaders.items():
        uploader.flush_final()
        stats = uploader.stats
        total_ok += stats["total_ok"]
        total_fail += stats["total_fail"]
        logger.info(
            "  %s: %d ok, %d fail (cumulative)",
            idx, stats["total_ok"], stats["total_fail"],
        )

    result["records_indexed"] = total_ok
    result["records_failed"] = total_fail
    result["records_skipped"] = skipped
    result["tables"] = dict(parser.tables_seen)
    result["status"] = "ok" if total_ok > 0 else (
        "no_records" if parsed == 0 else "normalization_filtered"
    )

    logger.info(
        "SQL dump done: %s — %d parsed, %d indexed, %d skipped, %d failed "
        "across %d indexes",
        Path(file_path).name, parsed, total_ok, skipped, total_fail,
        len(uploaders),
    )

    # ------------------------------------------------------------------
    # Auto-recovery: high skip rate → schema agent → reload aliases → retry
    # ------------------------------------------------------------------
    rate = _skip_rate(parsed, skipped)
    if (
        result["status"] != "parse_error"
        and rate >= _SKIP_RATE_THRESHOLD
        and _recovery_attempt < _MAX_RECOVERY_ATTEMPTS
    ):
        logger.warning(
            "[auto-recovery] High skip rate %.0f%% on %s (%d/%d records dropped). "
            "Invoking schema agent…",
            rate * 100, Path(file_path).name, skipped, parsed,
        )
        try:
            from schema_agent import discover_file_schema
            from pipeline.normalizer import reload_aliases

            new_mappings = discover_file_schema(file_path, use_ai=True)
            learned = len(new_mappings.get("column_aliases", {}))
            logger.info(
                "[auto-recovery] Schema agent learned %d column aliases — "
                "reloading normalizer and re-processing %s",
                learned, Path(file_path).name,
            )
            reload_aliases()

            # Re-run the entire handler with an incremented attempt counter.
            # Pass options through unchanged so caller context is preserved.
            recovery_result = _handle_sql_dump(
                file_path, breach_name, classification,
                options, start_time,
                _recovery_attempt=_recovery_attempt + 1,
            )
            recovery_result["recovery_attempts"] = _recovery_attempt + 1
            recovery_result["pre_recovery_skip_rate"] = round(rate, 4)
            return recovery_result

        except Exception as exc:
            logger.error(
                "[auto-recovery] Schema agent failed for %s: %s — "
                "keeping original (partial) result",
                Path(file_path).name, exc,
            )
    elif rate >= _SKIP_RATE_THRESHOLD and _recovery_attempt >= _MAX_RECOVERY_ATTEMPTS:
        logger.info(
            "[auto-recovery] Skip rate still %.0f%% after %d recovery attempt(s) "
            "on %s — accepting result as-is",
            rate * 100, _recovery_attempt, Path(file_path).name,
        )

    # Patch structural doc + dedup
    try:
        if uploaders:
            primary = uploaders.get(primary_index) or next(iter(uploaders.values()))
            primary.patch_status(
                str(Path(file_path).name),
                "done" if total_ok > 0 else "skipped",
            )
    except Exception:
        pass
    try:
        _dedup.mark_processed(file_sha256(file_path), file_path, breach_name)
    except Exception:
        pass

    result["skip_rate"] = round(rate, 4)
    result["processing_time_ms"] = int((time.time() - start_time) * 1000)
    return result


def _get_parser(classification: ClassificationResult):
    """
    Instantiate the correct parser based on classification result.
    """
    from parsers.text_ulp_parser import TextULPParser
    from parsers.structured_table_parser import StructuredTableParser
    from parsers.sql_dump_parser import SQLDumpParser
    from parsers.json_parser import JSONParser

    ptype = classification.parser_type
    kwargs = classification.parser_kwargs

    if ptype == "ulp":
        return TextULPParser(classification.file_path, classification.breach_name)

    elif ptype == "structured_table":
        return StructuredTableParser(
            classification.file_path,
            classification.breach_name,
            column_map_name=kwargs.get("column_map_name"),
            delimiter=kwargs.get("delimiter"),
            has_header=kwargs.get("has_header", True),
        )

    elif ptype == "sql_dump":
        return SQLDumpParser(
            classification.file_path,
            classification.breach_name,
            tables=kwargs.get("tables"),
            ignore_tables=kwargs.get("ignore_tables"),
            chunk_size=SQL_CHUNK_SIZE,
            max_row_bytes=SQL_MAX_ROW_BYTES,
            max_rows_per_table=SQL_MAX_ROWS_PER_TABLE,
        )

    elif ptype == "json":
        return JSONParser(classification.file_path, classification.breach_name)

    else:
        raise ValueError(f"Unknown parser type: {ptype}")


# ======================================================================
# RabbitMQ consumer daemon
# ======================================================================

def run_daemon():
    """Start the RabbitMQ consumer daemon."""
    import pika

    logger.info("Starting Breach Processing Engine daemon...")
    logger.info("RabbitMQ URL: %s", RABBITMQ_URL)
    logger.info("Elasticsearch URL: (from settings)")
    logger.info("Archive Root: %s", ARCHIVE_ROOT)
    logger.info("Ingest Queue: %s", INGEST_QUEUE)

    # Set up signal handlers for graceful shutdown
    shutdown_requested = False

    def signal_handler(sig, frame):
        nonlocal shutdown_requested
        logger.info("Shutdown signal received — finishing current message...")
        shutdown_requested = True

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Append heartbeat=0 if not present to prevent RabbitMQ from dropping the connection
    # during heavy/long processing of huge files.
    url = RABBITMQ_URL
    if "heartbeat" not in url:
        if "?" in url:
            url += "&heartbeat=0"
        else:
            url += "?heartbeat=0"

    while not shutdown_requested:
        connection = None
        try:
            # Connect to RabbitMQ
            connection = pika.BlockingConnection(pika.URLParameters(url))
            channel = connection.channel()

            # Declare queues
            channel.queue_declare(queue=INGEST_QUEUE, durable=True)
            channel.queue_declare(queue=DEAD_LETTER_QUEUE, durable=True)

            # Set prefetch to 1 for fair dispatch
            channel.basic_qos(prefetch_count=1)

            def on_message(ch, method, properties, body):
                if shutdown_requested:
                    try:
                        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                    except Exception:
                        pass
                    return

                try:
                    message = json.loads(body)
                    file_path = message.get("file_path")
                    breach_name = message.get("breach_name", "unknown")
                    options = message.get("options", {})

                    if not file_path:
                        logger.error("Message missing file_path — NACK")
                        try:
                            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                        except Exception:
                            pass
                        try:
                            ch.basic_publish(
                                exchange="",
                                routing_key=DEAD_LETTER_QUEUE,
                                body=json.dumps({
                                    "error": "missing_file_path",
                                    "original_message": message,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                }),
                            )
                        except Exception:
                            pass
                        return

                    logger.info("Processing: %s (breach: %s)", Path(file_path).name, breach_name)
                    result = process_file(file_path, breach_name, options)

                    logger.info(
                        "Result: %s → status=%s, indexed=%d, time=%dms",
                        Path(file_path).name,
                        result.get("status"),
                        result.get("records_indexed", 0),
                        result.get("processing_time_ms", 0),
                    )

                    # ACK on success
                    try:
                        ch.basic_ack(delivery_tag=method.delivery_tag)
                    except Exception as ack_exc:
                        logger.error("Failed to ACK message (connection might have been lost): %s", ack_exc)

                except json.JSONDecodeError as exc:
                    logger.error("Invalid JSON message: %s", exc)
                    try:
                        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                    except Exception:
                        pass
                except Exception as exc:
                    logger.error("Unhandled message error: %s", exc, exc_info=True)
                    try:
                        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                    except Exception as nack_exc:
                        logger.error("Failed to NACK message: %s", nack_exc)

            channel.basic_consume(queue=INGEST_QUEUE, on_message_callback=on_message)
            logger.info("Daemon ready — waiting for messages on '%s'", INGEST_QUEUE)
            channel.start_consuming()

        except pika.exceptions.AMQPConnectionError as exc:
            if shutdown_requested:
                break
            logger.warning("RabbitMQ connection lost/error: %s. Reconnecting in 5 seconds...", exc)
            time.sleep(5)
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received in consume loop.")
            break
        except Exception as exc:
            if shutdown_requested:
                break
            logger.error("Unexpected error in daemon loop: %s. Reconnecting in 5 seconds...", exc, exc_info=True)
            time.sleep(5)
        finally:
            if connection and not connection.is_closed:
                try:
                    connection.close()
                except Exception:
                    pass

    logger.info("Daemon stopped. Final stats:")
    logger.info("  Breaches structured: %d", len(_structured_breaches))
    logger.info("  Dedup registry: %d hashes tracked", _dedup.count())


# ======================================================================
# Directory Watcher Daemon
# ======================================================================

def watch_directory(directory: str, breach_name: str | None = None, force: bool = False, use_queue: bool = False):
    """
    Watch a directory for new files/folders and process them automatically.
    Runs indefinitely until interrupted.
    """
    root = Path(directory)
    if not root.exists() or not root.is_dir():
        logger.error("Watch directory does not exist or is not a directory: %s", directory)
        sys.exit(1)

    logger.info("Watching directory for new assets: %s", directory)
    logger.info("Press Ctrl+C to stop watching.")

    # We track last known file sizes/times to detect write stability
    stable_files: dict[str, tuple[int, float]] = {}  # path -> (size, mtime)
    published_paths: set[str] = set()

    # Simple signal handler for graceful stop
    stop_requested = False
    def sig_handler(sig, frame):
        nonlocal stop_requested
        logger.info("Stop requested — exiting watch loop...")
        stop_requested = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    while not stop_requested:
        try:
            # Recursively find all files in the directory
            current_files = []
            def _on_walk_error(exc: OSError) -> None:
                logger.debug("Permission denied scanning in watch loop: %s", exc.filename)

            for dirpath, _dirnames, filenames in os.walk(root, onerror=_on_walk_error):
                for filename in filenames:
                    entry = Path(dirpath) / filename
                    # Skip symlinks
                    try:
                        if entry.is_symlink():
                            continue
                    except PermissionError:
                        continue
                    # Skip hidden/temporary files
                    if filename.startswith(".") or filename.startswith("~") or any(skip in entry.parts for skip in ("__MACOSX", ".DS_Store")):
                        continue
                    current_files.append(entry)

            # Check stability and process files
            for file_path in current_files:
                path_str = str(file_path)
                try:
                    stat = file_path.stat()
                    size = stat.st_size
                    mtime = stat.st_mtime
                except Exception:
                    # File might be locked or deleted
                    continue

                if path_str not in stable_files:
                    # First time seeing this file, record size/mtime
                    stable_files[path_str] = (size, mtime)
                    continue

                prev_size, prev_mtime = stable_files[path_str]

                # If size and mtime are the same, it means the file is stable
                if size == prev_size and mtime == prev_mtime:
                    # Skip if we have already queued/processed this file
                    if path_str in published_paths:
                        continue

                    # Let's see if we've already processed it
                    try:
                        sha = file_sha256(path_str)
                        if _dedup.is_duplicate(sha) and not force:
                            # Already processed, skip and mark as published
                            published_paths.add(path_str)
                            continue
                    except Exception as exc:
                        logger.warning("Could not calculate hash for %s: %s", file_path.name, exc)
                        continue

                    # Safe to process!
                    logger.info("[watcher] Found new stable file: %s", file_path.name)
                    
                    # Determine breach name dynamically
                    file_breach = breach_name
                    if file_breach is None:
                        relative_parts = file_path.relative_to(root).parts
                        if len(relative_parts) > 1:
                            # Use the first subfolder name under the watch root
                            file_breach = clean_breach_name(relative_parts[0])
                        else:
                            file_breach = clean_breach_name(file_path.name)
                    else:
                        file_breach = clean_breach_name(file_breach)

                    if use_queue:
                        import pika
                        try:
                            connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
                            channel = connection.channel()
                            channel.queue_declare(queue=INGEST_QUEUE, durable=True)
                            
                            message = {
                                "file_path": path_str,
                                "breach_name": file_breach,
                                "options": {"force": force}
                            }
                            
                            channel.basic_publish(
                                exchange="",
                                routing_key=INGEST_QUEUE,
                                body=json.dumps(message),
                                properties=pika.BasicProperties(
                                    delivery_mode=2,
                                )
                            )
                            connection.close()
                            logger.info("[watcher] Published file to RabbitMQ: %s (breach: %s)", file_path.name, file_breach)
                            published_paths.add(path_str)
                        except Exception as exc:
                            logger.error("[watcher] Failed to publish file %s to RabbitMQ: %s", file_path.name, exc)
                    else:
                        logger.info("[watcher] Starting processing for: %s (breach: %s)", file_path.name, file_breach)
                        try:
                            result = process_file(path_str, file_breach, options={"force": force, "breach_root": str(file_path.parent)})
                            logger.info(
                                "[watcher] Finished %s: status=%s, indexed=%d",
                                file_path.name, result.get("status"), result.get("records_indexed", 0)
                            )
                            published_paths.add(path_str)
                        except Exception as exc:
                            logger.error("[watcher] Error processing %s: %s", file_path.name, exc)
                else:
                    # File is still changing, update size/mtime and reset publish status
                    stable_files[path_str] = (size, mtime)
                    published_paths.discard(path_str)

            # Cleanup stable_files list of entries that no longer exist
            active_paths = {str(p) for p in current_files}
            for p in list(stable_files.keys()):
                if p not in active_paths:
                    stable_files.pop(p, None)
                    published_paths.discard(p)

        except Exception as exc:
            logger.error("[watcher] Error in watch loop: %s", exc)

        # Sleep before next poll
        for _ in range(5):
            if stop_requested:
                break
            time.sleep(1)


# ======================================================================
# One-shot mode: scan directory or process single file
# ======================================================================

def scan_directory(directory: str, breach_name: str | None = None,
                   force: bool = False):
    """Scan a directory and process all files found.

    Args:
        directory:   Root path to scan.
        breach_name: Breach source name (defaults to directory name).
        force:       If True, bypass the SHA-256 dedup check so already-
                     processed files are re-ingested.

    Directories that cannot be entered due to permission restrictions are
    skipped with a WARNING log so the rest of the scan can continue
    uninterrupted.  This is intentional for secured/quarantine folders that
    may contain malware and have been locked down at the OS level.
    """
    root = Path(directory)
    if breach_name is None:
        breach_name = clean_breach_name(root.name)
    else:
        breach_name = clean_breach_name(breach_name)

    if force:
        logger.warning("[force] Dedup bypassed — ALL files will be re-processed.")

    logger.info("Scanning directory: %s (breach: %s)", directory, breach_name)

    skipped_dirs: list[str] = []
    file_count = 0
    total_indexed = 0

    def _on_walk_error(exc: OSError) -> None:
        """Called by os.walk when a directory cannot be entered."""
        logger.warning(
            "Permission denied — skipping inaccessible path: %s", exc.filename
        )
        skipped_dirs.append(str(exc.filename))

    for dirpath, _dirnames, filenames in os.walk(root, onerror=_on_walk_error):
        for filename in filenames:
            entry = Path(dirpath) / filename

            # Skip symlinks (avoids following arbitrary links in breach data)
            try:
                if entry.is_symlink():
                    continue
            except PermissionError:
                logger.warning("Permission denied checking symlink: %s", entry)
                continue

            # Skip macOS metadata and hidden files
            if any(skip in entry.parts for skip in ("__MACOSX", ".DS_Store")):
                continue
            if filename.startswith(".") or filename.startswith("~"):
                continue

            file_count += 1
            logger.info("[%d] Processing: %s", file_count, entry.name)

            try:
                result = process_file(str(entry), breach_name,
                                      options={"force": force, "breach_root": directory})
            except PermissionError as exc:
                logger.warning(
                    "Permission denied reading file — skipping: %s (%s)", entry, exc
                )
                continue

            total_indexed += result.get("records_indexed", 0)

            logger.info(
                "  → status=%s, indexed=%d, time=%dms",
                result.get("status"),
                result.get("records_indexed", 0),
                result.get("processing_time_ms", 0),
            )

    if skipped_dirs:
        logger.warning(
            "Scan finished with %d inaccessible director%s (permission denied): %s",
            len(skipped_dirs),
            "y" if len(skipped_dirs) == 1 else "ies",
            ", ".join(skipped_dirs),
        )

    logger.info(
        "Scan complete: %d files processed, %d total records indexed",
        file_count, total_indexed,
    )


# ======================================================================
# CLI entry point
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Breach Processing Engine — Ingestion Pipeline Daemon",
    )
    parser.add_argument("--daemon", action="store_true",
                        help="Start as RabbitMQ consumer daemon")
    parser.add_argument("--scan", metavar="DIR",
                        help="One-shot scan a directory")
    parser.add_argument("--file", metavar="FILE",
                        help="One-shot process a single file")
    parser.add_argument("--breach", metavar="NAME",
                        help="Breach name (default: directory/file name)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Re-process files even if already indexed (bypass dedup)")
    parser.add_argument("--structure-only", action="store_true",
                        help="Only build structural index of the directory/file tree and exit")
    parser.add_argument("--schema-only", action="store_true",
                        help="Only run schema pre-flight/agent discovery and exit")
    parser.add_argument("--watch", metavar="DIR",
                        help="Watch a directory for new files/folders and process them automatically")
    parser.add_argument("--use-queue", action="store_true",
                        help="Publish found files to RabbitMQ queue instead of processing them locally")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.daemon:
        run_daemon()
    elif args.watch:
        watch_directory(args.watch, args.breach, force=args.force, use_queue=args.use_queue)
    elif args.structure_only:
        target_path = args.scan or args.file or args.watch
        if not target_path:
            print("Error: --structure-only requires --scan <DIR>, --file <FILE> or --watch <DIR>.", file=sys.stderr)
            sys.exit(1)
        breach = clean_breach_name(args.breach or Path(target_path).name)
        logger.info("Running structural index only for path: %s (breach: %s)", target_path, breach)
        if "pasport" in breach.lower():
            walk_pasporta(target_path)
        else:
            walk_and_index(target_path, breach)
        logger.info("Structural indexing complete.")
    elif args.schema_only:
        target_file = args.file
        if not target_file:
            print("Error: --schema-only requires --file <FILE>.", file=sys.stderr)
            sys.exit(1)
        breach = clean_breach_name(args.breach or Path(target_file).name)
        logger.info("Running schema discovery only for file: %s (breach: %s)", target_file, breach)
        from schema_agent import discover_file_schema
        discover_file_schema(target_file, use_ai=True, breach_name=breach)
        logger.info("Schema discovery complete.")
    elif args.scan:
        scan_directory(args.scan, args.breach, force=args.force)
    elif args.file:
        breach = clean_breach_name(args.breach or Path(args.file).name)
        result = process_file(args.file, breach,
                              options={"force": args.force, "breach_root": args.file})
        print(json.dumps(result, indent=2, default=str))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
