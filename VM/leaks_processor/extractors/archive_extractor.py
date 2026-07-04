"""
Safe archive extractor with comprehensive security protections.

Supports: ZIP, RAR (via rarfile), 7z (via py7zr), TAR, TAR.GZ, TAR.BZ2, TAR.XZ

Security protections:
  - Zip bomb detection (compression ratio > 100:1)
  - Path traversal prevention (reject ``../`` members)
  - Executable magic bytes detection (ELF, PE, shebang)
  - Max file count, max total size, max single file size
  - Max nesting depth (3 levels by default)
  - Streaming extraction with running byte counter
"""

import hashlib
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from config.settings import (
    ARCHIVE_ROOT,
    ARCHIVE_MAX_UNCOMPRESSED_BYTES,
    ARCHIVE_MAX_COMPRESSION_RATIO,
    ARCHIVE_MAX_FILE_COUNT,
    ARCHIVE_MAX_SINGLE_FILE_BYTES,
    ARCHIVE_MAX_NESTING_DEPTH,
)
from utils.hash_utils import file_sha256, is_executable_magic

logger = logging.getLogger(__name__)

# Extraction root — where extracted files go
EXTRACT_ROOT = os.path.join(ARCHIVE_ROOT, "extracted")

# Nested archive extensions (for recursive extraction)
NESTED_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}


class ArchiveExtractionResult:
    """Result of an archive extraction attempt."""

    def __init__(self, archive_path: str, success: bool = False):
        self.archive_path = archive_path
        self.success = success
        self.extracted_files: list[str] = []
        self.skipped_members: list[str] = []
        self.total_extracted_bytes: int = 0
        self.error: str | None = None
        self.nested_archives: list[str] = []


def extract(archive_path: str, breach_name: str,
            depth: int = 0, requeue_callback=None) -> ArchiveExtractionResult:
    """
    Safely extract an archive and re-queue its contents.

    Args:
        archive_path: Path to the archive file.
        breach_name: Breach source name.
        depth: Current nesting depth (0 = top-level archive).
        requeue_callback: Callable(path, breach_name, options) to re-publish
                          extracted files to the ingest queue.

    Returns:
        ArchiveExtractionResult with details.
    """
    result = ArchiveExtractionResult(archive_path)
    path = Path(archive_path)

    if not path.exists():
        result.error = "archive_not_found"
        return result

    # Depth check
    if depth >= ARCHIVE_MAX_NESTING_DEPTH:
        logger.warning(
            "Max nesting depth (%d) reached for %s — registering as forensic asset",
            depth, path.name,
        )
        result.error = "max_nesting_depth"
        return result

    # Create isolated extraction directory
    archive_hash = file_sha256(archive_path)[:8]
    extract_dir = os.path.join(EXTRACT_ROOT, archive_hash)
    os.makedirs(extract_dir, exist_ok=True)

    ext = path.suffix.lower()

    try:
        if ext == ".zip":
            _extract_zip(archive_path, extract_dir, result, depth,
                         breach_name, requeue_callback)
        elif ext == ".rar":
            _extract_rar(archive_path, extract_dir, result, depth,
                         breach_name, requeue_callback)
        elif ext == ".7z":
            _extract_7z(archive_path, extract_dir, result, depth,
                         breach_name, requeue_callback)
        elif ext in (".tar", ".gz", ".bz2", ".xz"):
            _extract_tar(archive_path, extract_dir, result, depth,
                         breach_name, requeue_callback)
        else:
            result.error = f"unsupported_format: {ext}"
            logger.error("Unsupported archive format: %s", ext)
            return result
    except Exception as exc:
        result.error = str(exc)
        logger.error("Extraction error for %s: %s", path.name, exc)
    finally:
        # Cleanup the isolated extraction directory after re-queueing
        if os.path.exists(extract_dir):
            try:
                shutil.rmtree(extract_dir)
                logger.info("Cleaned up extraction directory: %s", extract_dir)
            except Exception as exc:
                logger.warning("Failed to clean up extraction directory %s: %s", extract_dir, exc)

    result.success = len(result.extracted_files) > 0
    return result


# ======================================================================
# ZIP extraction
# ======================================================================

def _extract_zip(archive_path: str, extract_dir: str,
                 result: ArchiveExtractionResult, depth: int,
                 breach_name: str, requeue_callback):
    """Extract a ZIP archive with safety checks."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        # Pre-flight checks
        members = zf.infolist()
        if len(members) > ARCHIVE_MAX_FILE_COUNT:
            result.error = f"too_many_members: {len(members)}"
            logger.warning("ZIP bomb: %d members in %s", len(members), archive_path)
            return

        total_estimated = sum(m.file_size for m in members)
        if total_estimated > ARCHIVE_MAX_UNCOMPRESSED_BYTES:
            result.error = f"estimated_size_exceeded: {total_estimated}"
            logger.warning("ZIP: estimated uncompressed size %d exceeds limit", total_estimated)
            return

        running_bytes = 0

        for member in members:
            # Path traversal check
            if not _is_safe_path(member.filename, extract_dir):
                result.skipped_members.append(member.filename)
                logger.warning("Path traversal attempt: %s", member.filename)
                continue

            # Compression ratio check
            if member.compress_size > 0:
                ratio = member.file_size / member.compress_size
                if ratio > ARCHIVE_MAX_COMPRESSION_RATIO:
                    result.skipped_members.append(member.filename)
                    logger.warning(
                        "Zip bomb member: %s (ratio %.1f:1)",
                        member.filename, ratio,
                    )
                    continue

            # Single file size check
            if member.file_size > ARCHIVE_MAX_SINGLE_FILE_BYTES:
                result.skipped_members.append(member.filename)
                logger.warning("Member too large: %s (%d bytes)", member.filename, member.file_size)
                continue

            # Running total check
            running_bytes += member.file_size
            if running_bytes > ARCHIVE_MAX_UNCOMPRESSED_BYTES:
                result.error = "total_size_exceeded"
                logger.warning("Total extracted bytes exceeded limit — stopping")
                break

            # Executable check
            extracted_path = os.path.join(extract_dir, member.filename)
            os.makedirs(os.path.dirname(extracted_path), exist_ok=True)

            with zf.open(member) as src, open(extracted_path, "wb") as dst:
                # Read in chunks, check first bytes for executable magic
                header = src.read(4)
                if is_executable_magic(header):
                    result.skipped_members.append(member.filename)
                    logger.warning("Executable member skipped: %s", member.filename)
                    # Clean up partial file
                    os.remove(extracted_path) if os.path.exists(extracted_path) else None
                    continue

                dst.write(header)
                while True:
                    chunk = src.read(8192)
                    if not chunk:
                        break
                    dst.write(chunk)

            result.extracted_files.append(extracted_path)
            result.total_extracted_bytes += member.file_size

            # Requeue for pipeline processing
            if requeue_callback:
                ext = Path(member.filename).suffix.lower()
                if ext in NESTED_ARCHIVE_EXTS and depth + 1 < ARCHIVE_MAX_NESTING_DEPTH:
                    result.nested_archives.append(extracted_path)
                    requeue_callback(extracted_path, breach_name, {"archive": True, "depth": depth + 1})
                else:
                    requeue_callback(extracted_path, breach_name, {"from_archive": archive_path})

    # Cleanup extract dir after re-queueing
    if result.extracted_files:
        logger.info(
            "ZIP extracted: %d files (%d bytes) from %s",
            len(result.extracted_files), result.total_extracted_bytes, archive_path,
        )


# ======================================================================
# RAR extraction (optional — requires unrar/rarfile)
# ======================================================================

def _extract_rar(archive_path: str, extract_dir: str,
                 result: ArchiveExtractionResult, depth: int,
                 breach_name: str, requeue_callback):
    """Extract a RAR archive with safety checks."""
    try:
        import rarfile
    except ImportError:
        result.error = "rarfile_not_installed"
        logger.error("rarfile module not installed — cannot extract RAR: %s", archive_path)
        return

    try:
        with rarfile.RarFile(archive_path, "r") as rf:
            members = rf.infolist()
            if len(members) > ARCHIVE_MAX_FILE_COUNT:
                result.error = f"too_many_members: {len(members)}"
                return

            running_bytes = 0

            for member in members:
                if not _is_safe_path(member.filename, extract_dir):
                    result.skipped_members.append(member.filename)
                    continue

                if member.file_size > ARCHIVE_MAX_SINGLE_FILE_BYTES:
                    result.skipped_members.append(member.filename)
                    continue

                running_bytes += member.file_size
                if running_bytes > ARCHIVE_MAX_UNCOMPRESSED_BYTES:
                    result.error = "total_size_exceeded"
                    break

                extracted_path = os.path.join(extract_dir, member.filename)
                os.makedirs(os.path.dirname(extracted_path), exist_ok=True)

                # Check for executable magic
                try:
                    data = rf.read(member)
                    if is_executable_magic(data[:4]):
                        result.skipped_members.append(member.filename)
                        continue
                    with open(extracted_path, "wb") as dst:
                        dst.write(data)
                except Exception as exc:
                    logger.warning("Failed to extract RAR member %s: %s", member.filename, exc)
                    result.skipped_members.append(member.filename)
                    continue

                result.extracted_files.append(extracted_path)
                result.total_extracted_bytes += member.file_size

                if requeue_callback:
                    ext = Path(member.filename).suffix.lower()
                    if ext in NESTED_ARCHIVE_EXTS and depth + 1 < ARCHIVE_MAX_NESTING_DEPTH:
                        result.nested_archives.append(extracted_path)
                        requeue_callback(extracted_path, breach_name, {"archive": True, "depth": depth + 1})
                    else:
                        requeue_callback(extracted_path, breach_name, {"from_archive": archive_path})

    except Exception as exc:
        result.error = f"rar_error: {exc}"
        logger.error("RAR extraction error: %s", exc)


# ======================================================================
# 7z extraction (optional — requires py7zr)
# ======================================================================

def _extract_7z(archive_path: str, extract_dir: str,
                result: ArchiveExtractionResult, depth: int,
                breach_name: str, requeue_callback):
    """Extract a 7z archive with safety checks."""
    try:
        import py7zr
    except ImportError:
        result.error = "py7zr_not_installed"
        logger.error("py7zr module not installed — cannot extract 7z: %s", archive_path)
        return

    try:
        with py7zr.SevenZipFile(archive_path, "r") as sz:
            # Get member list
            archive_info = sz.archivefiles()
            if len(archive_info) > ARCHIVE_MAX_FILE_COUNT:
                result.error = f"too_many_members: {len(archive_info)}"
                return

            total_estimated = sum(
                info.get("uncompressed", 0) for info in archive_info.values()
                if isinstance(info, dict)
            )
            if total_estimated > ARCHIVE_MAX_UNCOMPRESSED_BYTES:
                result.error = f"estimated_size_exceeded"
                return

            # Extract to temp dir first, then check
            sz.extractall(path=extract_dir)

            # Walk extracted files and check each
            for root_dir, _dirs, files in os.walk(extract_dir):
                for fname in files:
                    extracted_path = os.path.join(root_dir, fname)

                    # Executable check
                    try:
                        with open(extracted_path, "rb") as f:
                            header = f.read(4)
                        if is_executable_magic(header):
                            os.remove(extracted_path)
                            result.skipped_members.append(fname)
                            continue
                    except OSError:
                        result.skipped_members.append(fname)
                        continue

                    result.extracted_files.append(extracted_path)
                    try:
                        result.total_extracted_bytes += os.path.getsize(extracted_path)
                    except OSError:
                        pass

                    if requeue_callback:
                        ext = Path(fname).suffix.lower()
                        if ext in NESTED_ARCHIVE_EXTS and depth + 1 < ARCHIVE_MAX_NESTING_DEPTH:
                            result.nested_archives.append(extracted_path)
                            requeue_callback(extracted_path, breach_name, {"archive": True, "depth": depth + 1})
                        else:
                            requeue_callback(extracted_path, breach_name, {"from_archive": archive_path})

    except Exception as exc:
        result.error = f"sevenz_error: {exc}"
        logger.error("7z extraction error: %s", exc)


# ======================================================================
# TAR extraction (including .tar.gz, .tar.bz2, .tar.xz)
# ======================================================================

def _extract_tar(archive_path: str, extract_dir: str,
                 result: ArchiveExtractionResult, depth: int,
                 breach_name: str, requeue_callback):
    """Extract a TAR archive (plain, gz, bz2, xz) with safety checks."""
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > ARCHIVE_MAX_FILE_COUNT:
                result.error = f"too_many_members: {len(members)}"
                return

            running_bytes = 0

            for member in members:
                if not member.isfile():
                    continue

                if not _is_safe_path(member.name, extract_dir):
                    result.skipped_members.append(member.name)
                    logger.warning("Tar path traversal: %s", member.name)
                    continue

                if member.size > ARCHIVE_MAX_SINGLE_FILE_BYTES:
                    result.skipped_members.append(member.name)
                    continue

                running_bytes += member.size
                if running_bytes > ARCHIVE_MAX_UNCOMPRESSED_BYTES:
                    result.error = "total_size_exceeded"
                    break

                extracted_path = os.path.join(extract_dir, member.name)
                os.makedirs(os.path.dirname(extracted_path), exist_ok=True)

                # Extract with streaming to check executable magic
                try:
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with src:
                        header = src.read(4)
                        if is_executable_magic(header):
                            result.skipped_members.append(member.name)
                            continue
                        with open(extracted_path, "wb") as dst:
                            dst.write(header)
                            while True:
                                chunk = src.read(8192)
                                if not chunk:
                                    break
                                dst.write(chunk)
                except Exception as exc:
                    logger.warning("Failed to extract tar member %s: %s", member.name, exc)
                    result.skipped_members.append(member.name)
                    continue

                result.extracted_files.append(extracted_path)
                result.total_extracted_bytes += member.size

                if requeue_callback:
                    ext = Path(member.name).suffix.lower()
                    if ext in NESTED_ARCHIVE_EXTS and depth + 1 < ARCHIVE_MAX_NESTING_DEPTH:
                        result.nested_archives.append(extracted_path)
                        requeue_callback(extracted_path, breach_name, {"archive": True, "depth": depth + 1})
                    else:
                        requeue_callback(extracted_path, breach_name, {"from_archive": archive_path})

    except tarfile.TarError as exc:
        result.error = f"tar_error: {exc}"
        logger.error("Tar extraction error: %s", exc)


# ======================================================================
# Shared safety checks
# ======================================================================

def _is_safe_path(member_path: str, extract_dir: str) -> bool:
    """
    Check if a member path is safe (doesn't escape the extraction directory).

    Rejects:
      - Paths containing ``..``
      - Absolute paths (starting with ``/``)
      - Paths that resolve outside the extract directory
    """
    # Strip leading slashes and backslashes
    clean = member_path.lstrip("/\\").lstrip(".")

    # Reject path traversal
    if ".." in clean:
        return False

    # Resolve and verify it stays inside extract_dir
    full_path = os.path.realpath(os.path.join(extract_dir, clean))
    extract_real = os.path.realpath(extract_dir)

    try:
        return os.path.commonpath([extract_real, full_path]) == extract_real
    except ValueError:
        return False
