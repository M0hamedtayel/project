"""
Utility functions for file hashing and integrity checks.
"""

import hashlib
from pathlib import Path


def file_sha256(file_path: str, chunk_size: int = 8192) -> str:
    """Compute SHA-256 hex digest of a file using chunked reads."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def file_md5(file_path: str, chunk_size: int = 8192) -> str:
    """Compute MD5 hex digest of a file using chunked reads."""
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def is_executable_magic(data: bytes) -> bool:
    """
    Return True if the given bytes start with executable magic bytes.
    Detects: ELF, PE (Windows EXE/DLL), shebang scripts.
    """
    if data[:4] == b"\x7fELF":
        return True
    if data[:2] == b"MZ":
        return True
    if data[:2] == b"#!":
        return True
    return False


def human_bytes(n: int) -> str:
    """Convert bytes count to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def sanitize_index_name(name: str, prefix: str = "leaks-") -> str:
    """
    Sanitize a breach/folder name into a valid Elasticsearch index name.
    Lowercase, strip special chars, max 100 chars.
    """
    import re
    safe = re.sub(r"[^a-z0-9_-]", "-", name.lower())
    safe = re.sub(r"-{2,}", "-", safe).strip("-")
    if not safe.startswith(prefix):
        safe = prefix + safe
    return safe[:100]
