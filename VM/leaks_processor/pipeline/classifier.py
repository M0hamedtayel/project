"""
File classifier — routes each file to the correct parser and determines
the processing mode and target Elasticsearch index.

Classification logic:
  1. Extension-based routing (.txt, .csv, .sql, .json, .jsonl, archives)
  2. Filename pattern overrides (known breach-specific formats)
  3. Content-based detection for ambiguous files (sample + delimiter sniff)
  4. Live stream detection for actively-written transaction files
"""

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import requests

from config.settings import (
    ARCHIVE_ROOT, COLUMN_MAPS, TRANSACTION_MODE_TRIGGERS,
    STREAM_LIVE_FILE_AGE_SECS, STREAM_LIVE_FILE_MIN_BYTES,
)

logger = logging.getLogger(__name__)

# Archive extensions
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz",
                      ".tar.bz2", ".tbz2", ".tar.xz", ".txz"}

# Forensic/binary extensions — no text parsing
FORENSIC_EXTENSIONS = {".pdf", ".xlsx", ".xls", ".docx", ".doc",
                         ".pptx", ".ppt", ".jpg", ".jpeg", ".png",
                         ".gif", ".bmp", ".tif", ".tiff", ".webp"}

# Parseable text extensions
PARSEABLE_EXTENSIONS = {
    ".txt":  "ulp",
    ".csv":  "structured_table",
    ".tsv":  "structured_table",
    ".sql":  "sql_dump",
    ".json": "json",
    ".jsonl": "json",
}


class ClassificationResult:
    """Result of classifying a single file."""

    def __init__(self, file_path: str, breach_name: str,
                 parser_type: str, index_name: str, mode: str = "batch",
                 parser_kwargs: dict | None = None,
                 extra: dict | None = None):
        self.file_path = file_path
        self.breach_name = breach_name
        self.parser_type = parser_type       # parser identifier string
        self.index_name = index_name         # target ES index
        self.mode = mode                     # "batch" or "stream"
        self.parser_kwargs = parser_kwargs or {}
        self.extra = extra or {}

        # Derived flags
        self.is_archive = parser_type == "archive"
        self.is_forensic = parser_type == "forensic"
        self.is_stream = mode == "stream"
        self.is_parseable = not self.is_archive and not self.is_forensic


def _classify_with_ollama(file_path: str) -> dict | None:
    """
    Use local Ollama to classify text/csv file format.
    Returns a dict with keys: 'format', 'delimiter', 'has_header', or None on error/unsupported.
    """
    from config.settings import OLLAMA_URL, OLLAMA_MODEL
    
    # Read first 15 lines as sample
    try:
        sample_lines = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(15):
                line = f.readline()
                if not line:
                    break
                sample_lines.append(line.strip())
    except Exception as exc:
        logger.warning("[AI Classifier] Could not read sample for Ollama: %s", exc)
        return None

    if not sample_lines:
        return None

    sample_text = "\n".join(sample_lines[:15])

    prompt = f"""You are a data breach file classification assistant.
Analyze the following sample lines of a leaked file:
---
{sample_text}
---

Determine the format of the file. Choose exactly one of the following format types:
- "ulp": Username-Leaked-Password combo list format. The lines contain credentials separated by colons (e.g., email:password, username:password, url:email:password, or url:username:password). No database table layout structure or headers.
- "structured_table": A delimited database table export (CSV, TSV, or comma/semicolon/tab separated text). It represents a single database table, containing database column structures (such as first_name, email, phone, address, etc.), either with or without a header row.
- "sql_dump": A SQL script containing CREATE TABLE or INSERT INTO statements.
- "other": Unrelated text, logs, HTML, or binary data.

Return your verdict in a clean JSON format. If you choose "structured_table", also specify the delimiter used (e.g. ",", ";", "\\t", etc.) and if you think it has a header row (true/false).
Example JSON responses:
{{
  "format": "ulp"
}}
or
{{
  "format": "structured_table",
  "delimiter": ",",
  "has_header": true
}}

JSON response:"""

    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 256},
            },
            timeout=720,  # 12 minute timeout for classification
        )
        resp.raise_for_status()
        text = resp.json().get("response", "").strip()
        
        # Parse JSON from response
        start_idx = text.find("{")
        if start_idx != -1:
            try:
                data, _ = json.JSONDecoder().raw_decode(text[start_idx:])
                return data
            except json.JSONDecodeError:
                # Try regex fallback
                m = re.search(r"\{.*?\}", text, re.DOTALL)
                if m:
                    try:
                        return json.loads(m.group(0))
                    except Exception:
                        pass
        logger.warning("[AI Classifier] Ollama returned non-JSON response: %s", text)
    except Exception as exc:
        logger.warning("[AI Classifier] Ollama request failed (falling back to heuristics): %s", exc)
    
    return None


def _looks_like_ulp_combo(file_path: str) -> bool:
    """
    Heuristically determine if a file is a ULP/combo list (URL/email:password)
    regardless of extension.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for _ in range(25):
                line = f.readline()
                if not line:
                    break
                line_stripped = line.strip()
                if line_stripped and not line_stripped.startswith("#"):
                    lines.append(line_stripped)
    except Exception:
        return False

    if not lines:
        return False

    # If the first line has common DB headers, it's a structured table, not ULP combo
    first_line = lines[0].lower()
    for delim in (",", "\t", ";"):
        if delim in first_line:
            cols = [c.strip().strip("'\"") for c in first_line.split(delim)]
            for header in ("id", "user_id", "member_id", "first_name", "last_name", "created_at", "updated_at", "phone_number", "billing_", "street_", "postcode", "zipcode"):
                if header.endswith("_"):
                    if any(col.startswith(header) for col in cols):
                        return False
                else:
                    if header in cols:
                        return False

    from parsers.text_ulp_parser import detect_password_type

    ulp_count = 0
    for line in lines:
        matched = False
        for delim in ("\t", ":", " "):
            parts = [p.strip() for p in line.split(delim) if p.strip()]
            if 2 <= len(parts) <= 4:
                # Require one part to look like email/username and one to be password
                has_email_or_user = False
                has_pw = False
                for p in parts:
                    if "@" in p and "." in p:
                        has_email_or_user = True
                    elif len(p) >= 3 and detect_password_type(p) != "empty":
                        has_pw = True

                # If no email found, verify first part looks like a username
                if not has_email_or_user:
                    if re.match(r"^[a-zA-Z0-9_.\-+@#$*!=|]+$", parts[0]):
                        has_email_or_user = True

                if has_email_or_user and has_pw:
                    matched = True
                    break
        if matched:
            ulp_count += 1

    return ulp_count >= len(lines) * 0.7


def classify(file_path: str, breach_name: str) -> ClassificationResult:
    """
    Classify a file and return a ClassificationResult with routing info.
    """
    path = Path(file_path)
    ext = path.suffix.lower()
    filename = path.name.lower()
    stem = path.stem.lower()

    # ------------------------------------------------------------------
    # 1. Archive files → extractor
    # ------------------------------------------------------------------
    full_ext = path.name.lower()
    # Handle compound extensions (.tar.gz, .tar.bz2, .tar.xz)
    if full_ext.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="archive",
            index_name=f"leaks-assets-{breach_name}",
            extra={"archive_format": "tar"},
        )

    if ext in ARCHIVE_EXTENSIONS:
        fmt = ext.lstrip(".")
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="archive",
            index_name=f"leaks-assets-{breach_name}",
            extra={"archive_format": fmt},
        )

    # ------------------------------------------------------------------
    # 2. Forensic/binary files → metadata-only handler
    # ------------------------------------------------------------------
    if ext in FORENSIC_EXTENSIONS:
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="forensic",
            index_name=f"leaks-assets-{breach_name}",
        )

    # ------------------------------------------------------------------
    # 3. Filename-specific overrides (known breach patterns)
    # ------------------------------------------------------------------
    classification = _apply_filename_rules(filename, stem, ext, file_path, breach_name)
    if classification:
        return classification

    # ------------------------------------------------------------------
    # 3a. Smart Content Heuristics (Detect ULP files regardless of extension)
    # ------------------------------------------------------------------
    if ext in (".txt", ".csv", ".tsv", ""):
        if _looks_like_ulp_combo(file_path):
            logger.info("[Classifier] Heuristically classified %s as ULP combo list", path.name)
            return ClassificationResult(
                file_path=file_path, breach_name=breach_name,
                parser_type="ulp", index_name=f"leaks-{breach_name}",
            )

    # ------------------------------------------------------------------
    # 3b. AI-assisted classification (optional/local Ollama check)
    # ------------------------------------------------------------------
    if ext in PARSEABLE_EXTENSIONS or ext in (".txt", ".csv", ".tsv", ".sql", ""):
        ai_res = _classify_with_ollama(file_path)
        if ai_res and isinstance(ai_res, dict):
            fmt = ai_res.get("format")
            if fmt == "ulp":
                logger.info("[AI Classifier] Classified %s as ULP combo list", path.name)
                return ClassificationResult(
                    file_path=file_path, breach_name=breach_name,
                    parser_type="ulp", index_name=f"leaks-{breach_name}",
                )
            elif fmt == "structured_table":
                delim = ai_res.get("delimiter", ",")
                has_hdr = ai_res.get("has_header", False)
                logger.info("[AI Classifier] Classified %s as Structured Table (delim=%s, header=%s)", path.name, delim, has_hdr)
                parser_kwargs = {
                    "delimiter": delim,
                    "has_header": has_hdr,
                    "needs_ai": True
                }
                index_name = f"leaks-{breach_name}"
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        first_line = f.readline().strip()
                        headers_lower = [h.strip().lower() for h in first_line.split(delim)]
                        if any(trigger in headers_lower for trigger in TRANSACTION_MODE_TRIGGERS):
                            parser_kwargs["transaction_mode"] = True
                            index_name = "leaks-udemy-transactions"
                except Exception:
                    pass
                return ClassificationResult(
                    file_path=file_path, breach_name=breach_name,
                    parser_type="structured_table", index_name=index_name,
                    parser_kwargs=parser_kwargs,
                )
            elif fmt == "sql_dump":
                logger.info("[AI Classifier] Classified %s as SQL Dump", path.name)
                return ClassificationResult(
                    file_path=file_path, breach_name=breach_name,
                    parser_type="sql_dump", index_name=f"leaks-{breach_name}",
                )

    # ------------------------------------------------------------------
    # 4. Extension-based routing (Fallback if AI is off/failed/indeterminate)
    # ------------------------------------------------------------------
    if ext in PARSEABLE_EXTENSIONS:
        parser_type = PARSEABLE_EXTENSIONS[ext]
        parser_kwargs = {}
        index_name = f"leaks-{breach_name}"

        # For CSV/TSV: detect delimiter and check for live stream mode
        if parser_type == "structured_table":
            parser_kwargs, index_name = _classify_csv(file_path, breach_name, filename)

        # For .txt files: default to ULP but check if it's positional
        if parser_type == "ulp":
            txt_result = _classify_txt_file(file_path, breach_name, filename)
            if txt_result:
                return txt_result

        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type=parser_type, index_name=index_name,
            parser_kwargs=parser_kwargs,
        )

    # ------------------------------------------------------------------
    # 5. Unknown extension — try content detection
    # ------------------------------------------------------------------
    return _classify_unknown(file_path, breach_name)


# ======================================================================
# Filename-specific overrides
# ======================================================================

def _looks_like_egypt_facebook(file_path: str) -> bool:
    """
    Content fingerprint for the Egypt Facebook scrape dataset.

    Distinctive signature (verified against real dump samples):
      - Col 0: large integer Facebook UID (8–20 digits, no quotes or stripped)
      - Col 3: phone number (digits with optional leading +, 8–15 digits total)
      - 20 or more comma-separated fields per line

    Uses ``csv.reader`` so quoted fields are handled correctly.
    Returns True only when ALL signals are present — false-positive risk is
    extremely low given the combination of constraints.
    """
    import csv as _csv
    import re as _re

    _FB_UID = _re.compile(r'^\d{8,20}$')
    _PHONE  = _re.compile(r'^\+?\d{8,15}$')   # allow leading + (e.g. +201274032841)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = _csv.reader(f)
            for _ in range(5):       # try up to 5 lines in case of blank rows
                try:
                    parts = next(reader)
                except StopIteration:
                    break
                if not parts or len(parts) < 20:
                    continue
                col0 = parts[0].strip()
                col3 = parts[3].strip()
                if _FB_UID.match(col0) and _PHONE.match(col3):
                    return True
    except Exception:
        pass
    return False


def _apply_filename_rules(filename: str, stem: str, ext: str,
                          file_path: str, breach_name: str) -> ClassificationResult | None:
    """Apply known breach-specific filename patterns."""

    # Egypt Facebook scrape — positional comma-separated, no header.
    # Matches by breach name AND by content fingerprint so it works regardless
    # of file extension (.csv, .txt, .tsv, or no extension).
    _EGYPT_EXTS = {".csv", ".txt", ".tsv", ""}
    if "egypt" in breach_name.lower() and ext in _EGYPT_EXTS:
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="structured_table",
            index_name="leaks-egypt-facebook-scrape",
            parser_kwargs={
                "column_map_name": "egypt_facebook",
                "has_header": False,
            },
        )

    # Egypt Facebook content-based detection: catches files in a non-Egypt
    # breach folder but whose content clearly matches the Egypt dataset format.
    if ext in (".txt", ".csv", "") and _looks_like_egypt_facebook(file_path):
        logger.info(
            "[classifier] %s matches Egypt Facebook fingerprint — routing to egypt-facebook-scrape",
            Path(file_path).name,
        )
        return ClassificationResult(
            file_path=file_path, breach_name="egypt-facebook-scrape",
            parser_type="structured_table",
            index_name="leaks-egypt-facebook-scrape",
            parser_kwargs={
                "column_map_name": "egypt_facebook",
                "has_header": False,
            },
        )

    # forum.kaspersky.csv — semicolon-delimited
    if "kaspersky" in filename:
        return ClassificationResult(
            file_path=file_path, breach_name="forum-kaspersky",
            parser_type="structured_table",
            index_name="leaks-forum-kaspersky",
            parser_kwargs={
                "delimiter": ";",
                "has_header": True,
            },
        )

    # bazookaegy.com CSV — standard comma-delimited with headers
    if "bazooka" in filename:
        return ClassificationResult(
            file_path=file_path, breach_name="bazookaegy-com",
            parser_type="structured_table",
            index_name="leaks-bazookaegy-com",
            parser_kwargs={
                "delimiter": ",",
                "has_header": True,
            },
        )

    # Instagram coneticlarp — root-level positional txt
    if "insta" in stem and "coneticlarp" in stem:
        return ClassificationResult(
            file_path=file_path, breach_name="instagram-coneticlarp",
            parser_type="structured_table",
            index_name="leaks-instagram-coneticlarp",
            parser_kwargs={
                "column_map_name": "instagram_coneticlarp",
                "has_header": False,
            },
        )

    # Nafham SQL dump
    if "nafham" in filename and filename.endswith(".sql"):
        return ClassificationResult(
            file_path=file_path, breach_name="nafham-com",
            parser_type="sql_dump",
            index_name="leaks-nafham-com",
            parser_kwargs={
                "table_name": "user",
            },
        )

    # Udemy transaction CSVs
    if "udemy" in breach_name.lower() and filename.endswith(".csv"):
        return _classify_udemy_csv(file_path, breach_name, filename)

    # Students sample CSV
    if "students_sample" in filename:
        return ClassificationResult(
            file_path=file_path, breach_name="sample-students",
            parser_type="structured_table",
            index_name="leaks-sample-students",
            parser_kwargs={
                "column_map_name": "sample_students",
                "has_header": False,
                "needs_ai": True,  # Arabic headers — needs Ollama
            },
        )

    return None


# ======================================================================
# CSV classification helpers
# ======================================================================

def _classify_csv(file_path: str, breach_name: str,
                  filename: str) -> tuple[dict, str]:
    """
    Classify a CSV file: detect delimiter, check for transaction mode,
    and optionally route to live stream.
    Returns (parser_kwargs, index_name).
    """
    parser_kwargs = {"has_header": True}
    index_name = f"leaks-{breach_name}"

    try:
        from schema_agent import is_no_header_csv
        if is_no_header_csv(file_path):
            parser_kwargs["has_header"] = False
            parser_kwargs["needs_ai"] = True
    except Exception:
        pass

    # Read first line to detect delimiter and headers
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
    except Exception:
        return parser_kwargs, index_name

    # Auto-detect delimiter
    delimiters = {";": first_line.count(";"), "\t": first_line.count("\t"),
                  ",": first_line.count(",")}
    best = max(delimiters, key=delimiters.get)
    if delimiters[best] > 0:
        parser_kwargs["delimiter"] = best

    # Check headers for transaction mode triggers
    headers_lower = [h.strip().lower() for h in first_line.split(best)]
    has_transaction_fields = any(
        trigger in headers_lower for trigger in TRANSACTION_MODE_TRIGGERS
    )

    if has_transaction_fields:
        index_name = "leaks-udemy-transactions"
        parser_kwargs["transaction_mode"] = True

        # Check for live stream mode
        if is_live_transaction_file(file_path):
            parser_kwargs["stream"] = True

    return parser_kwargs, index_name


def _classify_udemy_csv(file_path: str, breach_name: str,
                        filename: str) -> ClassificationResult:
    """Specific classification for Udemy transaction CSVs."""
    # Detect files without a header row (e.g. sus.csv, raw dumps)
    try:
        from schema_agent import is_no_header_csv
        no_header = is_no_header_csv(file_path)
    except Exception:
        no_header = False

    if no_header:
        logger.info(
            "[classifier] %s detected as no-header CSV — using udemy_sus positional map",
            Path(file_path).name,
        )
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="structured_table",
            index_name="leaks-udemy-transactions", mode="batch",
            parser_kwargs={
                "column_map_name": "udemy_sus",
                "has_header": False,
                "transaction_mode": True,
            },
        )

    # Read first line to detect delimiter and headers
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
    except Exception:
        first_line = ""

    # Detect delimiter
    delimiters = {";": first_line.count(";"), "\t": first_line.count("\t"),
                  ",": first_line.count(",")}
    best = max(delimiters, key=delimiters.get)
    best_delim = best if delimiters[best] > 0 else ","

    # Check headers for transaction mode triggers
    headers_lower = [h.strip().strip("'\"").lower() for h in first_line.split(best_delim)]
    has_transaction_fields = any(
        trigger in headers_lower for trigger in TRANSACTION_MODE_TRIGGERS
    )

    if has_transaction_fields:
        parser_kwargs = {
            "has_header": True,
            "transaction_mode": True,
        }
        index_name = "leaks-udemy-transactions"
    else:
        parser_kwargs = {
            "has_header": True,
            "transaction_mode": False,
        }
        index_name = f"leaks-{breach_name}"

    mode = "batch"
    if is_live_transaction_file(file_path):
        mode = "stream"

    return ClassificationResult(
        file_path=file_path, breach_name=breach_name,
        parser_type="structured_table",
        index_name=index_name, mode=mode,
        parser_kwargs=parser_kwargs,
    )



# ======================================================================
# TXT file classification
# ======================================================================

def _classify_txt_file(file_path: str, breach_name: str,
                        filename: str) -> ClassificationResult | None:
    """
    Classify .txt files: determine if ULP combo list, positional CSV, or other.

    Decision order (highest confidence first):
      1. If the file looks like a multi-field CSV (8+ comma-separated fields
         on average) — route to structured_table with AI schema discovery.
         This prevents URL-bearing CSVs from being misclassified as ULP.
      2. If colons dominate AND the colon density clearly exceeds the CSV
         signal — treat as ULP combo list.
      3. Otherwise return None — caller falls through to extension routing.
    """
    # Read a sample of up to 20 non-empty, non-comment lines
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw = [f.readline() for _ in range(30)]
    except Exception:
        return None

    lines = [l.strip() for l in raw if l.strip() and not l.startswith("#")]
    if not lines:
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="ulp", index_name=f"leaks-{breach_name}",
        )

    sample = lines[:20]

    # ------------------------------------------------------------------
    # Signal 1: CSV shape — check average comma-separated field count
    # We use csv.reader so quoted commas don’t inflate the count.
    # ------------------------------------------------------------------
    import csv as _csv
    field_counts = []
    for line in sample:
        try:
            parts = next(_csv.reader([line]))
            field_counts.append(len(parts))
        except Exception:
            field_counts.append(line.count(",") + 1)

    avg_fields = sum(field_counts) / len(field_counts) if field_counts else 0

    if avg_fields >= 8:
        # This is a CSV stored in a .txt file.
        # Route to structured_table; schema agent + Ollama will learn columns.
        logger.info(
            "[classifier] %s looks like a CSV (avg %.1f fields) — "
            "routing to structured_table with AI schema discovery",
            Path(file_path).name, avg_fields,
        )
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="structured_table",
            index_name=f"leaks-{breach_name}",
            parser_kwargs={
                "has_header": False,   # pre_flight_discover will decide
                "needs_ai": True,
            },
        )

    # ------------------------------------------------------------------
    # Signal 2: ULP combo list — colon density, excluding URL colons.
    # We strip obvious URL patterns (://) before counting so that a
    # single https:// link does not push a CSV over the threshold.
    # ------------------------------------------------------------------
    colon_counts = []
    for line in sample:
        # Remove URL schemes so https:// and ftp:// don’t count
        cleaned = line.replace("://", "__PROTO__")
        colon_counts.append(cleaned.count(":"))

    avg_colons = sum(colon_counts) / len(colon_counts) if colon_counts else 0

    # Only treat as ULP when colons dominate over comma fields AND
    # the file doesn’t look like a CSV (avg_fields < 4)
    if avg_colons >= 0.8 and avg_fields < 4:
        logger.info(
            "[classifier] %s looks like ULP (avg %.1f colons, %.1f fields)",
            Path(file_path).name, avg_colons, avg_fields,
        )
        return ClassificationResult(
            file_path=file_path, breach_name=breach_name,
            parser_type="ulp",
            index_name=f"leaks-{breach_name}",
        )

    return None


# ======================================================================
# Unknown file classification
# ======================================================================

def _classify_unknown(file_path: str, breach_name: str) -> ClassificationResult:
    """Fallback for files with unrecognized extensions."""
    return ClassificationResult(
        file_path=file_path, breach_name=breach_name,
        parser_type="forensic",
        index_name=f"leaks-assets-{breach_name}",
        extra={"reason": "unknown_extension"},
    )


# ======================================================================
# Live stream detection
# ======================================================================

def is_live_transaction_file(file_path: str) -> bool:
    """
    Determine if a transaction file should be processed in live stream mode.

    A file is considered *live* ONLY when another process currently has it
    open for writing — detected via ``lsof``.

    The previous heuristics (mtime < 60 s, size > 50 MB) have been removed
    because they produced false positives on static breach dump files:
      - A freshly downloaded/copied dump has a recent mtime but is not live.
      - A 108 MB CSV export is large but complete; tailing it at EOF means
        all existing data is skipped entirely.

    When lsof is unavailable, we default to False (batch mode), which is
    the safe choice — all existing rows are processed normally.
    """
    try:
        result = subprocess.run(
            ["lsof", "-F", "a", file_path],  # -F a → output access mode only
            capture_output=True,
            timeout=5,
        )
        # lsof exits 0 when at least one process has the file open.
        # Access mode 'w' means a process is writing to it.
        if result.returncode == 0 and b"w" in result.stdout:
            logger.info(
                "File %s is open for writing by another process → stream mode",
                file_path,
            )
            return True
    except FileNotFoundError:
        logger.debug("lsof not installed — defaulting to batch mode for %s", file_path)
    except subprocess.TimeoutExpired:
        logger.debug("lsof timed out for %s — defaulting to batch mode", file_path)
    except Exception as exc:
        logger.debug("lsof check failed for %s: %s", file_path, exc)

    return False
