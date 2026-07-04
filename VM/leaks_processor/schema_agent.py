#!/usr/bin/env python3
"""
Schema Discovery Agent.

A read-only intelligence layer that sits beside the pipeline. When a file
yields a high skip rate (records parsed but dropped by the normalizer because
no identity pillar matched), this agent:

  1. Examines the file (CREATE TABLE statements / header / sample rows) using
     fast streaming reads and ripgrep-style scans — never loads the whole file.
  2. Asks the local Ollama LLM to classify each column into a target field
     (email / phone / username / password / address / financial / pii /
     ignore).
  3. Writes the learned mapping to ``config/column_mappings.json``.
  4. Returns the mapping so the caller can immediately re-run the file.

CRITICAL DESIGN CONSTRAINT
--------------------------
The agent NEVER modifies source code. Its only output artifact is
``column_mappings.json``, which the normalizer loads at runtime. This
guarantees the AI cannot corrupt the pipeline — worst case the JSON is wrong,
and the operator deletes it. Code is immutable; knowledge is data.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

import requests

from parsers.sql_dump_parser import extract_columns_from_create

logger = logging.getLogger(__name__)

# Path to the shared knowledge file (relative to project root)
PROJECT_ROOT = Path(__file__).resolve().parent
MAPPINGS_PATH = PROJECT_ROOT / "config" / "column_mappings.json"

# Target fields the normalizer understands (must match normalizer's pilllars)
TARGET_FIELDS = {
    "email", "username", "phone", "password",
    "first_name", "last_name", "full_name",
    "facebook_uid", "facebook_generated_email",
    "address", "city", "region", "country", "postcode",
    "birthdate", "gender",
    "ip",
    # financial / transaction (stored in extra_data.* by the normalizer)
    "user_id", "payment_method", "charge_amount",
    "currency", "transaction_date", "purchase_ref",
    "ignore",  # explicit "do not index" verdict
}


# ---------------------------------------------------------------------------
# Column extractor — works on SQL dumps and flat files
# ---------------------------------------------------------------------------

def _detect_encoding(path: str) -> str:
    """Detect file encoding using BaseParser helper."""
    try:
        from parsers.base_parser import BaseParser
        return BaseParser.detect_encoding(path)
    except Exception:
        return "utf-8"


def _read_head(path: str, max_bytes: int = 200_000) -> str:
    """Read up to max_bytes from the start of a file (memory-bounded)."""
    enc = _detect_encoding(path)
    with open(path, "r", encoding=enc, errors="replace") as f:
        return f.read(max_bytes)


def _read_sample_rows(path: str, n: int = 5) -> list[str]:
    """Read up to n sample data lines (skipping comments/structure)."""
    samples: list[str] = []
    try:
        enc = _detect_encoding(path)
        with open(path, "r", encoding=enc, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("--", "/*", "#", "LOCK", "UNLOCK")):
                    continue
                samples.append(line[:2000])
                if len(samples) >= n:
                    break
    except OSError as exc:
        logger.warning("Could not sample rows from %s: %s", path, exc)
    return samples


# Constraint keywords that look like ```` `name` type ```` but are not columns.
_SQL_CONSTRAINT_KW = {
    "primary", "key", "unique", "constraint", "index", "foreign",
    "check", "fulltext", "spatial",
}

# CREATE TABLE statement scanner. Captures the table name and consumes up to
# the opening "(" of the column body. ``(?:if\s+not\s+exists\s+)?`` makes it
# tolerate ``CREATE TABLE IF NOT EXISTS``. ``\s*\(`` anchors on the real start
# of the column list so we don't match a stray table name in a comment.
_RE_CREATE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?`?(\w+)`?\s*\(",
    re.IGNORECASE,
)


def extract_sql_columns(path: str) -> dict[str, list[str]]:
    """
    Extract ``{table: [columns]}`` from a SQL dump.

    Streams the ENTIRE file in fixed-size chunks and learns every CREATE TABLE
    body it encounters — regardless of how deep into the file the table sits.
    Memory stays flat: at most one CREATE body is buffered at a time (CREATE
    bodies are small; column definitions, not data).

    This replaces the previous head-read + ripgrep approach, which had three
    bugs that together caused only the first few tables to be discovered on
    large dumps:
      1. The ripgrep fallback was gated behind ``len(tables) < 2`` and never
         ran when the first 400 KB already held >=2 CREATE blocks.
      2. ``_read_lines_range`` used a fixed 40-line window and silently dropped
         the trailing columns of wide tables.
      3. ripgrep itself is an external dependency not present on every host.

    The scan uses the same escape- and paren-depth-aware state machine the
    SQL row parser uses, so strings/comments can't trick it into ending a
    CREATE body early.
    """
    tables: dict[str, list[str]] = {}
    enc = _detect_encoding(path)
    chunk_size = 1 << 20  # 1 MiB

    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    if size:
        logger.info(
            "Scanning SQL schema (%.1f MB) for CREATE TABLE blocks: %s",
            size / (1 << 20), Path(path).name,
        )

    buf = ""
    mode = "SCAN"                 # SCAN | BODY
    body_parts: list[str] = []    # accumulated column-body text
    depth = 0                     # paren depth inside the column body
    in_str = False                # inside a string literal
    quote = ""                    # active string quote char
    cur_table = ""

    try:
        with open(path, "r", encoding=enc, errors="replace") as f:
            eof = False
            while True:
                if not eof and len(buf) < chunk_size:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        eof = True
                    else:
                        buf += chunk
                if not buf:
                    break

                if mode == "SCAN":
                    m = _RE_CREATE.search(buf)
                    if not m:
                        # Keep a tail so a keyword split across the chunk
                        # boundary isn't missed.
                        buf = buf[-200:]
                        if eof:
                            break
                        continue

                    cur_table = m.group(1)
                    body_parts = []
                    depth = 1                 # we are now inside the first "("
                    in_str = False
                    quote = ""
                    mode = "BODY"
                    buf = buf[m.end():]        # text after the opening "("
                    continue

                # ---- BODY: accumulate until the matching ")" at depth 0 ----
                i = 0
                n = len(buf)
                finished = False
                while i < n:
                    ch = buf[i]
                    if in_str:
                        if ch == "\\" and i + 1 < n:
                            i += 2
                            continue
                        if ch == quote:
                            in_str = False
                        i += 1
                        continue
                    if ch in ("'", '"', "`"):
                        in_str = True
                        quote = ch
                    elif ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            finished = True
                            break
                    i += 1

                    # Safety valve: a malformed/truncated CREATE body (no
                    # closing paren) must not buffer the whole file. 4 MiB is
                    # far beyond any legitimate column list.
                    if sum(len(p) for p in body_parts) + i > (4 << 20):
                        logger.warning(
                            "CREATE TABLE `%s` body exceeded 4 MiB without "
                            "closing ')' — aborting its schema",
                            cur_table,
                        )
                        finished = True
                        in_str = False
                        depth = 0
                        break

                if finished:
                    body_parts.append(buf[:i])
                    body = "".join(body_parts)
                    cols = extract_columns_from_create(body)
                    if cols:
                        tables[cur_table] = cols
                        logger.info(
                            "Schema learned: `%s` → %d columns",
                            cur_table, len(cols),
                        )
                    mode = "SCAN"
                    buf = buf[i + 1:]
                    continue

                # Need more data to find the closing paren.
                body_parts.append(buf)
                buf = ""
                if eof:
                    break
    except OSError as exc:
        logger.warning("Could not scan SQL schema from %s: %s", path, exc)

    logger.info("SQL schema scan complete: %d tables discovered", len(tables))
    return tables


def extract_flat_columns(path: str) -> tuple[list[str], list[str], str]:
    """
    For a flat file (CSV/TSV/txt), return (headers, sample_rows, delimiter).
    If no header, returns string indices as headers.
    """
    import csv as _csv
    head = _read_head(path, 50_000)
    lines = [l for l in head.splitlines() if l.strip()]
    if not lines:
        return [], [], ","
    # delimiter detection
    candidates = {";": 0, ",": 0, "\t": 0, "|": 0}
    for d in candidates:
        candidates[d] = lines[0].count(d)
    delim = max(candidates, key=candidates.get)

    try:
        first_row = next(_csv.reader([lines[0]], delimiter=delim))
    except Exception:
        first_row = [h.strip().strip('"') for h in lines[0].split(delim)]

    if is_no_header_csv(path):
        headers = [str(i) for i in range(len(first_row))]
        samples = lines[:5]
    else:
        headers = [h.strip().strip('"').strip("'") for h in first_row]
        samples = lines[1:6]

    return headers, samples, delim


# ---------------------------------------------------------------------------
# Ollama classification
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a database schema classifier for data-breach ingestion.
Given table columns and sample data, map each column to ONE of these target fields:

IDENTITY (most important — must map these):
  email, phone, username, password, first_name, last_name, full_name,
  facebook_uid, address, city, region, country, postcode, birthdate, gender, ip

FINANCIAL (stored in extra_data):
  user_id, payment_method, charge_amount, currency, transaction_date, purchase_ref

SPECIAL:
  ignore   (for internal IDs, timestamps, flags, booleans, JSON blobs with no PII)

Rules:
- JSON columns containing names -> full_name
- Phone columns named *_mobile, *_phone, telephone, fax -> phone
- Hash columns (password_hash, pwd, encrypt) -> password
- Internal auto-increment IDs (id, entity_id, *_id) -> ignore
- Timestamps (created_at, updated_at) -> ignore
- Token/session/cache columns -> ignore

Respond ONLY with a JSON object: {"column_name": "target_field"}"""


def classify_columns_ollama(
    columns: list[str],
    table_name: str = "",
    sample_values: dict[str, str] | None = None,
    model: str = "qwen2.5:3b",
    ollama_url: str = "http://127.0.0.1:11434",
) -> dict[str, str]:
    """
    Ask Ollama to classify columns into target fields.
    Returns ``{column: target_field}``.
    """
    sample_values = sample_values or {}
    # build prompt
    lines = [f"Table: {table_name}" if table_name else "Table: (unknown)"]
    for col in columns:
        sv = sample_values.get(col)
        if sv:
            lines.append(f"- {col}  (sample: {sv[:40]})")
        else:
            lines.append(f"- {col}")
    prompt = _SYSTEM_PROMPT + "\n\nColumns to classify:\n" + "\n".join(lines)
    prompt += "\n\nJSON mapping:"

    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 1024},
            },
            timeout=720,
        )
        resp.raise_for_status()
        text = resp.json().get("response", "")
        # extract first {...} block
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            logger.warning("Ollama returned no JSON: %s", text[:200])
            return {}
        mapping = json.loads(m.group(0))
        # validate target fields
        cleaned: dict[str, str] = {}
        for col, tgt in mapping.items():
            tgt = str(tgt).strip().lower()
            if tgt in TARGET_FIELDS:
                cleaned[col] = tgt
            else:
                logger.debug("Ollama returned unknown target %r for %r — skipping", tgt, col)
        return cleaned
    except Exception as exc:
        logger.error("Ollama classification failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Heuristic fallback (no AI) — covers the common cases deterministically
# ---------------------------------------------------------------------------

_HEURISTICS = [
    # (regex against column name, target field)
    (re.compile(r"(^|_)(email|mail|e_mail)($|_)", re.I),          "email"),
    (re.compile(r"(^|_)(phone|mobile|telephone|tel|fax|cellular)($|_)", re.I), "phone"),
    (re.compile(r"(^|_)(password|passwd|pwd|user_pass|encrypt|pass_hash|hash)($|_)", re.I), "password"),
    (re.compile(r"(^|_)(user_?name|login|handle|nick|account_name)($|_)", re.I), "username"),
    (re.compile(r"(^|_)first_?name($|_)", re.I),                   "first_name"),
    (re.compile(r"(^|_)last_?name($|_)", re.I),                    "last_name"),
    (re.compile(r"(^|_)(full_?name|display_?name|name|customer_?name|seller_?name|business_?owner_?name|beneficiary_?name|seller_?owner|seller_?contact_?name|contact_?name)($|_)", re.I), "full_name"),
    (re.compile(r"(^|_)(street|address_line|billing_address|shipping_address)($|_)", re.I), "address"),
    (re.compile(r"(^|_)(city|town)($|_)", re.I),                   "city"),
    (re.compile(r"(^|_)(region|state|province|governorate)($|_)", re.I), "region"),
    (re.compile(r"(^|_)(country|country_code|country_id)($|_)", re.I), "country"),
    (re.compile(r"(^|_)(postal|postcode|zip|zip_?code)($|_)", re.I), "postcode"),
    (re.compile(r"(^|_)(birth_?date|dob|birthday|date_of_birth)($|_)", re.I), "birthdate"),
    (re.compile(r"(^|_)(gender|sex)($|_)", re.I),                   "gender"),
    (re.compile(r"(^|_)(ip_?address|ip_addr|ipv4|ipv6|last_?ip)($|_)", re.I), "ip"),
    (re.compile(r"(^|_)(facebookid|facebook_uid|fb_?id)($|_)", re.I), "facebook_uid"),
    (re.compile(r"(^|_)(street|address)($|_)", re.I),             "address"),
    (re.compile(r"(^|_)(user_?id|customer_?id|uid|account_?id)($|_)", re.I), "user_id"),
    (re.compile(r"(^|_)(payment_?method)($|_)", re.I),            "payment_method"),
    (re.compile(r"(^|_)(charge_?amount|amount|total|price|grand_?total|item_?price)($|_)", re.I), "charge_amount"),
    (re.compile(r"(^|_)(currency|currency_?code)($|_)", re.I),    "currency"),
    (re.compile(r"(^|_)(transaction_?(time|date|timestamp)|created_at|order_?date|date_?order)($|_)", re.I), "transaction_date"),
    (re.compile(r"(^|_)(purchase_?ref|order_?id|order_?number|reference_?id)($|_)", re.I), "purchase_ref"),
]


def classify_columns_heuristic(columns: list[str]) -> dict[str, str]:
    """
    Deterministic column→target mapping using regex heuristics.
    Used as a fast first pass and as a fallback when Ollama is unavailable.
    """
    mapping: dict[str, str] = {}
    for col in columns:
        lower = col.lower()
        matched = False
        for pattern, target in _HEURISTICS:
            if pattern.search(lower):
                mapping[col] = target
                matched = True
                break
        # explicitly mark unmapped columns as ignore so the agent doesn't
        # re-classify them every run
        if not matched:
            mapping[col] = "ignore"
    return mapping


# ---------------------------------------------------------------------------
# Mappings file I/O
# ---------------------------------------------------------------------------

def load_mappings() -> dict[str, Any]:
    """Load the shared column_mappings.json (returns {} if absent/invalid)."""
    if not MAPPINGS_PATH.exists():
        return {}
    try:
        return json.loads(MAPPINGS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.error("column_mappings.json corrupt: %s — ignoring", exc)
        return {}


def save_mappings(mappings: dict[str, Any]) -> None:
    """Atomically write the mappings file (temp + rename)."""
    MAPPINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = MAPPINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(mappings, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(MAPPINGS_PATH)
    logger.info("Saved %d column mappings to %s", len(mappings.get("column_aliases", {})), MAPPINGS_PATH)


# ---------------------------------------------------------------------------
# Public API — discover and persist
# ---------------------------------------------------------------------------

def classify_tables_importance_ollama(
    tables: dict[str, list[str]],
    model: str | None = None,
    ollama_url: str | None = None,
) -> list[str]:
    """
    Ask Ollama to identify which tables contain PII or important organizational/personal info.
    Returns a list of important table names.
    """
    from config.settings import OLLAMA_MODEL, OLLAMA_URL
    model = model or OLLAMA_MODEL
    ollama_url = ollama_url or OLLAMA_URL
    
    if not tables:
        return []
        
    candidate_tables = tables
    skipped_tables = []
    
    # Pre-filtering candidates when there are too many tables (to reduce context and prompt latency)
    if len(tables) > 15:
        from parsers.sql_dump_parser import DEFAULT_IGNORE_TABLES
        pii_pattern = re.compile(
            r"(email|mail|phone|tel|mobile|pass|pwd|user|login|member|customer|admin|name|address|street|city|zip|postal|country|state|region|ip|birth|dob|gender|sex|card|pay|trans|order|charge|amount)",
            re.IGNORECASE
        )
        candidate_tables = {}
        for t_name, cols in tables.items():
            t_lower = t_name.lower()
            # 1. Skip default ignore tables
            if t_lower in DEFAULT_IGNORE_TABLES:
                skipped_tables.append(t_name)
                continue
            # 2. Skip typical system/log tables by substring
            if any(x in t_lower for x in ("_cache", "_session", "_log", "_index", "cache_", "session_", "log_", "temp_", "_tmp")):
                skipped_tables.append(t_name)
                continue
            # 3. Must match PII keywords in columns
            if any(pii_pattern.search(col) for col in cols):
                candidate_tables[t_name] = cols
            else:
                skipped_tables.append(t_name)
        
        if not candidate_tables:
            # If everything was filtered out, fallback to everything except DEFAULT_IGNORE_TABLES
            candidate_tables = {
                t_name: cols for t_name, cols in tables.items()
                if t_name.lower() not in DEFAULT_IGNORE_TABLES
            }
            logger.info("No candidates matched PII pattern — falling back to %d non-default-ignored tables", len(candidate_tables))
        else:
            logger.info(
                "Pre-filtered %d tables down to %d candidates (skipped %d ignored/metadata tables)",
                len(tables), len(candidate_tables), len(skipped_tables)
            )

    # Chunk candidates into batches of 40 to avoid context overflow and huge latencies
    candidate_list = list(candidate_tables.items())
    batch_size = 40
    important_tables_set = set()
    
    for start_idx in range(0, len(candidate_list), batch_size):
        batch = dict(candidate_list[start_idx : start_idx + batch_size])
        if len(candidate_list) > batch_size:
            logger.info(
                "Classifying table batch %d-%d of %d...",
                start_idx + 1, min(start_idx + batch_size, len(candidate_list)), len(candidate_list)
            )
            
        # Build schema summary for this batch
        schema_summary = []
        for table_name, cols in batch.items():
            cols_str = ", ".join(cols[:15]) + ("..." if len(cols) > 15 else "")
            schema_summary.append(f"- Table '{table_name}' with columns: {cols_str}")
            
        schema_block = "\n".join(schema_summary)
        prompt = f"""You are a database classification expert for forensic data security and breach detection.
Analyze the following database structure (tables and columns) and identify which tables are IMPORTANT (contain PII or critical user/financial/organizational data) and should be processed, versus which tables are UNIMPORTANT garbage (logs, cache, sessions, catalog list index, CSS, system config, design, translations) and should be ignored.

Important data examples:
- User accounts, credentials, profile details, customer info, student/employee records
- Addresses, phone numbers, emails, passwords/hashes, SSN, national IDs, genders, birthdates
- Financial transactions, orders, payments, invoices, purchases

Unimportant garbage examples:
- Visit logs, web session caches, system configurations, layout designs, cron logs, product categories, translation tables, temporary cache tables, metadata logs.

Database Tables to Analyze:
{schema_block}

Determine which tables are important.
Respond ONLY with a JSON list of strings containing the exact names of the important tables. Do not include any explanation or markdown other than the JSON array.
Example response: ["users", "customers", "orders", "payments"]

JSON List:"""

        try:
            resp = requests.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 1024},
                },
                timeout=720,  # was 60 second timeout per batch
            )
            resp.raise_for_status()
            text = resp.json().get("response", "")
            batch_important = []
            start_idx = text.find("[")
            if start_idx != -1:
                try:
                    batch_important, _ = json.JSONDecoder().raw_decode(text[start_idx:])
                except json.JSONDecodeError:
                    m = re.search(r"\[.*\]", text, re.DOTALL)
                    if m:
                        try:
                            batch_important = json.loads(m.group(0))
                        except Exception:
                            pass
            if batch_important:
                for t in batch_important:
                    important_tables_set.add(t.lower().strip())
            else:
                logger.warning("Ollama returned no JSON list for batch: %s", text[:200])
                for t in batch:
                    important_tables_set.add(t.lower().strip())
        except Exception as exc:
            logger.error("Ollama classification failed for batch: %s", exc)
            for t in batch:
                important_tables_set.add(t.lower().strip())

    # Ensure exact match in lower case, but return original table names
    result = [t for t in tables if t.lower().strip() in important_tables_set]
    logger.info("[AI] Table classification complete. Important tables: %s", result)
    return result


def get_sql_table_samples(path: str, table_name: str, columns: list[str], n_rows: int = 10) -> list[dict]:
    """
    Fast scan of a SQL dump to find the first n_rows of a specific table.
    Does not load the file into memory. Returns a list of dicts.
    """
    from parsers.sql_dump_parser import _InsertScanner
    # Case-insensitive match for INSERT INTO `table` or INSERT INTO table
    pattern = re.compile(
        r"insert\s+into\s+`?" + re.escape(table_name) + r"`?\b",
        re.IGNORECASE,
    )
    values_pattern = re.compile(r"values\s*", re.IGNORECASE)
    
    samples: list[dict] = []
    chunk_size = 1 << 16  # 64 KB chunks for fast scanning
    buf = ""
    scanner = None
    
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            while len(samples) < n_rows:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buf += chunk
                
                if scanner is None:
                    m = pattern.search(buf)
                    if not m:
                        # Keep last 100 chars to avoid splitting keyword
                        buf = buf[-100:]
                        continue
                    # Found the INSERT statement!
                    # Find the VALUES keyword after it
                    after_insert = buf[m.end():]
                    vm = values_pattern.search(after_insert)
                    if not vm:
                        buf = buf[m.start():]
                        continue
                    # Start scanning rows
                    scanner = _InsertScanner(table_name, columns, max_row_bytes=1000000)
                    buf = after_insert[vm.end():]
                
                if scanner is not None:
                    consumed, rows, done = scanner.feed(buf)
                    buf = buf[consumed:]
                    samples.extend(rows)
                    if len(samples) >= n_rows:
                        break
                    if done:
                        scanner = None
    except Exception as exc:
        logger.warning("Error scanning sample rows for %s: %s", table_name, exc)
        
    return samples[:n_rows]


def classify_table_columns_with_samples_ollama(
    table_name: str,
    columns: list[str],
    samples: list[dict],
    model: str | None = None,
    ollama_url: str | None = None,
) -> dict[str, str]:
    """
    Ask Ollama to classify columns into target fields using the table structure
    AND 5-10 sample rows. Returns ``{column: target_field}``.
    """
    from config.settings import OLLAMA_MODEL, OLLAMA_URL
    model = model or OLLAMA_MODEL
    ollama_url = ollama_url or OLLAMA_URL

    # Format the samples nicely for the prompt
    sample_lines = []
    for idx, row in enumerate(samples, 1):
        # Filter out metadata fields for cleaner prompt
        cleaned_row = {k: v for k, v in row.items() if not k.startswith("_")}
        sample_lines.append(f"Row {idx}: {json.dumps(cleaned_row, ensure_ascii=False)}")
    sample_text = "\n".join(sample_lines)

    prompt = f"""{_SYSTEM_PROMPT}

You are analyzing table '{table_name}' with the following structure (columns) and sample rows:

Columns to classify:
{", ".join(columns)}

Sample Rows (first {len(samples)} rows):
{sample_text}

Analyze the column names and the actual values in the sample rows to map each column to its correct target field.
Respond ONLY with a JSON object: {{"column_name": "target_field"}}"""

    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 1024},
            },
            timeout=720,
        )
        resp.raise_for_status()
        text = resp.json().get("response", "")
        mapping = {}
        start_idx = text.find("{")
        if start_idx != -1:
            try:
                mapping, _ = json.JSONDecoder().raw_decode(text[start_idx:])
            except json.JSONDecodeError:
                m = re.search(r"\{.*\}", text, re.DOTALL)
                if m:
                    try:
                        mapping = json.loads(m.group(0))
                    except Exception:
                        pass
        if not mapping:
            logger.warning("Ollama returned no valid JSON object for column classification: %s", text[:200])
            return {}
        # validate target fields
        cleaned: dict[str, str] = {}
        for col, tgt in mapping.items():
            tgt = str(tgt).strip().lower()
            if tgt in TARGET_FIELDS:
                cleaned[col] = tgt
        logger.info("[AI] Classified columns for table '%s': %s", table_name, cleaned)
        return cleaned
    except Exception as exc:
        logger.error("[AI] Sample-based column classification failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Alias-key validation
# ---------------------------------------------------------------------------

_RE_JUNK_KEY = re.compile(
    r"^(?:"                                   # reject if the whole key matches:
    r"\d+$"                                   #   pure numeric (national IDs, amounts)
    r"|[^@\s]+@[^@\s]+\.[^@\s]+$"            #   email-shaped
    r"|^\{.*\}$"                              #   JSON fragment
    r"|.{200,}"                               #   absurdly long (≥200 chars)
    r"|[\x00-\x08\x0e-\x1f]"                 #   control chars (except tab/newline)
    r")$",
)

def _is_valid_alias_key(key: str) -> bool:
    """
    Return False when *key* is clearly a data value promoted as a header name.
    """
    if not key or not key.strip():
        return False
    key_stripped = key.strip()
    # Reject obvious data values
    if _RE_JUNK_KEY.match(key_stripped):
        return False
    # Reject mojibake/Unicode replacement char
    if "\ufffd" in key_stripped or "" in key_stripped:
        return False
    # Reject keys with JSON/SQL structures
    if any(c in key_stripped for c in ('[', ']', '{', '}', '"', "'")):
        return False
    # Reject keys longer than 50 characters (almost certainly data)
    if len(key_stripped) > 50:
        return False
    return True


def discover_file_schema(file_path: str, use_ai: bool = True, breach_name: str = "unknown") -> dict:
    """
    Examine a file, classify its columns, and write the result to
    column_mappings.json. Returns the new/updated mappings dict.
    """
    mappings = load_mappings()
    aliases: dict[str, str] = mappings.get("column_aliases", {})
    sources: dict[str, Any] = mappings.get("_sources", {})

    ext = Path(file_path).suffix.lower()
    method = "heuristic"
    tables: dict[str, list[str]] = {}
    flat_headers: list[str] = []
    delim: str | None = None

    if ext == ".sql":
        tables = extract_sql_columns(file_path)
    else:
        flat_headers, _samples, delim = extract_flat_columns(file_path)
        tables = {"_flat": flat_headers} if flat_headers else {}

    if not tables:
        logger.warning("No columns discovered in %s", file_path)
        return mappings

    # ---- Table classification pass ----
    from config.settings import OLLAMA_MODEL, OLLAMA_URL
    
    important_tables = list(tables.keys())
    if ext == ".sql" and use_ai:
        logger.info("Asking Ollama to identify important tables in %s", Path(file_path).name)
        important_tables = classify_tables_importance_ollama(tables, model=OLLAMA_MODEL, ollama_url=OLLAMA_URL)
        method = "heuristic+ai_tables"
    
    if not important_tables:
        important_tables = list(tables.keys())

    # ---- Columns classification pass ----
    final_aliases: dict[str, str] = {}
    new_mappings_learned = False
    
    for table_name in important_tables:
        cols = tables[table_name]
        if not cols:
            continue
            
        # 1. heuristic pass first
        heur = classify_columns_heuristic(cols)
        
        # 2. Check if mapping failed or is ambiguous
        identity_pillars = {"email", "phone", "username", "password", "full_name", "first_name", "last_name", "facebook_uid"}
        financial_pillars = {"user_id", "payment_method", "charge_amount", "currency", "transaction_date", "purchase_ref"}
        
        has_identity = any(v in identity_pillars for v in heur.values())
        has_financial = any(v in financial_pillars for v in heur.values())
        
        mapping_failed = not (has_identity or has_financial)
        is_ambiguous = any(c.isdigit() or c.lower().startswith("col_") for c in cols)
        
        if table_name == "_flat" and is_ambiguous:
            mapping_failed = True
            
        table_aliases = dict(heur)
        
        if use_ai and (mapping_failed or is_ambiguous):
            logger.info("Column mapping failed/ambiguous for table '%s'. Extracting samples...", table_name)
            samples = []
            if ext == ".sql":
                samples = get_sql_table_samples(file_path, table_name, cols, n_rows=10)
            else:
                # Flat file samples
                _, raw_samples, delim = extract_flat_columns(file_path)
                import csv as _csv
                # parse raw lines into dicts
                delim_to_use = ","
                if raw_samples:
                    candidates = {";": 0, ",": 0, "\t": 0, "|": 0}
                    for d in candidates:
                        candidates[d] = raw_samples[0].count(d)
                    delim_to_use = max(candidates, key=candidates.get)
                for r in raw_samples:
                    try:
                        row_vals = next(_csv.reader([r], delimiter=delim_to_use))
                        row_dict = {cols[i]: row_vals[i] for i in range(min(len(cols), len(row_vals)))}
                        samples.append(row_dict)
                    except Exception:
                        pass
            
            if samples:
                ai = classify_table_columns_with_samples_ollama(
                    table_name, cols, samples, model=OLLAMA_MODEL, ollama_url=OLLAMA_URL
                )
                if ai:
                    table_aliases.update(ai)
                    if method == "heuristic+ai_tables":
                        method = "heuristic+ai_tables+ai_columns"
                    elif method == "heuristic":
                        method = "heuristic+ai_columns"
        
        final_aliases.update(table_aliases)

    # Merge into the global aliases (new columns added; existing preserved)
    new_count = 0
    rejected = 0
    for col, tgt in final_aliases.items():
        col_lower = col.strip().lower()
        if not _is_valid_alias_key(col_lower):
            logger.debug("[schema] rejected junk alias key %r → %s", col, tgt)
            rejected += 1
            continue
        existing = aliases.get(col_lower)
        if existing != tgt:
            if existing == "ignore" and tgt != "ignore":
                aliases[col_lower] = tgt
                new_count += 1
            elif not existing:
                aliases[col_lower] = tgt
                new_count += 1

    sources[file_path] = {
        "tables": tables,
        "important_tables": important_tables,
        "column_count": sum(len(cols) for cols in tables.values()),
        "method": method,
    }
    mappings["column_aliases"] = aliases
    mappings["_sources"] = sources

    if new_count or ext == ".sql":
        save_mappings(mappings)
        logger.info("Schema agent: learned %d new column mappings from %s",
                    new_count, Path(file_path).name)
    else:
        logger.info("Schema agent: no new mappings for %s", Path(file_path).name)

    # Isolated schema indexing: upload blueprint to leaks-schema-{breach_name}
    try:
        from utils.index_utils import ensure_index, single_doc_upload, DATABASE_SCHEMA_INDEX_MAPPING
        schema_index_name = f"leaks-schema-{breach_name}"
        if ensure_index(schema_index_name, DATABASE_SCHEMA_INDEX_MAPPING):
            scanned_at = datetime.now(timezone.utc).isoformat()
            tables_list = []
            for t_name, cols in tables.items():
                is_imp = t_name in important_tables
                tables_list.append({
                    "table_name": t_name,
                    "columns": cols,
                    "row_count_estimate": 0,
                    "is_important": is_imp
                })
            
            schema_doc = {
                "file_path": file_path,
                "breach_source": breach_name,
                "file_type": ext.lstrip("."),
                "tables": tables_list,
                "delimiter": delim if ext != ".sql" else None,
                "columns": flat_headers if ext != ".sql" else None,
                "method": method,
                "scanned_at": scanned_at,
            }
            single_doc_upload(schema_index_name, schema_doc)
            logger.info("Uploaded schema blueprint to Elasticsearch index: %s", schema_index_name)
    except Exception as exc:
        logger.warning("Could not upload schema blueprint to Elasticsearch: %s", exc)

    return mappings


# ---------------------------------------------------------------------------
# Pre-flight discovery — proactive schema learning before batch parsing
# ---------------------------------------------------------------------------

# Track files already discovered in this process run to avoid re-work
_PREFLIGHT_DONE: set[str] = set()


def pre_flight_discover(file_path: str, use_ai: bool = True, breach_name: str = "unknown") -> dict:
    """
    Proactively discover and persist column mappings for *file_path* BEFORE
    the normalizer processes it.

    Differs from ``discover_file_schema`` in two ways:
      1. Idempotent within a process run — skips files already analysed.
      2. Always runs AI for columns not matched by heuristics (when use_ai=True),
         because accuracy matters more than speed at this pre-parse stage.

    Returns the (possibly updated) mappings dict.
    """
    if file_path in _PREFLIGHT_DONE:
        return load_mappings()

    logger.info("[pre-flight] Analysing schema for: %s", Path(file_path).name)
    mappings = discover_file_schema(file_path, use_ai=use_ai, breach_name=breach_name)
    _PREFLIGHT_DONE.add(file_path)

    # Reload normalizer aliases so the mapping is live for this batch
    try:
        from pipeline.normalizer import reload_aliases
        reload_aliases()
        logger.info("[pre-flight] Normalizer aliases reloaded.")
    except Exception as exc:
        logger.warning("[pre-flight] Could not reload aliases: %s", exc)

    return mappings


def is_no_header_csv(file_path: str, sample_lines: int = 3) -> bool:
    """
    Heuristic check: return True when the first row of a CSV/TSV appears to be
    DATA rather than column headers.

    A row is considered a *data* row (not a header) when:
      - It contains purely numeric tokens, e-mail addresses, UUIDs, or IP
        addresses in the first several fields, OR
      - None of its tokens match any known column alias key in
        column_mappings.json or the built-in alias table.

    This is intentionally conservative — when in doubt we return False
    (i.e. treat the file as header-based) to avoid misclassifying exotic
    header names as data.
    """
    import csv, re as _re

    _NUM     = _re.compile(r'^-?\d+(\.\d+)?$')
    _EMAIL   = _re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
    _UUID    = _re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', _re.I)
    _IP      = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    _TS_NUM  = _re.compile(r'^\d{10,13}$')  # unix timestamps

    data_signals = (_NUM, _EMAIL, _UUID, _IP, _TS_NUM)

    try:
        enc = _detect_encoding(file_path)
        with open(file_path, 'r', encoding=enc, errors='replace') as f:
            first_line = f.readline()
            if not first_line.strip():
                return False
            delimiters = [";", "\t", "|", ","]
            best_delim = ","
            best_count = 0
            for delim in delimiters:
                count = first_line.count(delim)
                if count > best_count:
                    best_count = count
                    best_delim = delim
            
            f.seek(0)
            reader = csv.reader(f, delimiter=best_delim)
            first_row = next(reader, [])
    except Exception:
        return False

    if not first_row:
        return False

    # Load known aliases to check if first-row tokens look like column names
    mappings = load_mappings()
    known_aliases = set(k.lower() for k in mappings.get('column_aliases', {}))

    # Check first N tokens (up to 8) from the first row
    tokens = [t.strip().strip('"') for t in first_row[:8]]
    data_hits = sum(1 for t in tokens if any(p.match(t) for p in data_signals))
    alias_hits = sum(1 for t in tokens if t.lower() in known_aliases)

    # If more than half the tokens are clearly data patterns → no header
    if data_hits >= max(1, len(tokens) // 2):
        logger.info(
            "[is_no_header_csv] %s — %d/%d tokens look like data → treating as no-header",
            Path(file_path).name, data_hits, len(tokens),
        )
        return True

    # If zero tokens match known column aliases and there are obvious data
    # signals → probably headerless
    if alias_hits == 0 and data_hits > 0:
        logger.info(
            "[is_no_header_csv] %s — no alias matches and %d data signals → no-header",
            Path(file_path).name, data_hits,
        )
        return True

    return False


def _sample_values_for(path: str, columns: list[str]) -> dict[str, str]:
    """Best-effort: pull one sample value per column from the file head."""
    samples: dict[str, str] = {}
    rows = _read_sample_rows(path, n=100)
    if not rows:
        return samples
    # delimiter detection
    candidates = {";": 0, ",": 0, "\t": 0, "|": 0}
    for d in candidates:
        candidates[d] = rows[0].count(d)
    delim = max(candidates, key=candidates.get)

    for row in rows:
        try:
            import csv as _csv
            parts = next(_csv.reader([row], delimiter=delim))
        except Exception:
            parts = [p.strip().strip("'\"") for p in row.split(delim)]

        for i, col in enumerate(columns):
            if col not in samples and i < len(parts):
                val = parts[i].strip().strip("'\"")
                if val and val.lower() not in ("null", "", "n/a", "-"):
                    samples[col] = val[:100]
    return samples


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Schema Discovery Agent")
    p.add_argument("file", help="File to examine")
    p.add_argument("--no-ai", action="store_true", help="Use heuristics only")
    p.add_argument("--show", action="store_true", help="Print mappings after")
    args = p.parse_args()

    mappings = discover_file_schema(args.file, use_ai=not args.no_ai)
    if args.show:
        print(json.dumps(mappings, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
