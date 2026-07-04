"""
Record normalizer — transforms raw parsed records into Elasticsearch-ready documents.

Supports three modes:
  1. **Identity mode** — Three-Pillar extraction (email, username, phone)
  2. **Transaction mode** — Maps financial/transaction fields for Udemy-style data
  3. **AI mode** — Uses Ollama for Arabic/no-header column detection (with caching)

The normalizer does NOT upload — it returns a list of ES-ready dicts.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

import requests

from config.settings import (
    OLLAMA_URL, OLLAMA_MODEL, AI_CONFIDENCE_THRESHOLD,
    TRANSACTION_SEARCHABLE_FIELDS, EMBEDDED_JSON_FIELDS,
    COLUMN_MAPS,
)
from parsers.base_parser import ParsedRecord

logger = logging.getLogger(__name__)

# Cache for AI column detections
_AI_CACHE: dict[str, dict] = {}

# Password hash patterns
HASH_PATTERNS = {
    "bcrypt": re.compile(r"^\$2[aby]\$\d{2}\$"),
    "phpass": re.compile(r"^\$P\$"),
    "md5":    re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1":   re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "ntlm":   re.compile(r"^[A-Fa-f0-9]{32}$"),
}


def normalize_batch(records: list[ParsedRecord],
                    mode: str = "identity",
                    breach_source: str = "",
                    index_name: str = "") -> tuple[list[dict], list[dict]]:
    """
    Normalize a batch of ParsedRecords into ES-ready documents.

    Args:
        records: List of ParsedRecord objects from a parser.
        mode: "identity", "transaction", or "ai".
        breach_source: Breach identifier for the documents.
        index_name: Target ES index name.

    Returns:
        Tuple of (documents, stats) where stats has counts.
    """
    docs = []
    stats = {"total": len(records), "identity": 0, "transaction": 0,
             "skipped": 0, "ai_resolved": 0}

    now = datetime.now(timezone.utc).isoformat()

    for record in records:
        try:
            if mode == "transaction":
                doc = _normalize_transaction(record, breach_source, now)
                stats["transaction"] += 1
            elif mode == "ai":
                doc = _normalize_with_ai(record, breach_source, now)
                stats["ai_resolved"] += 1
            else:
                doc = _normalize_identity(record, breach_source, now)
                stats["identity"] += 1

            if doc:
                doc["_index"] = index_name
                docs.append(doc)
        except Exception as exc:
            logger.warning("Normalizer error on line %d: %s", record.line_number, exc)
            stats["skipped"] += 1

    return docs, stats


def normalize_single(record: ParsedRecord,
                     mode: str = "identity",
                     breach_source: str = "") -> dict | None:
    """
    Normalize a single record — used by the streaming SQL path where records
    arrive one at a time and must be flushed immediately to bound memory.

    Returns the ES-ready dict, or None if the record has no identity pillars.
    """
    now = datetime.now(timezone.utc).isoformat()
    try:
        if mode == "transaction":
            return _normalize_transaction(record, breach_source, now)
        if mode == "ai":
            return _normalize_with_ai(record, breach_source, now)
        return _normalize_identity(record, breach_source, now)
    except Exception as exc:
        logger.warning("normalize_single error on line %d: %s",
                       record.line_number, exc)
        return None


# ======================================================================
# Dynamic column aliasing (loaded from config/column_mappings.json)
# ======================================================================

# Built-in fallback aliases — used when the JSON file is absent or a column
# isn't listed in it. The schema_agent extends this at runtime.
_BUILTIN_ALIASES: dict[str, str] = {
    "email": "email", "mail": "email", "e_mail": "email",
    "email_address": "email", "customer_email": "email",
    "phone": "phone", "mobile": "phone", "telephone": "phone",
    "tel": "phone", "telephone_mobile": "phone",
    "username": "username", "user_name": "username", "login": "username",
    "handle": "username", "nick": "username",
    "password": "password", "password_raw": "password", "pass": "password",
    "pwd": "password", "passwd": "password", "user_pass": "password",
    "memberspasshash": "password", "password_hash": "password",
    "encrypt": "password", "hash": "password", "pass_hash": "password",
    "first_name": "first_name", "firstname": "first_name",
    "firstname": "first_name", "fname": "first_name",
    "last_name": "last_name", "lastname": "last_name", "lname": "last_name",
    "full_name": "full_name", "fullname": "full_name", "name": "full_name",
    "display_name": "full_name",
    "facebookid": "facebook_uid", "facebook_id": "facebook_uid",
    "facebook_uid": "facebook_uid",
    "facebook_generated_email": "facebook_generated_email",
    "address": "address", "street": "address",
    "city": "city", "town": "city",
    "region": "region", "state": "region",
    "country": "country", "country_id": "country",
    "postcode": "postcode", "zip": "postcode", "postal_code": "postcode",
    "birthdate": "birthdate", "birth_date": "birthdate",
    "dob": "birthdate", "birthday": "birthdate",
    "ip": "ip", "ip_address": "ip", "ipaddress": "ip",
    "url": "url", "site": "url", "website": "url", "web_site": "url", "link": "url",
}

# All valid target fields (columns that map to these are indexed as pillars
# or as a named extra_data key).
_VALID_TARGETS = {
    "email", "phone", "username", "password",
    "url", "first_name", "last_name", "full_name",
    "facebook_uid", "facebook_generated_email",
    "address", "city", "region", "country", "postcode",
    "birthdate", "gender", "ip",
    "user_id", "payment_method", "charge_amount",
    "currency", "transaction_date", "purchase_ref",
}

# Lazily-loaded merged alias table (built once, cached at module level).
_ALIAS_CACHE: dict[str, str] | None = None


def _load_aliases() -> dict[str, str]:
    """
    Merge built-in aliases with the AI-maintained column_mappings.json.
    The JSON file wins (operator/AI-curated) over the built-in defaults.
    """
    global _ALIAS_CACHE
    if _ALIAS_CACHE is not None:
        return _ALIAS_CACHE

    aliases = dict(_BUILTIN_ALIASES)
    try:
        from pathlib import Path
        mappings_path = Path(__file__).resolve().parent.parent / "config" / "column_mappings.json"
        if mappings_path.exists():
            import json as _json
            data = _json.loads(mappings_path.read_text(encoding="utf-8"))
            learned = data.get("column_aliases", {})
            for col, tgt in learned.items():
                tgt = str(tgt).strip().lower()
                if tgt in _VALID_TARGETS or tgt == "ignore":
                    aliases[col] = tgt
    except Exception as exc:
        logger.warning("Could not load column_mappings.json: %s", exc)

    _ALIAS_CACHE = aliases
    logger.info("Loaded %d column aliases (%d from column_mappings.json)",
                len(aliases),
                len(aliases) - len(_BUILTIN_ALIASES))
    return aliases


def reload_aliases():
    """Force a reload of the alias table (used after schema_agent runs)."""
    global _ALIAS_CACHE
    _ALIAS_CACHE = None
    _load_aliases()


def _remap_fields(fields: dict) -> dict:
    """
    Rename record fields to canonical targets using the alias table.

    - Fields mapped to a known target (except "ignore") are renamed to that target.
    - Fields with no alias (or mapped to "ignore") are left as-is (so unknown data isn't lost).
    - Metadata keys (``_source_table`` etc.) are preserved.
    """
    aliases = _load_aliases()
    out: dict[str, Any] = {}
    for key, val in fields.items():
        if key.startswith("_"):
            out[key] = val          # preserve parser metadata
            continue
        tgt = aliases.get(key.lower())
        if tgt and tgt != "ignore":
            # Preserve the first value per target if two columns collide
            if tgt not in out or not out[tgt]:
                out[tgt] = val
        else:
            out[key] = val          # keep original name, goes to extra_data downstream
    return out


def _sanitize_date(val: str | None) -> str | None:
    """
    Sanitizes date strings to prevent Elasticsearch mapping exceptions.
    Many SQL dumps use '0000-00-00' or '0000-00-00 00:00:00' as placeholder
    dates, which are rejected by ES strict_date_optional_time parsers.
    Also normalizes space separators in datetime strings to 'T' for ISO 8601 compliance.
    """
    if not val:
        return None
    val = str(val).strip()
    if val.startswith("0000-00-00") or val in ("0", "1/1/0001 12:00:00 AM"):
        return None
    # Replace space with T for ISO 8601 compatibility (e.g. "YYYY-MM-DD HH:MM:SS" -> "YYYY-MM-DDTHH:MM:SS")
    if " " in val:
        parts = val.split(" ")
        if len(parts) == 2 and "-" in parts[0] and ":" in parts[1]:
            val = f"{parts[0]}T{parts[1]}"
    return val


# ======================================================================
# Identity mode — Three-Pillar extraction
# ======================================================================

def _normalize_identity(record: ParsedRecord, breach_source: str,
                        indexed_at: str) -> dict | None:
    """
    Extract identity fields using the Three-Pillar model:
      Pillar 1: email
      Pillar 2: username (derived from name fields or explicit username)
      Pillar 3: phone

    Additional fields go into extra_data.

    Column names are normalized to canonical targets via column_mappings.json
    BEFORE extraction, so any new schema the AI learned is applied here.
    """
    # Remap to canonical field names using the (AI-extensible) alias table
    fields = _remap_fields(record.fields)
    doc: dict[str, Any] = {
        "breach_source": breach_source,
        "indexed_at": indexed_at,
    }

    extra_data: dict[str, Any] = {}

    # --- Pillar 1: Email ---
    email = fields.get("email")
    if email:
        doc["email"] = str(email).strip().lower()

    # --- Pillar 2: Username ---
    username = fields.get("username")
    if username:
        doc["username"] = str(username).strip()

    # --- Pillar 2b: URL ---
    url_val = fields.get("url")
    if url_val:
        doc["url"] = str(url_val).strip()

    # --- Pillar 3: Phone ---
    phone = fields.get("phone")
    if phone:
        doc["phone"] = _normalize_phone(str(phone))

    # --- Facebook UID (for Egypt dataset cross-reference) ---
    fb_uid = fields.get("facebook_uid")
    if fb_uid:
        doc["facebook_uid"] = str(fb_uid).strip()

    # --- Facebook generated email (col 19 from Egypt — do NOT put in email pillar) ---
    fb_email = fields.get("facebook_generated_email")
    if fb_email and str(fb_email).endswith("@facebook.com"):
        extra_data["facebook_generated_email"] = str(fb_email).strip()

    # --- Password handling ---
    password_raw = fields.get("password")
    if password_raw:
        pw_type = _detect_password_type(str(password_raw))
        if pw_type == "plaintext":
            doc["password_raw"] = str(password_raw)
        else:
            doc["password_hash"] = str(password_raw)
            doc["password_type"] = pw_type

    # password_type may already be set by the parser
    password_type = fields.get("password_type")
    if password_type and "password_type" not in doc:
        doc["password_type"] = password_type

    # --- Location / profile fields → extra_data ---
    for loc_key in ("first_name", "last_name", "full_name",
                     "city", "region", "country", "postcode", "address",
                     "birthdate", "gender", "ip",
                     "user_id", "payment_method", "charge_amount",
                     "currency", "transaction_date", "purchase_ref"):
        val = fields.get(loc_key)
        if val:
            val_str = str(val).strip()
            if loc_key in ("birthdate", "transaction_date"):
                val_str = _sanitize_date(val_str)
            if val_str:
                extra_data[loc_key] = val_str

    # --- Extra data from raw tokens (ULP parser) ---
    if "extra_data" in fields and isinstance(fields["extra_data"], dict):
        extra_data.update(fields["extra_data"])

    # --- Explicit extra_data.* keys (from JSON parser flattening) ---
    for key in list(fields.keys()):
        if key.startswith("extra_data.") and fields[key]:
            sub_key = key.split(".", 1)[1]
            extra_data[sub_key] = fields[key]

    # --- Pass through any remaining non-core fields as extra_data ---
    # Metadata keys injected by parsers (leading underscore) are never indexed.
    core_fields = {
        "email", "username", "phone", "password_raw", "password_hash",
        "password_type", "facebook_uid", "facebook_generated_email",
        "extra_data", "domain", "hash_flag", "id", "url",
        "first_name", "last_name", "full_name",
        "city", "region", "country", "postcode", "address",
        "birthdate", "gender", "ip",
        "user_id", "payment_method", "charge_amount",
        "currency", "transaction_date", "purchase_ref",
        "password",
    }
    for key, val in fields.items():
        if key.startswith("_"):
            continue  # parser metadata (e.g. _source_table from SQL parser)
        if key in core_fields or not val or key in doc or key in extra_data:
            continue
        extra_data[key] = val

    # --- Pack extra_data into doc ---
    if extra_data:
        doc["extra_data"] = extra_data

    # Require at least one identity pillar
    if not any(doc.get(p) for p in ("email", "username", "phone", "facebook_uid", "url")):
        return None

    return doc


# ======================================================================
# Transaction mode — financial/transaction field mapping
# ======================================================================

def _normalize_transaction(record: ParsedRecord, breach_source: str,
                           indexed_at: str) -> dict | None:
    """
    Normalize a transaction record using the TRANSACTION_SEARCHABLE_FIELDS mapping.

    Extracts top-level fields and embedded JSON sub-fields into flat extra_data.
    """
    fields = record.fields
    doc: dict[str, Any] = {
        "breach_source": breach_source,
        "indexed_at": indexed_at,
    }

    extra_data: dict[str, Any] = {}

    # Map transaction fields
    for src_col, dest_path in TRANSACTION_SEARCHABLE_FIELDS.items():
        val = _extract_field(fields, [src_col])
        if val:
            # Convert empty-ish strings to None
            val = val.strip()
            if val.lower() in ("null", "none", "", "n/a", "-"):
                val = None
            if val is not None:
                if "date" in dest_path:
                    val = _sanitize_date(val)
                if val:
                    extra_data[dest_path.replace("extra_data.", "")] = val

    # Extract embedded JSON sub-fields (already parsed by structured_table_parser).
    # EMBEDDED_JSON_FIELDS values are list[tuple[src_key, dest_path]] — not dicts.
    for json_col, sub_mappings in EMBEDDED_JSON_FIELDS.items():
        for json_key, dest_path in sub_mappings:
            # Check if parser already extracted it as a flat field
            val = fields.get(dest_path) or fields.get(json_key)
            if val:
                extra_data[dest_path.replace("extra_data.", "")] = str(val).strip()

    doc["extra_data"] = extra_data

    # Require at least one transaction field
    if not extra_data:
        return None

    return doc


# ======================================================================
# AI mode — Ollama-powered column detection
# ======================================================================

def _normalize_with_ai(record: ParsedRecord, breach_source: str,
                       indexed_at: str) -> dict | None:
    """
    Use Ollama to detect column meanings in no-header datasets (Arabic, etc.)
    Results are cached per breach to avoid repeated AI calls.
    """
    # Check if keys in record.fields are already mapped in the loaded global alias table
    aliases = _load_aliases()
    has_mappings = any(k.lower() in aliases for k in record.fields if not k.startswith("_"))

    if has_mappings:
        # We already have mapped these columns (from pre-flight or previous run)
        # So we don't need to call the AI at runtime!
        return _normalize_identity(record, breach_source, indexed_at)

    cache_key = f"ai:{record.breach_name}"
    if cache_key not in _AI_CACHE:
        _AI_CACHE[cache_key] = _detect_columns_via_ai(record)
    column_map = _AI_CACHE[cache_key]

    # Apply detected column map without discarding other fields
    if column_map:
        for col_idx, field_name in column_map.items():
            val = None
            if col_idx in record.fields:
                val = record.fields[col_idx]
            elif str(col_idx) in record.fields:
                val = record.fields[str(col_idx)]
            if val is not None:
                record.fields[field_name] = val

    return _normalize_identity(record, breach_source, indexed_at)


def _detect_columns_via_ai(record: ParsedRecord) -> dict[int, str]:
    """
    Send sample rows to Ollama for column detection.

    Returns a dict mapping column index → field name.
    """
    fields = record.fields

    # Build a sample representation
    # Sort keys: numeric keys first (sorted numerically), then string keys
    sample_parts = []
    sorted_keys = sorted(
        fields.keys(),
        key=lambda x: (0, int(x)) if str(x).isdigit() else (1, str(x))
    )
    for key in sorted_keys:
        val = fields[key]
        sample_parts.append(f"Col{key}: {val}")

    sample_text = "\n".join(sample_parts)  # Send all columns instead of first 5!

    prompt = f"""You are a data classification expert. Given these sample columns from a data breach file, identify what each column represents.

Sample data:
{sample_text}

Respond in JSON format with column index as key and English field name as value.
Use these standard field names: email, phone, full_name, first_name, last_name, student_id, university, faculty, department, grade, year, gender, birthdate, address, national_id

Only include columns you can confidently identify (confidence > 0.85).
Example response: {{"0": "student_id", "1": "full_name", "8": "university"}}

JSON response:"""

    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        response_text = result.get("response", "")

        # Extract JSON from response
        json_match = re.search(r"\{[^}]+\}", response_text, re.DOTALL)
        if json_match:
            column_map = {}
            mapping = json.loads(json_match.group())
            for col_str, field_name in mapping.items():
                try:
                    column_map[int(col_str)] = field_name
                except ValueError:
                    continue
            logger.info("AI detected columns: %s", column_map)
            return column_map
    except Exception as exc:
        logger.error("Ollama column detection failed: %s", exc)

    return {}


# ======================================================================
# Helper functions
# ======================================================================

def _extract_field(fields: dict, names: list[str]) -> str | None:
    """Try multiple field names and return the first non-empty value."""
    for name in names:
        val = fields.get(name)
        if val is not None and str(val).strip():
            return str(val)
    return None


def _detect_password_type(password: str) -> str:
    """Detect hash type from password string."""
    if not password:
        return "empty"
    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(password):
            return hash_type
    return "plaintext"


def _normalize_phone(phone: str) -> str:
    """Normalize a phone number: strip non-digits, preserve leading +."""
    phone = phone.strip()
    if phone.startswith("+"):
        return "+" + re.sub(r"\D", "", phone[1:])
    return re.sub(r"\D", "", phone)
