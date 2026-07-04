"""
Stream normalizer — lightweight, synchronous normalizer optimized for
per-record throughput in the live streaming path.

Differences from ``pipeline/normalizer.py``:
  - No AI calls (too slow for streaming)
  - One-time schema detection at startup → cached column index positions
  - Positional field access (faster than dict lookup)
  - Drops unknown schemas to batch_review_queue instead of blocking
"""

import csv
import io
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from config.settings import (
    TRANSACTION_SEARCHABLE_FIELDS, EMBEDDED_JSON_FIELDS,
)

logger = logging.getLogger(__name__)


class StreamNormalizer:
    """
    Low-latency normalizer for streaming records.

    Performs one-time schema detection from the first line/header,
    then uses cached positional access for maximum throughput.
    """

    def __init__(self, file_path: str | None = None,
                 breach_name: str = "",
                 delimiter: str = ",",
                 source: str = "file"):
        """
        Args:
            file_path: Path to the file (for header detection). None for bus mode.
            breach_name: Breach source identifier.
            delimiter: CSV delimiter character.
            source: "file" or "rabbitmq".
        """
        self.breach_name = breach_name
        self.delimiter = delimiter
        self.source = source
        self._headers: list[str] = []
        self._header_indices: dict[str, int] = {}
        self._mode: str = "unknown"  # "transaction", "identity", "unknown"
        self._initialized = False
        self._transaction_field_map: dict[int, str] = {}
        self._embedded_json_cols: dict[int, str] = {}

        if file_path and source == "file":
            self._detect_schema(file_path)

    def _detect_schema(self, file_path: str):
        """
        Read the first line of the file as header and detect the schema mode.
        Caches column positions for fast positional access.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                first_line = f.readline().strip()

            reader = csv.reader(io.StringIO(first_line), delimiter=self.delimiter)
            self._headers = [h.strip().strip('"').strip("'") for h in next(reader, [])]

            # Build header → index map
            for i, h in enumerate(self._headers):
                self._header_indices[h.lower()] = i

            # Detect mode
            header_set = set(h.lower() for h in self._headers)

            if any(t in header_set for t in (
                "purchase_reference_id", "purchase_revenue_id",
                "buyable_object_type", "charge_amount", "payment_vendor",
            )):
                self._mode = "transaction"
                self._build_transaction_map()
            else:
                self._mode = "identity"

            self._initialized = True
            logger.info(
                "Stream schema detected: mode=%s, %d columns, headers=%s",
                self._mode, len(self._headers),
                self._headers[:10],  # log first 10 headers
            )

        except Exception as exc:
            logger.error("Schema detection failed for %s: %s", file_path, exc)
            self._mode = "unknown"

    def _build_transaction_map(self):
        """Build a positional map: column_index → ES field path."""
        for src_col, dest_path in TRANSACTION_SEARCHABLE_FIELDS.items():
            idx = self._header_indices.get(src_col.lower())
            if idx is not None:
                self._transaction_field_map[idx] = dest_path

        # Map embedded JSON columns
        for json_col, mappings in EMBEDDED_JSON_FIELDS.items():
            idx = self._header_indices.get(json_col.lower())
            if idx is not None:
                self._embedded_json_cols[idx] = json_col

    def normalize_line(self, line: str) -> dict | None:
        """
        Normalize a single CSV line from the stream into an ES-ready document.

        Uses positional access for maximum speed.
        """
        if self._mode == "unknown":
            return None

        parts = line.split(self.delimiter)
        now = datetime.now(timezone.utc).isoformat()

        if self._mode == "transaction":
            return self._normalize_transaction_row(parts, now)
        else:
            return self._normalize_identity_row(parts, now)

    def normalize_dict(self, payload: dict) -> dict | None:
        """
        Normalize a dict payload (from RabbitMQ stream) into an ES document.
        Used when source is "rabbitmq" instead of file tail.
        """
        now = datetime.now(timezone.utc).isoformat()

        doc: dict[str, Any] = {
            "breach_source": self.breach_name,
            "indexed_at": now,
            "stream_mode": True,
        }

        extra_data: dict[str, Any] = {}

        # Transaction field extraction from dict
        for src_col, dest_path in TRANSACTION_SEARCHABLE_FIELDS.items():
            val = payload.get(src_col)
            if val is not None:
                key = dest_path.replace("extra_data.", "")
                val_str = str(val).strip()
                if val_str.lower() not in ("null", "none", "", "n/a", "-"):
                    extra_data[key] = val_str

        # Embedded JSON extraction from dict
        for json_col, mappings in EMBEDDED_JSON_FIELDS.items():
            raw = payload.get(json_col)
            if isinstance(raw, str):
                try:
                    inner = json.loads(raw)
                    for json_key, dest_path in mappings:
                        if json_key in inner and inner[json_key]:
                            key = dest_path.replace("extra_data.", "")
                            extra_data[key] = str(inner[json_key])
                except (json.JSONDecodeError, TypeError):
                    pass

        if extra_data:
            doc["extra_data"] = extra_data
        else:
            # Try identity mode
            for key, alias in [("email", ["email"]), ("username", ["username", "name"]),
                                ("phone", ["phone", "mobile"])]:
                for a in alias:
                    val = payload.get(a)
                    if val:
                        doc[key] = str(val).strip()
                        break

        if not any(doc.get(k) for k in ("extra_data", "email", "username", "phone")):
            return None

        return doc

    def _normalize_transaction_row(self, parts: list[str],
                                   indexed_at: str) -> dict | None:
        """Normalize a transaction row using positional access."""
        extra_data: dict[str, Any] = {}

        for col_idx, dest_path in self._transaction_field_map.items():
            if col_idx < len(parts):
                val = parts[col_idx].strip().strip('"')
                if val and val.lower() not in ("null", "none", "", "n/a", "-"):
                    key = dest_path.replace("extra_data.", "")
                    extra_data[key] = val

        # Extract embedded JSON sub-fields
        for col_idx, json_col in self._embedded_json_cols.items():
            if col_idx < len(parts):
                raw = parts[col_idx].strip().strip('"')
                try:
                    inner = json.loads(raw)
                    mappings = EMBEDDED_JSON_FIELDS.get(json_col, [])
                    for json_key, dest_path in mappings:
                        if json_key in inner and inner[json_key]:
                            key = dest_path.replace("extra_data.", "")
                            extra_data[key] = str(inner[json_key])
                except (json.JSONDecodeError, TypeError):
                    pass

        if not extra_data:
            return None

        return {
            "breach_source": self.breach_name,
            "indexed_at": indexed_at,
            "stream_mode": True,
            "extra_data": extra_data,
        }

    def _normalize_identity_row(self, parts: list[str],
                                  indexed_at: str) -> dict | None:
        """Normalize an identity row using positional access."""
        doc: dict[str, Any] = {
            "breach_source": self.breach_name,
            "indexed_at": indexed_at,
            "stream_mode": True,
        }

        # Extract identity pillars by header name
        for pillar, aliases in [
            ("email", ["email", "e_mail", "mail"]),
            ("username", ["username", "user_name", "name", "login", "handle"]),
            ("phone", ["phone", "mobile", "tel"]),
        ]:
            for alias in aliases:
                idx = self._header_indices.get(alias)
                if idx is not None and idx < len(parts):
                    val = parts[idx].strip().strip('"')
                    if val:
                        doc[pillar] = val
                        break

        if not any(doc.get(p) for p in ("email", "username", "phone")):
            return None

        return doc

    @property
    def mode(self) -> str:
        """Return the detected schema mode."""
        return self._mode
