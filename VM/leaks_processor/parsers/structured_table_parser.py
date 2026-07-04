"""
Structured table (CSV / TSV / semicolon-delimited) parser.

Handles multiple breach formats with different delimiters and header schemes:

1. **Header-based CSV** — Kaspersky forum (semicolon), Bazookaegy (comma)
2. **No-header positional** — Egypt Facebook scrape (35 cols), Instagram combo (4 cols)
3. **Transaction CSVs** — Udemy revenue files with embedded JSON columns
4. **Auto-delimiter detection** — Sniffs the first line for delimiter inference

The parser yields raw dicts per row. Normalization and field mapping happen
downstream in ``pipeline/normalizer.py``.
"""

import csv
import io
import json
import logging
import re
import sys
from pathlib import Path
from typing import Generator

# Increase CSV field size limit to handle large columns (e.g. long text, bios, URLs)
_max_limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(_max_limit)
        break
    except OverflowError:
        _max_limit = int(_max_limit / 10)

from config.settings import COLUMN_MAPS, EMBEDDED_JSON_FIELDS
from parsers.base_parser import BaseParser, ParsedRecord

logger = logging.getLogger(__name__)

# Delimiter detection — try in order of specificity
DELIMITER_CANDIDATES = [
    ("semicolon", ";"),
    ("tab",       "\t"),
    ("pipe",      "|"),
    ("comma",     ","),
]


class StructuredTableParser(BaseParser):
    """
    Parser for structured table files (CSV, TSV, semicolon-delimited).

    Supports:
      - Auto-delimiter detection from the first line
      - Standard header-based parsing
      - No-header positional parsing via COLUMN_MAPS
      - Embedded JSON field extraction (e.g. visitor_tracking_context)
    """

    def __init__(self, file_path: str, breach_name: str,
                 column_map_name: str | None = None,
                 delimiter: str | None = None,
                 has_header: bool = True):
        """
        Args:
            file_path: Absolute path to the CSV/TSV file.
            breach_name: Name of the breach source.
            column_map_name: Key into COLUMN_MAPS for no-header positional parsing.
                             If None, file is assumed to have a header row.
            delimiter: Explicit delimiter override. If None, auto-detected.
            has_header: Whether the first row is a header (ignored if column_map_name is set).
        """
        super().__init__(file_path, breach_name)
        self.column_map_name = column_map_name
        self.has_header = has_header if column_map_name is None else False
        self.delimiter = delimiter
        self.headers: list[str] = []
        self._column_map: dict[int, str] | None = None
        self._embedded_json_cols: list[str] = []

    def _detect_delimiter(self, first_line: str) -> str:
        """Auto-detect delimiter from the first line by counting candidates."""
        best_delim = ","
        best_count = 0
        for _name, delim in DELIMITER_CANDIDATES:
            count = first_line.count(delim)
            if count > best_count:
                best_count = count
                best_delim = delim
        return best_delim

    def _clean_header(self, header: str) -> str:
        """Strip whitespace, quotes, and normalize a column header."""
        return header.strip().strip('"').strip("'").strip()

    def parse(self) -> Generator[ParsedRecord, None, None]:
        """Yield ParsedRecord for each data row."""
        enc = self.detect_encoding(self.file_path)
        with open(self.file_path, "r", encoding=enc, errors="replace") as f:
            first_line = f.readline()
            if not first_line.strip():
                logger.warning("Empty file: %s", self.file_path)
                return

            # Determine delimiter
            self.delimiter = self.delimiter or self._detect_delimiter(first_line)

            # If positional (no-header), build column map from config
            if self.column_map_name and self.column_map_name in COLUMN_MAPS:
                self._column_map = COLUMN_MAPS[self.column_map_name]
                self._embedded_json_cols = [
                    v for v in self._column_map.values() if v in EMBEDDED_JSON_FIELDS
                ]
                # Rewind — first_line is data, not header
                f.seek(0)
                reader = csv.reader(f, delimiter=self.delimiter)
            elif not self.has_header:
                # Positional mode without config map: map columns to string indices
                f.seek(0)
                reader = csv.reader(f, delimiter=self.delimiter)
                first_row = next(reader, [])
                self._column_map = {i: str(i) for i in range(len(first_row))}
                self._embedded_json_cols = [
                    v for v in self._column_map.values() if v in EMBEDDED_JSON_FIELDS
                ]
                # Rewind again so we don't miss the first row during iteration
                f.seek(0)
                reader = csv.reader(f, delimiter=self.delimiter)
            else:
                # Parse header row
                header_reader = csv.reader(io.StringIO(first_line), delimiter=self.delimiter)
                raw_headers = next(header_reader, [])
                self.headers = [self._clean_header(h) for h in raw_headers]

                # Detect embedded JSON columns
                self._embedded_json_cols = [
                    h for h in self.headers if h in EMBEDDED_JSON_FIELDS
                ]

                reader = csv.reader(f, delimiter=self.delimiter)

            for line_num, row in enumerate(reader, start=2 if self.headers else 1):
                record = self._parse_row(row, line_num)
                if record:
                    yield ParsedRecord(
                        source_file=self.file_path,
                        breach_name=self.breach_name,
                        line_number=line_num,
                        raw_line=self.delimiter.join(row),
                        fields=record,
                    )

    def _parse_row(self, row: list[str], line_num: int) -> dict | None:
        """Convert a single CSV row into a fields dict."""
        # --- Positional (no-header) mode ---
        if self._column_map is not None:
            fields = {}
            for col_idx, field_name in self._column_map.items():
                if col_idx < len(row):
                    value = row[col_idx].strip()
                    if field_name in self._embedded_json_cols:
                        fields[field_name] = value  # store raw JSON too
                        self._extract_json_subfields(fields, field_name, value)
                    else:
                        fields[field_name] = value
            if not fields:
                return None
            return fields

        # --- Header-based mode ---
        if len(row) != len(self.headers):
            # Column count mismatch — best-effort: map what we can
            logger.debug(
                "Row %d: expected %d cols, got %d — mapping partial",
                line_num, len(self.headers), len(row),
            )

        fields = {}
        for i, header in enumerate(self.headers):
            if i < len(row):
                value = row[i].strip()
                # Extract embedded JSON sub-fields
                if header in self._embedded_json_cols:
                    fields[header] = value  # store raw JSON too
                    self._extract_json_subfields(fields, header, value)
                else:
                    fields[header] = value

        return fields if fields else None

    @staticmethod
    def _extract_json_subfields(fields: dict, col_name: str, json_str: str):
        """
        Parse an embedded JSON column and inject extracted sub-fields
        into the fields dict using the EMBEDDED_JSON_FIELDS mapping.
        """
        try:
            inner = json.loads(json_str)
            if not isinstance(inner, dict):
                return
            for json_key, dest_key in EMBEDDED_JSON_FIELDS.get(col_name, []):
                if json_key in inner and inner[json_key]:
                    fields[dest_key] = str(inner[json_key])
        except (json.JSONDecodeError, TypeError):
            pass  # malformed JSON → skip silently

    def get_header_list(self) -> list[str]:
        """Return the parsed header names (empty list for positional mode)."""
        return self.headers
