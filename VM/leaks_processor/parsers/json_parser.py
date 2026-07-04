"""
JSON / JSONL parser for breach data.

Handles two formats:
1. **JSONL** — one JSON object per line (most common for breach data)
2. **JSON Array** — a single file containing ``[{...}, {...}, ...]``

The parser yields ``ParsedRecord`` objects with the full JSON dict as fields.
Nested objects are preserved — flattening happens in the normalizer.
"""

import json
import logging
from pathlib import Path
from typing import Any, Generator

from parsers.base_parser import BaseParser, ParsedRecord

logger = logging.getLogger(__name__)


class JSONParser(BaseParser):
    """
    Parser for JSON and JSONL breach data files.

    Auto-detects format: JSONL if the first non-empty line parses as a JSON
    object; JSON array if the file starts with ``[``.
    """

    def __init__(self, file_path: str, breach_name: str):
        super().__init__(file_path, breach_name)
        self.format = "unknown"  # set during parse

    def parse(self) -> Generator[ParsedRecord, None, None]:
        """Yield ParsedRecord for each JSON object in the file."""
        # Detect format from file extension
        ext = Path(self.file_path).suffix.lower()

        if ext == ".jsonl":
            yield from self._parse_jsonl()
        elif ext == ".json":
            # Peek at the first character to decide
            enc = self.detect_encoding(self.file_path)
            with open(self.file_path, "r", encoding=enc, errors="replace") as f:
                first_char = f.read(1).strip()

            if first_char == "[":
                yield from self._parse_json_array()
            elif first_char == "{":
                yield from self._parse_single_json_object()
            else:
                # Treat as JSONL (one object per line)
                yield from self._parse_jsonl()
        else:
            # Unknown extension — try JSONL first
            yield from self._parse_jsonl()

    def _parse_single_json_object(self) -> Generator[ParsedRecord, None, None]:
        """Parse a single JSON object file (wholesale) falling back to JSONL on failure."""
        self.format = "single_json"
        enc = self.detect_encoding(self.file_path)
        try:
            with open(self.file_path, "r", encoding=enc, errors="replace") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                yield ParsedRecord(
                    source_file=self.file_path,
                    breach_name=self.breach_name,
                    line_number=1,
                    raw_line="",
                    fields=self._flatten_json(obj),
                )
        except Exception as exc:
            logger.info("Failed wholesale JSON parse, falling back to JSONL: %s", exc)
            yield from self._parse_jsonl()

    def _parse_jsonl(self) -> Generator[ParsedRecord, None, None]:
        """Parse JSONL: one JSON object per line."""
        self.format = "jsonl"
        enc = self.detect_encoding(self.file_path)
        with open(self.file_path, "r", encoding=enc, errors="replace") as f:
            for line_num, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.debug(
                        "JSONL line %d parse error: %s — skipping",
                        line_num, exc,
                    )
                    continue

                if isinstance(obj, dict):
                    yield ParsedRecord(
                        source_file=self.file_path,
                        breach_name=self.breach_name,
                        line_number=line_num,
                        raw_line=raw_line.strip()[:500],
                        fields=self._flatten_json(obj),
                    )
                elif isinstance(obj, list):
                    # Line contains an array — expand into individual records
                    for item in obj:
                        if isinstance(item, dict):
                            yield ParsedRecord(
                                source_file=self.file_path,
                                breach_name=self.breach_name,
                                line_number=line_num,
                                raw_line=raw_line.strip()[:500],
                                fields=self._flatten_json(item),
                            )

    def _parse_json_array(self) -> Generator[ParsedRecord, None, None]:
        """Parse a JSON file containing an array of objects streamingly."""
        self.format = "json_array"
        enc = self.detect_encoding(self.file_path)
        decoder = json.JSONDecoder()
        
        try:
            with open(self.file_path, "r", encoding=enc, errors="replace") as f:
                # Find the start of the array
                while True:
                    char = f.read(1)
                    if not char:
                        return
                    if char == "[":
                        break
                
                # Now we stream the objects inside the array
                buf = ""
                chunk_size = 65536
                item_index = 0
                
                while True:
                    # Refill buffer if needed
                    if "{" not in buf and not buf.strip() == "]":
                        chunk = f.read(chunk_size)
                        if not chunk:
                            # EOF reached, parse anything left in buf
                            break
                        buf += chunk
                        continue
                    
                    buf = buf.lstrip()
                    if not buf:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        buf += chunk
                        continue
                    
                    if buf.startswith("]"):
                        # End of the outer array
                        break
                        
                    if buf.startswith(","):
                        buf = buf[1:].lstrip()
                        continue
                        
                    if buf.startswith("{"):
                        try:
                            obj, idx = decoder.raw_decode(buf)
                            item_index += 1
                            if isinstance(obj, dict):
                                yield ParsedRecord(
                                    source_file=self.file_path,
                                    breach_name=self.breach_name,
                                    line_number=item_index,
                                    raw_line="",
                                    fields=self._flatten_json(obj),
                                )
                            buf = buf[idx:].lstrip()
                        except json.JSONDecodeError:
                            # Object is incomplete, read more data
                            chunk = f.read(chunk_size)
                            if not chunk:
                                # No more data to read
                                break
                            buf += chunk
                    else:
                        # Skip other characters (like whitespace, comments, trailing commas)
                        buf = buf[1:]
        except Exception as exc:
            logger.error("JSON array streaming error in %s: %s", self.file_path, exc)

    @staticmethod
    def _flatten_json(obj: dict, parent_key: str = "", sep: str = ".") -> dict:
        """
        Flatten a nested JSON dict using dot notation for keys.
        Example: {"user": {"name": "Ali"}} → {"user.name": "Ali"}

        Only flattens one level of nesting to keep fields manageable.
        """
        items = {}
        for key, value in obj.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            if isinstance(value, dict) and value:
                # Flatten one level only
                for sub_key, sub_val in value.items():
                    items[f"{new_key}.{sub_key}"] = sub_val
            else:
                items[new_key] = value
        return items

    def get_index_name(self) -> str:
        """Return the Elasticsearch index name for this JSON file."""
        return f"leaks-{self.breach_name}"
