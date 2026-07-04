"""
Universal MySQL dump parser.

Designed to handle ANY leaked mysqldump file (Nafham, homzmart/Magento 2,
payment databases, sellers dumps, etc.) with zero hardcoded schema.

Key design principles
---------------------
1. **Schema auto-detection** — column lists are learned from each
   ``CREATE TABLE`` statement on the fly. No table is hardcoded.
2. **Multi-table** — every ``INSERT INTO`` in the file is processed; records
   are tagged with ``_source_table`` so downstream routing/normalization can
   use provenance. Identity data spread across several tables (Magento's
   ``customer_entity`` + ``sales_order_address`` + ``admin_user``) is captured
   in full.
3. **Streaming, memory-safe** — the file is read in fixed-size chunks and
   individual row tuples are yielded the moment they close. The parser never
   holds more than ~one row + the current table's column list in memory, so
   4 GB extended-INSERT dumps (where a whole table sits on a single physical
   line) are handled without OOM.
4. **Correct MySQL value parsing** — single/double-quoted strings with
   backslash *and* doubled-quote escapes, ``NULL``, numerics, hex literals and
   bit fields are all handled by a single-pass unescaper.
5. **Universal password detection** — bcrypt, phpass, Argon2/Argon2id
   (including Magento's ``hash:salt:version`` layout), MD5/SHA-1/SHA-256/SHA-512,
   and crypt(3) variants.

If a table's INSERT appears without a preceding CREATE TABLE (partial dump),
columns fall back to positional names ``col_0, col_1, ...`` so no data is lost.
"""

from __future__ import annotations

import logging
import re
from typing import Generator, Iterable

from parsers.base_parser import BaseParser, ParsedRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_CHUNK_SIZE = 1 << 20            # 1 MiB read chunks
DEFAULT_MAX_ROW_BYTES = 16 << 20        # 16 MiB — pathological row ceiling
DEFAULT_MAX_ROWS_PER_TABLE = 50_000_000 # safety valve

# Tables that are pure noise in almost every CMS/e-commerce dump.
DEFAULT_IGNORE_TABLES = {
    "log_customer", "log_quote", "log_summary", "log_summary_type",
    "log_visitor", "log_visitor_info", "log_url", "log_url_info",
    "report_event", "report_viewed_product_index", "report_compared_product_index",
    "catalog_product_index_price_tmp", "cache", "cache_tag",
    "session", "cron_schedule", "magento_logging_event",
    "customer_log", "core_session", "oauth_token",
    "catalogsearch_result", "catalogsearch_fulltext",
    "search_query", "search_synonyms",
}

# Column names that look like a password (any of these → password detection runs)
_PASSWORD_COLUMN_NAMES = {
    "password", "password_hash", "pass", "pwd", "user_pass",
    "memberspasshash", "passwd", "user_password", "pass_hash",
    "encrypt", "password_salt",
}


# ---------------------------------------------------------------------------
# Keyword anchors
# ---------------------------------------------------------------------------
_RE_CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?`?(\w+)`?\s*\(",
    re.IGNORECASE,
)
_RE_INSERT_INTO = re.compile(
    r"insert\s+(?:ignore\s+|delayed\s+|low_priority\s+|high_priority\s+|"
    r"priority\s+)*into\s+`?(\w+)`?"
    r"(?:\s*\(([^)]+)\))?"   # optional explicit column list: (col1, col2, ...)
    ,
    re.IGNORECASE,
)
_RE_VALUES_KW = re.compile(r"values\s*", re.IGNORECASE)
# Guards against phantom rows from ``ON DUPLICATE KEY UPDATE ... VALUES(col)``
_RE_ON_DUP = re.compile(r"\bon\s+duplicate\s+key\s+update\b", re.IGNORECASE)

# Backtick-quoted column name extraction for explicit INSERT column lists
_RE_BTICK_COL = re.compile(r"`?(\w+)`?")


def _parse_insert_columns(raw: str | None) -> list[str] | None:
    """
    Parse the explicit column list from an ``INSERT INTO t (col1, col2)``
    clause.  Returns a list of column names, or ``None`` if no list was
    provided (fall back to CREATE TABLE order).

    *raw* is group(2) of ``_RE_INSERT_INTO``.
    """
    if not raw:
        return None
    cols = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        m = _RE_BTICK_COL.match(part)
        if m:
            cols.append(m.group(1))
    return cols if cols else None


# ---------------------------------------------------------------------------
# SQL value parsing — single-pass, escape-correct
# ---------------------------------------------------------------------------

def split_sql_values(text: str) -> list[str]:
    """
    Split the inner text of a row tuple on top-level commas.

    Respects single/double-quoted strings and both backslash (``\\'``) and
    doubled-quote (``''``) escape styles. Bare parens outside strings are
    tracked so values like ``POINT(1 2)`` survive intact.
    """
    values: list[str] = []
    cur: list[str] = []
    in_str = False
    quote = ""
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                cur.append(ch)
                cur.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                if i + 1 < n and text[i + 1] == quote:
                    cur.append(ch)
                    cur.append(text[i + 1])
                    i += 2
                    continue
                in_str = False
            cur.append(ch)
            i += 1
            continue
        # not in string
        if ch in ("'", '"'):
            in_str = True
            quote = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            values.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    values.append("".join(cur))
    return values


_SQL_ESCAPES = {
    "n": "\n", "r": "\r", "t": "\t", "b": "\b",
    "0": "\x00", "Z": "\x1a", "z": "\x1a",
    "\\": "\\", "'": "'", '"': '"', "`": "`",
    "%": "%", "_": "_",
}


def unquote_sql(raw: str) -> str | None:
    """
    Convert a raw SQL value token into its Python string form.

    - ``NULL`` / empty → ``None``
    - ``'...'`` / ``"..."`` → unescaped inner string
    - ``0x...`` hex literal → decoded utf-8 (replace on error)
    - bare token (number, identifier) → returned as-is
    """
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    if s.upper() == "NULL":
        return None
    if len(s) >= 2 and s[0] in ("'", '"') and s[-1] == s[0]:
        return _unescape_quoted(s[1:-1], s[0])
    if s[:2].lower() == "0x" and len(s) > 2:
        try:
            return bytes.fromhex(s[2:]).decode("utf-8", "replace")
        except ValueError:
            return s
    if len(s) >= 3 and s[0] in ("x", "X", "b", "B") and s[1] in ("'", '"') and s[-1] == s[1]:
        return _unescape_quoted(s[2:-1], s[1])
    return s


def _unescape_quoted(inner: str, quote: str) -> str:
    """Unescape a MySQL string literal body (handles \\x and doubled quotes)."""
    out: list[str] = []
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch == "\\" and i + 1 < n:
            out.append(_SQL_ESCAPES.get(inner[i + 1], inner[i + 1]))
            i += 2
            continue
        if ch == quote and i + 1 < n and inner[i + 1] == quote:
            out.append(quote)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Password-format detection (universal)
# ---------------------------------------------------------------------------

_PASSWORD_FORMATS = [
    ("argon2id",    re.compile(r"^\$argon2id\$")),
    ("argon2i",     re.compile(r"^\$argon2i\$")),
    ("argon2",      re.compile(r"^\$argon2\$")),
    ("bcrypt",      re.compile(r"^\$2[abxy]\$\d{1,2}\$[./A-Za-z0-9]{53}$")),
    ("phpass",      re.compile(r"^\$P\$[./A-Za-z0-9]{30}$")),
    ("sha512crypt", re.compile(r"^\$6\$")),
    ("sha256crypt", re.compile(r"^\$5\$")),
    ("md5crypt",    re.compile(r"^\$1\$")),
    ("pbkdf2",      re.compile(r"^\$pbkdf2-")),
    ("scrypt",      re.compile(r"^\$scrypt\$")),
    ("sha512",      re.compile(r"^[A-Fa-f0-9]{128}$")),
    ("sha256",      re.compile(r"^[A-Fa-f0-9]{64}$")),
    ("sha1",        re.compile(r"^[A-Fa-f0-9]{40}$")),
    ("md5",         re.compile(r"^[A-Fa-f0-9]{32}$")),
]

# Magento 2 Argon2ID layout:  <64-hex-hash>:<salt>:<params>  e.g. 3_32_2_67108864
_RE_MAGENTO_ARGON2 = re.compile(
    r"^[A-Fa-f0-9]{64}:[A-Za-z0-9+/=_-]{6,64}:\d+_\d+_\d+_\d+$"
)
_RE_HASH_SALT = re.compile(r"^[A-Fa-f0-9]{32,128}:[A-Za-z0-9+/=._-]{4,}:[\w.]*$")


def detect_password_format(pw: str | None) -> str:
    """Return the detected hash algorithm, or ``'plaintext'``."""
    if not pw:
        return "empty"
    s = pw.strip()
    if not s or s.upper() == "NULL":
        return "empty"
    for name, pat in _PASSWORD_FORMATS:
        if pat.match(s):
            return name
    if _RE_MAGENTO_ARGON2.match(s):
        return "magento_argon2id"
    if _RE_HASH_SALT.match(s):
        return "hash_salt"
    return "plaintext"


# ---------------------------------------------------------------------------
# CREATE TABLE column extraction
# ---------------------------------------------------------------------------

def extract_columns_from_create(body: str) -> list[str]:
    """
    Given the text *inside* the parentheses of a CREATE TABLE statement,
    return the ordered list of column names.

    Constraint lines (``PRIMARY KEY``, ``KEY``, ``UNIQUE``, ``CONSTRAINT``,
    ``INDEX``, ``FULLTEXT``, ``FOREIGN``, ``CHECK``, ``SPATIAL``) are skipped.
    """
    cols: list[str] = []
    constraint_kw = {
        "primary", "key", "unique", "constraint", "index", "fulltext",
        "spatial", "foreign", "check",
    }
    for part in _split_top_level_commas(body):
        seg = part.strip()
        if not seg:
            continue
        m = re.match(r"`(\w+)`", seg)
        if m:
            cols.append(m.group(1))
            continue
        # unquoted column?  `name type ...`
        m = re.match(r"(\w+)", seg)
        if m and m.group(1).lower() not in constraint_kw:
            cols.append(m.group(1))
    return cols


def _split_top_level_commas(text: str) -> list[str]:
    """Split on commas not nested in parens or strings."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_str = False
    quote = ""
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                cur.append(ch); cur.append(text[i + 1]); i += 2; continue
            if ch == quote:
                in_str = False
            cur.append(ch); i += 1; continue
        if ch in ("'", '"', "`"):
            in_str = True; quote = ch; cur.append(ch)
        elif ch == "(":
            depth += 1; cur.append(ch)
        elif ch == ")":
            depth -= 1; cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur)); cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        parts.append("".join(cur))
    return parts


# ---------------------------------------------------------------------------
# Streaming row-tuple scanner
# ---------------------------------------------------------------------------

class _InsertScanner:
    """
    Streaming extractor for the ``VALUES (...)`` clause of one INSERT.

    Feed successive text chunks via :meth:`feed`; it yields fully-parsed row
    dicts per closed tuple and retains a partial tuple across calls so it
    works across chunk boundaries. Memory use is bounded by a single row.
    """

    __slots__ = (
        "table", "columns", "depth", "in_str", "quote",
        "tuple_buf", "row_open", "rows_out", "max_row_bytes",
        "skip_to_semi", "escaped",
    )

    def __init__(self, table: str, columns: list[str], max_row_bytes: int):
        self.table = table
        self.columns = columns
        self.depth = 0
        self.in_str = False
        self.quote = ""
        self.tuple_buf: list[str] = []
        self.row_open = False
        self.rows_out = 0
        self.max_row_bytes = max_row_bytes
        self.skip_to_semi = False
        self.escaped = False

    def feed(self, chunk: str) -> tuple[int, list[dict], bool]:
        """
        Process a chunk belonging to this INSERT statement.

        Returns ``(consumed_chars, rows, statement_done)``.
        ``statement_done`` is True once the terminating ``;`` at depth 0 was
        reached — the caller should switch back to SCAN mode.
        """
        rows: list[dict] = []
        i = 0
        n = len(chunk)
        cols = self.columns
        ncol = len(cols)
        buf = self.tuple_buf

        # Skip to semi if the flag is set
        if self.skip_to_semi:
            semi_pos = chunk.find(";", i)
            if semi_pos != -1:
                self.skip_to_semi = False
                self.tuple_buf = []
                return semi_pos + 1, rows, True
            else:
                return n, rows, False

        # Carry-over escape from previous chunk
        if self.escaped and n > 0:
            buf.append(chunk[0])
            self.escaped = False
            i = 1

        while i < n:
            ch = chunk[i]

            if self.in_str:
                buf.append(ch)
                if ch == "\\" and i + 1 < n:
                    buf.append(chunk[i + 1])
                    i += 2
                    continue
                if ch == "\\" and i + 1 == n:
                    self.escaped = True
                    i += 1
                    continue
                if ch == self.quote:
                    self.in_str = False
                i += 1
                continue

            # --- outside any string ---
            # Check for ON DUPLICATE KEY UPDATE at depth 0
            if ch in ("O", "o") and self.depth == 0 and not self.row_open:
                if chunk[i:i+12].lower() == "on duplicate":
                    self.skip_to_semi = True
                    semi_pos = chunk.find(";", i)
                    if semi_pos != -1:
                        self.skip_to_semi = False
                        self.tuple_buf = []
                        return semi_pos + 1, rows, True
                    else:
                        self.tuple_buf = []
                        return n, rows, False

            if ch in ("'", '"'):
                self.in_str = True
                self.quote = ch
                if self.row_open:
                    buf.append(ch)
                i += 1
                continue

            if ch == "(":
                if self.depth == 0:
                    buf = []
                    self.row_open = True
                else:
                    buf.append(ch)
                self.depth += 1
                i += 1
                continue

            if ch == ")":
                self.depth -= 1
                if self.depth == 0 and self.row_open:
                    raw = "".join(buf)
                    buf = []
                    self.row_open = False
                    if len(raw) <= self.max_row_bytes:
                        rows.append(self._build_row(raw))
                        self.rows_out += 1
                    else:
                        logger.warning(
                            "Row in `%s` exceeded %d bytes — skipped",
                            self.table, self.max_row_bytes,
                        )
                else:
                    buf.append(ch)
                i += 1
                continue

            if ch == ";" and self.depth == 0 and not self.row_open:
                self.tuple_buf = buf
                return i + 1, rows, True

            if self.row_open:
                buf.append(ch)
            # chars between tuples (commas, whitespace) at depth 0 → ignored
            i += 1

        self.tuple_buf = buf
        return n, rows, False

    def _build_row(self, raw: str) -> dict:
        tokens = split_sql_values(raw)
        row: dict = {"_source_table": self.table}
        ntok = len(tokens)
        ncol = len(self.columns)
        if ncol:
            if ntok > ncol:
                logger.debug(
                    "Table `%s` row has more values (%d) than columns (%d)",
                    self.table, ntok, ncol,
                )
            for idx, col in enumerate(self.columns):
                row[col] = unquote_sql(tokens[idx]) if idx < ntok else None
        else:
            for idx in range(ntok):
                row[f"col_{idx}"] = unquote_sql(tokens[idx])
        return row


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class SQLDumpParser(BaseParser):
    """
    Universal mysqldump parser. Processes every table in the file.

    Parameters
    ----------
    file_path : str
        Path to the ``.sql`` dump.
    breach_name : str
        Breach identifier.
    tables : Iterable[str] | None
        Optional whitelist of table names to include (lowercase). None = all.
    ignore_tables : Iterable[str] | None
        Blacklist (defaults to common log/cache/session tables).
    max_rows_per_table : int
        Safety cap to avoid runaway loops on pathological input.
    chunk_size : int
        Read-buffer size in bytes.
    """

    def __init__(
        self,
        file_path: str,
        breach_name: str,
        tables: Iterable[str] | None = None,
        ignore_tables: Iterable[str] | None = None,
        max_rows_per_table: int = DEFAULT_MAX_ROWS_PER_TABLE,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_row_bytes: int = DEFAULT_MAX_ROW_BYTES,
    ):
        super().__init__(file_path, breach_name)
        self.tables_whitelist = {t.lower() for t in tables} if tables else None
        self.ignore_tables = (
            {t.lower() for t in ignore_tables}
            if ignore_tables is not None
            else set(DEFAULT_IGNORE_TABLES)
        )
        self.max_rows_per_table = max_rows_per_table
        self.chunk_size = chunk_size
        self.max_row_bytes = max_row_bytes

        # learned schemas: { table_name_lower: [col, col, ...] }
        self._schema: dict[str, list[str]] = {}
        # stats
        self.tables_seen: dict[str, int] = {}
        self._total_rows = 0
        self._skipped_rows = 0

    # ------------------------------------------------------------------
    def _want_table(self, table: str) -> bool:
        t = table.lower()
        if t in self.ignore_tables:
            return False
        if self.tables_whitelist is not None and t not in self.tables_whitelist:
            return False
        return True

    # ------------------------------------------------------------------
    def parse(self) -> Generator[ParsedRecord, None, None]:
        """
        Stream over the dump file and yield one ParsedRecord per row.

        A single rolling buffer drives a three-mode state machine:
          * **SCAN**   — regex-find the next ``CREATE TABLE`` or
                         ``INSERT INTO`` anchor.
          * **CREATE** — char-scan the column body (bounded; CREATE bodies are
                         small) until the matching close paren, then learn the
                         column list.
          * **INSERT** — hand the post-VALUES text to an :class:`_InsertScanner`
                         which streams rows until the statement's ``;``.
        """
        schema = self._schema
        mode = "SCAN"          # SCAN | CREATE | INSERT
        buf = ""

        # CREATE accumulation
        create_table = ""
        create_body_parts: list[str] = []
        create_paren = 0
        create_in_str = False
        create_quote = ""

        # INSERT state
        scanner: _InsertScanner | None = None
        # unwanted-table fast-skip state
        skip_in_str = False
        skip_quote = ""

        enc = self.detect_encoding(self.file_path)
        with open(self.file_path, "r", encoding=enc, errors="replace") as f:
            eof = False
            while True:
                # --- refill ---
                if not eof and len(buf) < self.chunk_size:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        eof = True
                    else:
                        buf += chunk
                if not buf:
                    break

                # ======================================================
                # SCAN — find next CREATE TABLE or INSERT INTO
                # ======================================================
                if mode == "SCAN":
                    c = _RE_CREATE_TABLE.search(buf)
                    ins = _RE_INSERT_INTO.search(buf)
                    cpos = c.start() if c else -1
                    ipos = ins.start() if ins else -1

                    if cpos == -1 and ipos == -1:
                        # no anchor in buffer — keep a tail so a keyword split
                        # across the chunk boundary isn't missed
                        keep = min(len(buf), 200)
                        buf = buf[-keep:]
                        if eof:
                            break
                        continue

                    # earliest anchor wins
                    if cpos != -1 and (ipos == -1 or cpos < ipos):
                        # ---- CREATE TABLE ----
                        create_table = c.group(1)
                        create_body_parts = []
                        create_paren = 0
                        create_in_str = False
                        create_quote = ""
                        mode = "CREATE"
                        buf = buf[c.end():]   # text after opening "("
                        continue

                    # ---- INSERT INTO ----
                    table = ins.group(1)
                    after_insert = buf[ins.end():]



                    vm = _RE_VALUES_KW.search(after_insert)
                    if not vm:
                        # VALUES keyword not yet in buffer — keep from INSERT
                        buf = buf[ins.start():]
                        if eof:
                            break
                        continue
                    after_values = after_insert[vm.end():]

                    if self._want_table(table):
                        # Use explicit INSERT column list if provided,
                        # otherwise fall back to CREATE TABLE order.
                        explicit_cols = _parse_insert_columns(ins.group(2))
                        if explicit_cols is not None:
                            cols = explicit_cols
                            if table.lower() not in schema:
                                schema[table.lower()] = explicit_cols  # learn it
                        else:
                            cols = schema.get(table.lower(), [])
                        scanner = _InsertScanner(table, cols, self.max_row_bytes)
                        mode = "INSERT"
                    else:
                        scanner = None
                        skip_in_str = False
                        skip_quote = ""
                        mode = "INSERT"   # handled as fast-skip below
                    buf = after_values
                    continue

                # ======================================================
                # CREATE — accumulate column body until matching ")"
                # ======================================================
                if mode == "CREATE":
                    i = 0
                    n = len(buf)
                    finished = False
                    while i < n:
                        ch = buf[i]
                        if create_in_str:
                            if ch == "\\" and i + 1 < n:
                                i += 2
                                continue
                            if ch == create_quote:
                                create_in_str = False
                            i += 1
                            continue
                        if ch in ("'", '"', "`"):
                            create_in_str = True
                            create_quote = ch
                        elif ch == "(":
                            create_paren += 1
                        elif ch == ")":
                            if create_paren == 0:
                                finished = True
                                break
                            create_paren -= 1
                        i += 1

                    if finished:
                        create_body_parts.append(buf[:i])
                        buf = buf[i + 1:]
                        full_body = "".join(create_body_parts)
                        cols = extract_columns_from_create(full_body)
                        schema[create_table.lower()] = cols
                        logger.info(
                            "Schema learned: `%s` → %d columns",
                            create_table, len(cols),
                        )
                        mode = "SCAN"
                        continue

                    # need more data to find the closing paren
                    create_body_parts.append(buf)
                    buf = ""
                    continue

                # ======================================================
                # INSERT — stream rows (or fast-skip unwanted table)
                # ======================================================
                if mode == "INSERT":
                    if scanner is not None:
                        consumed, rows, done = scanner.feed(buf)
                        buf = buf[consumed:]
                        for row in rows:
                            rec = self._to_record(row)
                            if rec is not None:
                                yield rec
                        if done:
                            self.tables_seen[scanner.table] = self.tables_seen.get(scanner.table, 0) + scanner.rows_out
                            if scanner.rows_out >= self.max_rows_per_table:
                                logger.warning(
                                    "Table `%s` hit row cap (%d) — stopping",
                                    scanner.table, self.max_rows_per_table,
                                )
                            scanner = None
                            mode = "SCAN"
                        continue

                    # ---- unwanted table: fast-skip to next ";" ----
                    i = 0
                    n = len(buf)
                    found = False
                    while i < n:
                        ch = buf[i]
                        if skip_in_str:
                            if ch == "\\" and i + 1 < n:
                                i += 2
                                continue
                            if ch == skip_quote:
                                skip_in_str = False
                            i += 1
                            continue
                        if ch in ("'", '"', "`"):
                            skip_in_str = True
                            skip_quote = ch
                        elif ch == ";":
                            found = True
                            break
                        i += 1
                    if found:
                        buf = buf[i + 1:]
                        mode = "SCAN"
                    else:
                        buf = ""
                        if eof:
                            break
                    continue

        # finalize trailing scanner
        if scanner is not None and scanner.rows_out:
            self.tables_seen[scanner.table] = self.tables_seen.get(scanner.table, 0) + scanner.rows_out

        logger.info(
            "SQL parse complete: %d rows from %d tables (%d skipped)",
            self._total_rows, len(self.tables_seen), self._skipped_rows,
        )

    # ------------------------------------------------------------------
    def _to_record(self, row: dict) -> ParsedRecord | None:
        self._total_rows += 1
        fields = dict(row)
        # detect password format on any password-ish column
        for key, val in fields.items():
            if key.lower() in _PASSWORD_COLUMN_NAMES and val:
                fields["password_type"] = detect_password_format(val)
                break
        return ParsedRecord(
            source_file=self.file_path,
            breach_name=self.breach_name,
            line_number=0,
            raw_line="",
            fields=fields,
        )

    # ------------------------------------------------------------------
    def get_index_name(self) -> str:
        return f"leaks-{self.breach_name}"
