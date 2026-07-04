"""
ULP (Username:Leaked:Password) combo-list parser.

Handles the ULP/combo dataset where files contain credential lines.
Uses a self-learning approach with a signature cache and AI (Ollama) fallback
to identify separators (delimiter) and parse fields (URL, email, username, password).
"""

import logging
import re
import os
import json
import requests
from pathlib import Path
from typing import Generator

from parsers.base_parser import BaseParser, ParsedRecord
from config.settings import OLLAMA_URL, OLLAMA_MODEL

logger = logging.getLogger(__name__)

# Password hash pattern detection
HASH_PATTERNS = {
    "bcrypt":    re.compile(r"^\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}$"),
    "phpass":    re.compile(r"^\$P\$[A-Za-z0-9./]{31}$"),
    "md5":       re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1":      re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256":    re.compile(r"^[a-fA-F0-9]{64}$"),
    "ntlm":      re.compile(r"^[A-Fa-f0-9]{32}$"),
}


def detect_password_type(password: str) -> str:
    """
    Return the detected hash type, or 'plaintext' if no pattern matches.
    """
    if not password:
        return "empty"
    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(password):
            return hash_type
    return "plaintext"


def detect_hash_flag_from_filename(filename: str) -> str:
    """
    Extract the hash indicator from the filename.
    Returns 'hash', 'nohash', or 'unknown'.
    """
    upper = filename.upper()
    if "[HASH]" in upper:
        return "hash"
    if "[NOHASH]" in upper:
        return "nohash"
    return "unknown"


def sanitize_domain(filename: str) -> str:
    """
    Convert a combo-list filename to a safe Elasticsearch-compatible index segment.
    e.g. 'facebook.com_[HASH].txt' → 'facebook-com'
    """
    import re
    name = Path(filename).stem          # strip extension
    name = re.sub(r"\[.*?\]", "", name)  # strip [HASH]/[NOHASH] tags
    name = name.strip("._- ")
    name = re.sub(r"[^a-z0-9]", "-", name.lower())
    name = re.sub(r"-{2,}", "-", name).strip("-")
    return name


class TextULPParser(BaseParser):
    """
    Parser for ULP combo-list text files.
    """

    # Core fields expected per line
    EXPECTED_MIN_FIELDS = 2

    def __init__(self, file_path: str, breach_name: str):
        super().__init__(file_path, breach_name)
        self.filename = Path(file_path).name
        self.domain = sanitize_domain(self.filename)
        self.hash_flag = detect_hash_flag_from_filename(self.filename)

        # Setup Knowledge Base path
        self.kb_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config",
            "parsing_knowledge.json"
        )
        self.kb = {}
        self._load_kb()

    def _load_kb(self) -> None:
        """Load knowledge base signatures."""
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, "r", encoding="utf-8") as fh:
                    self.kb = json.load(fh)
            except Exception as exc:
                logger.warning("Could not load KB from config: %s", exc)
        else:
            # Fall back to copying/loading from ulp/parsing_knowledge.json
            ulp_kb = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "ulp",
                "parsing_knowledge.json"
            )
            if os.path.exists(ulp_kb):
                try:
                    with open(ulp_kb, "r", encoding="utf-8") as fh:
                        self.kb = json.load(fh)
                    # Create config dir if needed and save
                    os.makedirs(os.path.dirname(self.kb_path), exist_ok=True)
                    with open(self.kb_path, "w", encoding="utf-8") as fh:
                        json.dump(self.kb, fh, indent=4, ensure_ascii=False)
                except Exception as exc:
                    logger.warning("Could not copy KB from ulp folder: %s", exc)

    def _save_kb(self) -> None:
        """Save knowledge base signatures."""
        try:
            os.makedirs(os.path.dirname(self.kb_path), exist_ok=True)
            tmp = self.kb_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.kb, fh, indent=4, ensure_ascii=False)
            os.replace(tmp, self.kb_path)
        except Exception as exc:
            logger.warning("Could not save KB: %s", exc)

    def parse(self) -> Generator[ParsedRecord, None, None]:
        """Yield ParsedRecord for each valid line in the combo file."""
        kb_updated = [False]
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, raw_line in enumerate(f, start=1):
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue

                    fields = self._parse_line(line, kb_updated)
                    if fields:
                        yield ParsedRecord(
                            source_file=self.file_path,
                            breach_name=self.breach_name,
                            line_number=line_num,
                            raw_line=line,
                            fields=fields,
                        )
                    else:
                        if self.is_banner_line(line):
                            continue
                        self.report_failure(line_num, line, "parse_failure")
        finally:
            if kb_updated[0]:
                self._save_kb()

    @staticmethod
    def _sig(line: str) -> str:
        """Fingerprint of the non-alphanumeric characters of a line (first 15 chars)."""
        return "".join(c for c in line if not c.isalnum())[:15]

    def _parse_line(self, line: str, kb_updated: list[bool]) -> dict | None:
        """
        Parse a single ULP line using delimiters (smart checks -> KB cache -> AI fallback).
        """
        s = self._sig(line)
        
        # 1. Signature check
        if s in self.kb:
            rule = self.kb[s]
            if rule.get("ignore"):
                return None
            delim = rule.get("delimiter")
            if delim:
                res = self._parse_with_delimiter(line, delim)
                if res:
                    return res

        # 2. Smart Delimiters: try \t, :, space
        if "\t" in line:
            res = self._parse_with_delimiter(line, "\t")
            if res:
                self.kb[s] = {"delimiter": "\t"}
                kb_updated[0] = True
                return res
            return None

        if ":" in line:
            res = self._parse_with_delimiter(line, ":")
            if res:
                self.kb[s] = {"delimiter": ":"}
                kb_updated[0] = True
                return res
            return None

        if " " in line:
            res = self._parse_with_delimiter(line, " ")
            if res:
                self.kb[s] = {"delimiter": " "}
                kb_updated[0] = True
                return res
            return None

        # 3. AI Fallback (Ollama)
        prompt = (
            f"You are a credential leak parser. Analyze this line: '{line}'\n"
            f"Return JSON with keys: 'url', 'username', 'password', 'delimiter'.\n"
            f"'delimiter' = the exact separator character(s) between the three fields.\n"
            f"If there are only 2 fields (no password), set 'password' to empty string.\n"
            f"Output ONLY valid JSON. No markdown, no explanation."
        )
        try:
            resp = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=15,
            )
            if resp.status_code == 200:
                text = resp.json().get("response", "").strip()
                if "```json" in text:
                    text = text.split("```json", 1)[1].split("```", 1)[0].strip()
                elif "```" in text:
                    text = text.split("```", 1)[1].split("```", 1)[0].strip()

                parsed = json.loads(text)
                delim = parsed.get("delimiter")
                url = parsed.get("url")
                username = parsed.get("username")
                password = parsed.get("password")

                if delim:
                    res = self._parse_with_delimiter(line, delim)
                    if res:
                        self.kb[s] = {"delimiter": delim}
                        kb_updated[0] = True
                        return res

                if (username or url) and password:
                    record = {
                        "password_raw": password if self.hash_flag != "hash" else None,
                        "password_hash": password if self.hash_flag == "hash" else None,
                        "password_type": detect_password_type(password),
                        "domain": self.domain,
                        "hash_flag": self.hash_flag,
                    }
                    if url:
                        record["url"] = url.rstrip(":")
                    if username:
                        if "@" in username:
                            record["email"] = username.lower()
                        else:
                            record["username"] = username
                    return record
        except Exception as exc:
            logger.debug("Ollama parse fallback failed: %s", exc)

        # Cache failure to avoid repeating AI calls on similar junk
        self.kb[s] = {"ignore": True}
        kb_updated[0] = True
        return None

    def _parse_with_delimiter(self, line: str, delim: str) -> dict | None:
        """
        Split a line by a delimiter and extract URL, email, username, password.
        """
        parts = line.split(delim)
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) < 2:
            return None

        # Reconstruct URL scheme if delim is ":"
        has_scheme = False
        if delim == ":":
            # Handle http:// or similar
            if len(parts) >= 3 and parts[1].startswith("//") and (
                parts[0].lower() in ("http", "https", "android", "ftp", "sftp", "chrome") or re.match(r"^[a-z]{2,15}$", parts[0].lower())
            ):
                parts[0] = parts[0] + ":" + parts[1]
                parts.pop(1)
                has_scheme = True
            # Handle port number if present, e.g. domain.com:8080:email:pass
            if len(parts) >= 3 and parts[1].isdigit() and len(parts[1]) <= 5:
                if "@" not in parts[0] and ("." in parts[0] or "/" in parts[0] or parts[0].startswith("http")):
                    parts[0] = parts[0] + ":" + parts[1]
                    parts.pop(1)

        url_val = None
        remaining = parts

        # Check if the first part looks like a URL/domain
        if has_scheme or self._looks_like_url(parts[0]):
            url_val = parts[0].rstrip(":")
            remaining = parts[1:]

        if len(remaining) < 2:
            return None

        email = None
        username = None
        password = None
        extra_parts = []

        if "@" in remaining[0]:
            email = remaining[0]
            if len(remaining) >= 3:
                if self._looks_like_ip(remaining[2]):
                    password = remaining[1]
                    extra_parts = remaining[2:]
                else:
                    username = remaining[1]
                    password = remaining[2]
                    extra_parts = remaining[3:]
            else:
                password = remaining[1]
        else:
            username = remaining[0]
            password = remaining[1]
            extra_parts = remaining[2:]

        # Validate that we have at least one identity pillar and a password
        if not (email or username) or not password:
            return None

        # Sanitize identity pillars to exclude control characters.
        # If the delimiter is tab (\t), we allow spaces/unicode spaces in username (e.g. full names).
        # If the delimiter is colon (:) or space ( ), we do not allow spaces in username.
        if delim == "\t":
            valid_pattern_username = re.compile(r"^[^\x00-\x1f\x7f]+$")
        else:
            valid_pattern_username = re.compile(r"^[^\s\x00-\x1f\x7f]+$")
            
        valid_pattern_email = re.compile(r"^[^\s\x00-\x1f\x7f]+$")

        if email and not valid_pattern_email.match(email):
            return None
        if username and not valid_pattern_username.match(username):
            return None

        record = {
            "password_raw": password if self.hash_flag != "hash" else None,
            "password_hash": password if self.hash_flag == "hash" else None,
            "password_type": detect_password_type(password),
            "domain": self.domain,
            "hash_flag": self.hash_flag,
        }

        if email:
            record["email"] = email.lower()
        if username:
            record["username"] = username
        if url_val:
            record["url"] = url_val

        if extra_parts:
            record["extra_data"] = {
                "raw_tokens": extra_parts,
                "token_count": len(extra_parts),
            }
            if len(extra_parts) >= 1:
                record["extra_data"]["ip"] = extra_parts[-1] if self._looks_like_ip(extra_parts[-1]) else None

        return record

    @staticmethod
    def _looks_like_ip(token: str) -> bool:
        """Heuristic check if a token looks like an IP address."""
        import re
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", token))

    @staticmethod
    def _looks_like_url(token: str) -> bool:
        """Heuristic check if a token looks like a URL or domain name."""
        token_lower = token.lower()
        if token_lower.startswith(("http://", "https://", "android://", "chrome://", "ftp://", "www.")):
            return True
        if "@" in token:
            return False
        if "/" in token_lower and "." in token_lower:
            return True
        # Domain name match (e.g. pixabay.com, patria.org.ve)
        if re.match(r"^(?:[a-z0-9\-]+\.)+[a-z]{2,6}$", token_lower):
            return True
        return False

    @staticmethod
    def is_banner_line(line: str) -> bool:
        """
        Check if a line looks like a banner, advertisement, or decorative line.
        """
        line_stripped = line.strip()
        if not line_stripped:
            return True
        
        # 1. Decorative lines (consisting entirely of punctuation/symbols/spaces)
        if re.match(r"^[=\-_+*#/\\~@%|>< ]+$", line_stripped):
            return True
            
        # 2. Comment lines
        if line_stripped.startswith(("#", "//", "--", "/*", "*", ";")):
            return True
            
        # 3. Advertisement or banner keywords
        line_lower = line_stripped.lower()
        banner_keywords = (
            "t.me/", "telegram", "discord.gg", "leak by", "leaked by",
            "uploaded by", "downloaded from", "contact:", "support:",
            "credits:", "credit to", "breached by", "hacked by",
            "welcome to", "all rights reserved", "generated by",
            "thread link", "forum link", "visit our", "created by"
        )
        if any(kw in line_lower for kw in banner_keywords):
            return True
            
        # 4. Single URLs without any credential structure (no tabs, no other colons)
        if line_lower.startswith(("http://", "https://")):
            rest = line_stripped[8:] if line_lower.startswith("https://") else line_stripped[7:]
            if ":" not in rest and "\t" not in rest and " " not in rest:
                return True
                
        return False

    def get_index_name(self) -> str:
        """Return the Elasticsearch index name for this combo list."""
        return f"leaks-{self.domain}"
