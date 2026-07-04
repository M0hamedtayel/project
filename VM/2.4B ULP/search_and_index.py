#!/usr/bin/env python3
"""
search_and_index.py  —  Search → Parse → Elasticsearch Index Pipeline
======================================================================
Takes any asset value (domain / email / username / phone), searches for
it inside a large ULP file using ripgrep, parses every matching line
with a three-path self-healing parser (fast split → KB cache → AI),
and bulk-indexes the results into Elasticsearch.

Usage
-----
    python search_and_index.py paypal.com        --file /data/combo.tsv
    python search_and_index.py jack@gmail.com    --file /data/combo.tsv
    python search_and_index.py +201012345678     --file /data/combo.tsv
    python search_and_index.py jack_doe99        --file /data/combo.tsv --type username
    python search_and_index.py paypal.com        --file /data/combo.tsv --no-cache
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import requests
import tldextract
from elasticsearch import Elasticsearch, helpers

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_DIR         = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KB   = os.path.join(_DIR, "parsing_knowledge.json")
DEFAULT_AI   = "http://127.0.0.1:11434/api/generate"
DEFAULT_MODEL= "qwen2.5:3b"
DEFAULT_ES   = "http://192.168.52.1:9200"

_PHONE_RE = re.compile(r"^\+?\d[\d\s\-(). ]{6,19}$")

# Smart parser — ordered pattern set
# Stage 2: url<SPACE>email<SPACE|TAB>pass
_RE_EMAIL_PASS = re.compile(r"^(\S+)\s+([^\s@]+@\S+)\s+(.+)$")
# Stage 3: url<SPACE>user<SPACE|TAB>pass  (3 whitespace-separated tokens)
_RE_SPACE_3    = re.compile(r"^(\S+)\s+(\S+)\s+(.+)$")
# Stage 4: classic domain:user:pass  (URL must look like a hostname, no http://)
_RE_COLON_3    = re.compile(
    r"^([a-zA-Z0-9][\w\-.]+\.[a-zA-Z]{2,}(?:/[^:\s]*)?)"  # domain/path
    r":([^:]+)"                                              # :username
    r":(.+)$"                                                # :password
)
# Stage 5: url<SPACE>user  (2 fields, no password)
_RE_SPACE_2    = re.compile(r"^(\S+)\s+(\S+)$")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ripgrep → parse → Elasticsearch pipeline for ULP files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("value",      metavar="VALUE",
                   help="Asset to search (domain, email, username, phone, or any string)")
    p.add_argument("--file",     required=True, metavar="PATH",
                   help="Path to the ULP file (.tsv / .txt / .csv / …)")
    p.add_argument("--type",     default="auto",
                   choices=["auto", "domain", "email", "username", "phone"],
                   help="Asset type override (default: auto-detect)")
    p.add_argument("--no-cache", action="store_true", default=False,
                   help="Force re-scan even if ES index already exists")
    p.add_argument("--ai-url",   default=DEFAULT_AI,   metavar="URL")
    p.add_argument("--model",    default=DEFAULT_MODEL, metavar="NAME")
    p.add_argument("--es-url",   default=DEFAULT_ES,   metavar="URL")
    p.add_argument("--kb",       default=DEFAULT_KB,   metavar="PATH",
                   help="Knowledge-base JSON file (default: same dir as script)")
    p.add_argument("--threads",  type=int, default=8,  metavar="N",
                   help="ripgrep thread count (default: 8, max = CPU core count)")
    p.add_argument("--timeout",  type=int, default=30, metavar="SEC",
                   help="Ollama request timeout seconds (default: 30)")
    p.add_argument("--batch",    type=int, default=1000, metavar="N",
                   help="Elasticsearch bulk-insert batch size (default: 1000)")
    p.add_argument("--tmp-dir",  default=_DIR, metavar="PATH",
                   help="Directory for ripgrep temp file (default: script dir on disk, "
                        "NOT /tmp which may be RAM-based tmpfs)")
    return p


# ---------------------------------------------------------------------------
# Type auto-detection
# ---------------------------------------------------------------------------
def detect_type(value: str) -> str:
    if "@" in value:
        return "email"
    digits = re.sub(r"[\s\-\+\(\).]", "", value)
    if digits.isdigit() and 7 <= len(digits) <= 15:
        return "phone"
    if "." in value and not value.startswith("http"):
        return "domain"
    return "username"


# ---------------------------------------------------------------------------
# ES index naming  →  ulp-2b4-domain-paypalcom
# ---------------------------------------------------------------------------
def build_index_name(asset_type: str, value: str) -> str:
    safe = re.sub(r"[^a-z0-9]", "", value.lower())[:80]
    return f"ulp-2b4-{asset_type}-{safe}"


_ES_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "url":           {"type": "keyword"},
            "username":      {"type": "keyword"},
            "password":      {"type": "keyword"},
            "domain":        {"type": "keyword"},
            "phone":         {"type": "keyword"},
            "matched_asset": {"type": "keyword"},
            "asset_type":    {"type": "keyword"},
            "source":        {"type": "keyword"},
        }
    },
}


def ensure_index(es: Elasticsearch, name: str) -> None:
    if not es.indices.exists(index=name):
        es.indices.create(index=name, body=_ES_MAPPING)
        print(f"[*] Created ES index: {name}")


# ---------------------------------------------------------------------------
# Knowledge-base helpers
# ---------------------------------------------------------------------------
def load_kb(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            print(f"[!] KB load error '{path}': {exc} — starting fresh.")
    return {}


def save_kb(kb: dict, path: str) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(kb, fh, indent=4, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as exc:
        print(f"[-] KB save failed: {exc}")


# ---------------------------------------------------------------------------
# AI helper
# ---------------------------------------------------------------------------
def ask_ai(line: str, ai_url: str, model: str, timeout: int) -> dict | None:
    """
    Ask Ollama to parse an anomalous line.
    Returns dict with keys url/username/password/delimiter, or None on failure.
    Requesting 'delimiter' lets us cache the pattern without garbage extraction.
    """
    prompt = (
        f"You are a credential leak parser. Analyze this line: '{line}'\n"
        f"Return JSON with keys: 'url', 'username', 'password', 'delimiter'.\n"
        f"'delimiter' = the exact separator character(s) between the three fields.\n"
        f"If there are only 2 fields (no password), set 'password' to empty string.\n"
        f"Output ONLY valid JSON. No markdown, no explanation."
    )
    try:
        resp = requests.post(
            ai_url,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        resp.raise_for_status()
        text = resp.json().get("response", "").strip()
        if "```json" in text:
            text = text.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in text:
            text = text.split("```", 1)[1].split("```", 1)[0].strip()
        parsed = json.loads(text)
        if all(k in parsed for k in ("url", "username", "password")):
            return parsed
    except requests.exceptions.Timeout:
        print(f"[-] AI timeout after {timeout}s — skipping line.")
    except Exception as exc:
        print(f"[-] AI error: {exc}")
    return None


# ---------------------------------------------------------------------------
# Structural signature (used only for KB keying)
# ---------------------------------------------------------------------------
def sig(line: str) -> str:
    """Fingerprint of the non-alphanumeric characters of a line (first 15 chars)."""
    return "".join(c for c in line if not c.isalnum())[:15]


# ---------------------------------------------------------------------------
# Smart 5-stage ULP line parser
# ---------------------------------------------------------------------------
def _parse_smart(line: str) -> tuple[str, str, str] | None:
    """
    Try 5 ordered stages to extract (url, username, password).
    Password may be an empty string for 2-field lines (url+user or url+phone).
    Returns None only when ALL stages fail.

    Stage 1  TAB-primary   — native .tsv format, handles 'url:\tuser\tpass' quirk
    Stage 2  email-pass    — url<SPACE>email@domain<SPACE>pass
    Stage 3  space-3field  — url<SPACE>user<SPACE>pass
    Stage 4  colon-3field  — domain.tld/path:user:pass  (no http scheme)
    Stage 5  2-field       — url<SPACE>user  (no password)
    """

    # ── Stage 1: TAB split (primary for .tsv) ───────────────────────────────
    if "\t" in line:
        raw_parts = line.split("\t")
        parts     = [p.strip() for p in raw_parts if p.strip()]

        if len(parts) >= 3:
            url  = parts[0].rstrip(":")   # strip trailing colon quirk: "url:\t"
            user = parts[1]
            pw   = "\t".join(parts[2:])   # rejoin in case password contained tabs
            if url and user:
                return url, user, pw

        if len(parts) == 2:
            url   = parts[0].rstrip(":")
            field = parts[1]
            if url and field:
                return url, field, ""     # 2-field: url + user/phone (no password)

    # ── Stage 2: url<SPACE>email<SPACE|TAB>pass ─────────────────────────
    m = _RE_EMAIL_PASS.match(line)
    if m:
        return m.group(1), m.group(2), m.group(3)

    # ── Stage 3: url<SPACE>user<SPACE|TAB>pass ─────────────────────────
    m = _RE_SPACE_3.match(line)
    if m:
        return m.group(1), m.group(2), m.group(3)

    # ── Stage 4: domain.tld/path:user:pass (classic colon, no scheme) ──────
    m = _RE_COLON_3.match(line)
    if m:
        return m.group(1), m.group(2), m.group(3)

    # ── Stage 5: url<SPACE>user (2 fields, no password) ───────────────────
    m = _RE_SPACE_2.match(line)
    if m:
        return m.group(1), m.group(2), ""

    return None


# ---------------------------------------------------------------------------
# Domain extractor
# ---------------------------------------------------------------------------
def extract_domain(url_or_email: str) -> str:
    try:
        val = url_or_email.split("@")[-1] if "@" in url_or_email else url_or_email
        ext = tldextract.extract(val)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Phone classifier
# ---------------------------------------------------------------------------
def classify_phone(username: str) -> str:
    c = username.strip()
    if _PHONE_RE.match(c):
        d = re.sub(r"\D", "", c)
        if 7 <= len(d) <= 15:
            return c
    return ""


# ---------------------------------------------------------------------------
# Main line parser  (smart stages → KB cache → AI)
# ---------------------------------------------------------------------------
def parse_line(
    line: str,
    kb: dict,
    ai_url: str,
    model: str,
    timeout: int,
    stats: dict,
    kb_path: str,
    failed_fh=None,
) -> dict | None:

    url = username = password = None

    # ── Stage A: smart regex parser (covers ~99% of lines) ────────────────
    result = _parse_smart(line)
    if result:
        url, username, password = result

    # ── Stage B: KB cached regex (exotic patterns learned from AI) ─────────
    if url is None:
        s = sig(line)
        if s in kb:
            rule = kb[s]
            try:
                m = re.match(rule["regex"], line)
                if m:
                    grps     = list(m.groups())
                    url      = grps[0] if len(grps) > 0 else ""
                    username = grps[1] if len(grps) > 1 else ""
                    password = grps[2] if len(grps) > 2 else ""
                    stats["kb_hits"] += 1
            except Exception:
                pass  # corrupt/stale KB entry — fall through to AI

    # ── Stage C: AI slow path (only truly alien lines) ───────────────────
    if url is None:
        s = sig(line)
        print(f"[!] Stage A+B failed for sig={s!r} — consulting AI…")
        ai_data = ask_ai(line, ai_url, model, timeout)
        stats["ai_calls"] += 1
        if ai_data:
            url       = ai_data.get("url", "")
            username  = ai_data.get("username", "")
            password  = ai_data.get("password", "")
            delimiter = ai_data.get("delimiter", "")

            # Learn a regex pattern from AI-provided delimiter (safe method)
            if delimiter and url and username:
                try:
                    esc     = re.escape(delimiter)
                    has_pw  = bool(password)
                    pattern = (
                        f"^(.+?){esc}(.+?){esc}(.+)$"
                        if has_pw else
                        f"^(.+?){esc}(.+)$"
                    )
                    # Verify pattern actually matches this line before caching
                    if re.match(pattern, line):
                        kb[s] = {
                            "regex":     pattern,
                            "delimiter": delimiter,
                            "fields":    ["url", "username", "password"] if has_pw
                                         else ["url", "username"],
                        }
                        stats["kb_new"] += 1
                        print(f"[+] Learned sig {s!r} → delimiter={delimiter!r}")
                        if stats["kb_new"] % 50 == 0:
                            save_kb(kb, kb_path)
                            print(f"[*] KB saved ({len(kb)} signatures).")
                except Exception:
                    pass  # unparseable delimiter from AI — just skip caching

    # ── All paths failed ─────────────────────────────────────────────────────
    if not url:
        stats["failed"] += 1
        if failed_fh is not None:
            failed_fh.write(line + "\n")
        return None

    stats["parsed"] += 1
    return {
        "url":      url,
        "username": username or "",
        "password": password or "",
        "domain":   extract_domain(url),
        "phone":    classify_phone(username or ""),
    }


# ---------------------------------------------------------------------------
# ripgrep runner → temp file
# ---------------------------------------------------------------------------
def run_ripgrep(value: str, file_path: str, threads: int) -> tuple[str, int]:
    val_hash = hashlib.sha256(value.encode()).hexdigest()[:8]
    tmp_path = os.path.join(tempfile.gettempdir(), f"rg_{val_hash}.txt")

    # Offer to reuse a leftover temp file from a previous crashed run
    if os.path.exists(tmp_path):
        size_mb = os.path.getsize(tmp_path) / 1_048_576
        print(f"[!] Found existing temp file ({size_mb:.1f} MB): {tmp_path}")
        choice = input("    Reuse it (skip re-scan)? [Y/n]: ").strip().lower()
        if choice in ("", "y", "yes"):
            lc = sum(1 for _ in open(tmp_path, encoding="utf-8", errors="ignore"))
            print(f"[*] Reusing temp file — {lc:,} lines.")
            return tmp_path, lc

    print(f"[*] ripgrep scanning : {file_path}")
    print(f"[*] Searching for    : {value!r}")
    print(f"[*] Threads          : {threads}")
    print(f"[*] Temp output      : {tmp_path}")
    t0 = time.time()

    with open(tmp_path, "w", encoding="utf-8", errors="ignore") as out_fh:
        result = subprocess.run(
            ["rg", "-F", value,
             "--threads", str(threads),
             "--no-filename",
             "--no-line-number",
             file_path],
            stdout=out_fh,
            stderr=subprocess.DEVNULL,
        )

    elapsed = time.time() - t0
    lc = sum(1 for _ in open(tmp_path, encoding="utf-8", errors="ignore"))
    print(f"[+] Scan done in {elapsed:.1f}s — {lc:,} matching lines.")
    return tmp_path, lc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = _build_parser().parse_args()

    value      = args.value.strip()
    file_path  = args.file

    if not os.path.isfile(file_path):
        sys.exit(f"[!] File not found: {file_path}")

    asset_type = args.type if args.type != "auto" else detect_type(value)
    es_index   = build_index_name(asset_type, value)

    print(f"\n{'='*62}")
    print(f"  Value        : {value}")
    print(f"  Detected type: {asset_type}")
    print(f"  ES index     : {es_index}")
    print(f"  Source file  : {file_path}")
    print(f"{'='*62}\n")

    # -- Connect to Elasticsearch -------------------------------------------
    es = Elasticsearch([args.es_url])
    try:
        if not es.ping():
            raise ConnectionError("ping failed")
        print("[+] Connected to Elasticsearch.")
    except Exception as exc:
        sys.exit(f"[!] Elasticsearch unreachable: {exc}")

    # -- Cache check --------------------------------------------------------
    if not args.no_cache and es.indices.exists(index=es_index):
        count = es.count(index=es_index)["count"]
        print(f"[+] Cache hit: index '{es_index}' already has {count:,} docs.")
        print("    Use --no-cache to force a fresh scan.\n")
        sys.exit(0)

    # -- Load knowledge base ------------------------------------------------
    kb = load_kb(args.kb)
    print(f"[*] Knowledge base: {len(kb)} signatures loaded from {args.kb}")

    # -- ripgrep scan → temp file -------------------------------------------
    tmp_file, match_count = run_ripgrep(value, file_path, args.threads)

    if match_count == 0:
        print("[!] No matches found. Nothing to index.")
        os.remove(tmp_file)
        sys.exit(0)

    # -- Prepare ES index ---------------------------------------------------
    ensure_index(es, es_index)

    # -- Failed-lines log file ----------------------------------------------
    date_tag   = datetime.date.today().strftime("%Y-%m-%d")
    safe_val   = re.sub(r"[^a-z0-9]", "", value.lower())[:40]
    failed_path = os.path.join(_DIR, f"failed_{safe_val}_{date_tag}.txt")
    print(f"[*] Failed lines log : {failed_path}")

    # -- Parse temp file + bulk index ---------------------------------------
    stats = {
        "parsed": 0, "failed": 0,
        "ai_calls": 0, "kb_hits": 0, "kb_new": 0,
        "indexed": 0,
    }
    batch   = []
    t_start = time.time()

    print(f"\n[*] Parsing {match_count:,} lines → indexing into '{es_index}'…\n")

    with open(tmp_file, "r", encoding="utf-8", errors="ignore") as fh, \
         open(failed_path, "w", encoding="utf-8") as failed_fh:

        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            doc = parse_line(line, kb, args.ai_url, args.model,
                             args.timeout, stats, args.kb,
                             failed_fh=failed_fh)
            if doc is None:
                continue

            doc["matched_asset"] = value
            doc["asset_type"]    = asset_type
            doc["source"]        = "ULP_2.4B"

            batch.append({"_index": es_index, "_source": doc})

            if len(batch) >= args.batch:
                ok, _ = helpers.bulk(es, batch, raise_on_error=False)
                stats["indexed"] += ok
                batch.clear()
                elapsed = time.time() - t_start
                spd = stats["parsed"] / elapsed if elapsed else 0
                print(f"  ↳ {stats['indexed']:,} indexed | "
                      f"{stats['parsed']:,} parsed | "
                      f"{spd:,.0f} lines/s")

    # Final ES flush
    if batch:
        ok, _ = helpers.bulk(es, batch, raise_on_error=False)
        stats["indexed"] += ok

    # Final KB save
    if stats["kb_new"] > 0:
        save_kb(kb, args.kb)
        print(f"[*] KB saved: {len(kb)} total signatures (+{stats['kb_new']} new).")

    # Temp file cleanup
    try:
        os.remove(tmp_file)
        print(f"[*] Temp file deleted: {tmp_file}")
    except Exception as exc:
        print(f"[-] Could not delete temp file: {exc}")

    # Delete failed log if it turned out empty
    if stats["failed"] == 0 and os.path.exists(failed_path):
        os.remove(failed_path)
        failed_path_display = "none (all lines parsed OK)"
    else:
        failed_path_display = failed_path

    # Summary
    elapsed = time.time() - t_start
    print(f"\n{'='*62}")
    print(f"[+] Search & Index Complete.")
    print(f"    Asset type     : {asset_type:>25}")
    print(f"    Search value   : {value:>25}")
    print(f"    ES index       : {es_index:>25}")
    print(f"    Matched lines  : {match_count:>25,}")
    print(f"    Parsed OK      : {stats['parsed']:>25,}")
    print(f"    Parse failed   : {stats['failed']:>25,}")
    print(f"    Failed log     : {failed_path_display:>25}")
    print(f"    AI calls       : {stats['ai_calls']:>25,}")
    print(f"    KB cache hits  : {stats['kb_hits']:>25,}")
    print(f"    ES indexed     : {stats['indexed']:>25,}")
    print(f"    Elapsed        : {elapsed:>24.1f}s")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()

