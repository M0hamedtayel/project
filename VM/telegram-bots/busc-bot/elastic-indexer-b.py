import json
import os
import sys
from datetime import datetime, UTC

from elasticsearch import Elasticsearch, helpers

# =========================
# CONFIG
# =========================

ELASTIC_URL = "http://192.168.52.1:9200"
INDEX_NAME = "busc-bot"

BATCH_SIZE = 500

PARSED_DIR = "busc-bot/parsed"

# =========================
# CONNECT
# =========================

es = Elasticsearch(ELASTIC_URL)


# =========================
# ENSURE INDEX EXISTS
# =========================

def ensure_index():
    """Create index with proper mapping if it doesn't exist."""
    if es.indices.exists(index=INDEX_NAME):
        return

    mapping = {
        "mappings": {
            "properties": {
                "asset": {"type": "keyword"},
                "asset_type": {"type": "keyword"},
                "provider": {"type": "keyword"},
                "indexed_at": {"type": "date"},

                "host": {"type": "keyword"},
                "username": {"type": "keyword"},
                "password": {"type": "keyword"},

                "format": {"type": "keyword"},
                "confidence": {"type": "integer"},

                "unparsed_lines": {"type": "text"}
            }
        }
    }

    es.indices.create(index=INDEX_NAME, body=mapping)
    print(f"[+] Created index: {INDEX_NAME}")


# =========================
# GENERATE BULK ACTIONS
# =========================

def generate_actions(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    asset = data.get("asset")
    asset_type = data.get("asset_type")
    provider = data.get("provider")

    results = data.get("results", [])
    unparsed = data.get("unparsed_lines", [])

    indexed_at = datetime.now(UTC).isoformat()

    for entry in results:
        yield {
            "_index": INDEX_NAME,
            "_source": {
                "asset": asset,
                "asset_type": asset_type,
                "provider": provider,
                "indexed_at": indexed_at,

                "host": entry.get("host"),
                "username": entry.get("username"),
                "password": entry.get("password"),

                "format": entry.get("format"),
                "confidence": entry.get("confidence"),
            }
        }

    # Optional: store junk lines separately
    for line in unparsed:
        yield {
            "_index": INDEX_NAME,
            "_source": {
                "asset": asset,
                "asset_type": asset_type,
                "provider": provider,
                "indexed_at": indexed_at,

                "raw_line": line,
                "type": "unparsed"
            }
        }


# =========================
# INDEX SINGLE FILE
# =========================

def index_file(filepath):
    print(f"\n[+] Processing: {filepath}")

    try:
        success, failed = helpers.bulk(
            es,
            generate_actions(filepath),
            chunk_size=BATCH_SIZE,
            raise_on_error=False
        )

        print(f"[+] Indexed: {success}")

        if failed:
            print(f"[-] Failed docs: {len(failed)}")

    except Exception as e:
        print(f"[-] Error indexing file:")
        print(e)


# =========================
# INDEX ALL FILES
# =========================

def index_all():
    files = [
        f for f in os.listdir(PARSED_DIR)
        if f.endswith(".json")
    ]

    if not files:
        print("[-] No JSON files found.")
        return

    for file in files:
        index_file(os.path.join(PARSED_DIR, file))

    print(f"\n[+] Done indexing {len(files)} files")


# =========================
# MAIN
# =========================

if __name__ == "__main__":
    ensure_index()

    if len(sys.argv) == 2:
        index_file(sys.argv[1])
    else:
        index_all()
