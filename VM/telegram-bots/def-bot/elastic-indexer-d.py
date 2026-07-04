import json
import os
import sys
from datetime import datetime, UTC

from elasticsearch import Elasticsearch, helpers

# =========================
# CONFIG
# =========================

ELASTIC_URL = "http://192.168.52.1:9200"

INDEX_NAME = "def-bot"

PARSED_DIR = "def-bot/parsed"

BATCH_SIZE = 500

# =========================
# CONNECT
# =========================

es = Elasticsearch(
    ELASTIC_URL
)

# =========================
# GENERATE BULK ACTIONS
# =========================

def generate_actions(filepath):

    with open(
        filepath,
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    asset = data.get("asset")
    asset_type = data.get("asset_type")
    provider = data.get("provider")

    results = data.get("results", [])

    for entry in results:

        document = {
            "asset": asset,
            "asset_type": asset_type,
            "provider": provider,
            "indexed_at": datetime.now(
                UTC
            ).isoformat(),
            **entry
        }

        yield {
            "_index": INDEX_NAME,
            "_source": document
        }

# =========================
# INDEX SINGLE FILE
# =========================

def index_file(filepath):

    print(f"\n[+] Processing:")
    print(filepath)

    try:

        success, failed = helpers.bulk(
            es,
            generate_actions(filepath),
            chunk_size=BATCH_SIZE,
            raise_on_error=False
        )

        print(f"[+] Indexed: {success}")

        if failed:
            print(f"[-] Failed: {len(failed)}")

    except Exception as e:

        print(f"\n[-] Error:")
        print(e)

# =========================
# INDEX ALL FILES
# =========================

def index_all():

    files = os.listdir(PARSED_DIR)

    json_files = [
        f for f in files
        if f.endswith(".json")
    ]

    if not json_files:

        print("[-] No JSON files found.")
        return

    total_files = 0

    for file in json_files:

        filepath = os.path.join(
            PARSED_DIR,
            file
        )

        try:

            index_file(filepath)

            total_files += 1

        except Exception as e:

            print(
                f"\n[-] Failed file:"
                f" {file}"
            )

            print(e)

            continue

    print(
        f"\n[+] Finished indexing "
        f"{total_files} files."
    )

# =========================
# MAIN
# =========================

if __name__ == "__main__":

    # SINGLE FILE
    if len(sys.argv) == 2:

        filepath = sys.argv[1]

        index_file(filepath)

    # ALL FILES
    else:

        index_all()
