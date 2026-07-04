#!/usr/bin/env python3
"""
Infostealer Log Indexer CLI

Usage:
    python indexer.py <command> [options]

Commands:
    start          Start Elasticsearch via Docker and wait for it
    setup          Create the index with the correct mapping
    index          Index a JSONL file into Elasticsearch
    search         Run a search query against the index
    status         Show cluster and index status
    delete         Delete the index
    reset          Delete and recreate the index
    help           Show this help message

Examples:
    python indexer.py setup
    python indexer.py index victims.jsonl
    python indexer.py index victims.jsonl --index infostealer-logs-prod
    python indexer.py search '{"query":{"match":{"metadata.stealer_family":"Lumma"}}}'
    python indexer.py status
    python indexer.py reset
"""
import json
import sys
import time
import subprocess
import argparse
import os

from elasticsearch import Elasticsearch, RequestError

# Defaults
ES_HOST = "http://localhost:9200"
DEFAULT_INDEX = "infostealer-logs"
PREFIX = "infostealer-logs"
BULK_SIZE = 500
ES_IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:8.19.2"
COMPOSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml")


def build_mapping():
    return {
        "settings": {
            "index.mapping.nested_objects.limit": 50000,
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "1s",
        },
        "mappings": {
            "properties": {
                "metadata": {
                    "properties": {
                        "stealer_family":   {"type": "keyword"},
                        "parse_version":    {"type": "keyword"},
                        "parse_timestamp":  {"type": "date", "format": "yyyy-MM-dd'T'HH:mm:ss.SSSSSS||yyyy-MM-dd'T'HH:mm:ss||epoch_millis"},
                        "source_file":      {"type": "keyword"},
                        "source_log_date":  {"type": "date", "format": "yyyy-MM-dd'T'HH:mm:ss||epoch_millis"},
                        "build_date":       {"type": "keyword"},
                        "build_tag":        {"type": "keyword"},
                    },
                },
                "victim": {
                    "properties": {
                        "id": {
                            "properties": {
                                "machine_id": {"type": "keyword"},
                                "guid":       {"type": "keyword"},
                                "hwid":       {"type": "keyword"},
                            },
                        },
                        "identity": {
                            "properties": {
                                "username":     {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 320}}},
                                "computer_name":{"type": "keyword"},
                            },
                        },
                        "network": {
                            "properties": {
                                "ip":          {"type": "ip"},
                                "country_code":{"type": "keyword"},
                                "country_name":{"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                            },
                        },
                        "os": {
                            "properties": {
                                "version":     {"type": "keyword"},
                                "time_zone":   {"type": "keyword"},
                                "local_date":  {"type": "keyword"},
                                "install_date":{"type": "keyword"},
                                "language":    {"type": "keyword"},
                                "hostname":    {"type": "keyword"},
                            },
                        },
                        "hardware": {
                            "properties": {
                                "display": {"type": "keyword"},
                                "motherboard": {
                                    "properties": {
                                        "manufacturer": {"type": "keyword"},
                                        "product":      {"type": "keyword"},
                                        "size":         {"type": "keyword"},
                                        "core_count":   {"type": "integer"},
                                        "core_enabled": {"type": "integer"},
                                        "thread_count": {"type": "integer"},
                                    },
                                },
                                "cpu": {
                                    "properties": {
                                        "manufacturer": {"type": "keyword"},
                                        "product":      {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                                        "size":         {"type": "keyword"},
                                        "core_count":   {"type": "integer"},
                                        "core_enabled": {"type": "integer"},
                                        "thread_count": {"type": "integer"},
                                    },
                                },
                                "ram": {
                                    "type": "nested",
                                    "properties": {
                                        "manufacturer": {"type": "keyword"},
                                        "product":      {"type": "keyword"},
                                        "size":         {"type": "keyword"},
                                        "core_count":   {"type": "integer"},
                                        "core_enabled": {"type": "integer"},
                                        "thread_count": {"type": "integer"},
                                    },
                                },
                                "gpu": {
                                    "type": "nested",
                                    "properties": {
                                        "manufacturer": {"type": "keyword"},
                                        "product":      {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                                        "size":         {"type": "keyword"},
                                        "core_count":   {"type": "integer"},
                                        "core_enabled": {"type": "integer"},
                                        "thread_count": {"type": "integer"},
                                    },
                                },
                            },
                        },
                        "anti_virus": {
                            "type": "nested",
                            "properties": {
                                "name":  {"type": "keyword"},
                                "state": {"type": "keyword"},
                            },
                        },
                    },
                },
                "credentials": {
                    "properties": {
                        "total_entries":        {"type": "integer"},
                        "with_valid_credentials":{"type": "integer"},
                        "empty_entries":        {"type": "integer"},
                        "unique_domains":       {"type": "integer"},
                        "accounts": {
                            "type": "nested",
                            "properties": {
                                "browser":  {"type": "keyword"},
                                "profile":  {"type": "keyword"},
                                "url":      {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                                "login":    {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                                "password": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                                "date":     {"type": "keyword"},
                            },
                        },
                    },
                },
                "browser_data": {
                    "properties": {
                        "autofill": {
                            "type": "nested",
                            "properties": {
                                "browser":  {"type": "keyword"},
                                "profile":  {"type": "keyword"},
                                "name":     {"type": "keyword"},
                                "value":    {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                            },
                        },
                        "cookie_summaries": {
                            "type": "nested",
                            "properties": {
                                "browser":      {"type": "keyword"},
                                "profile":      {"type": "keyword"},
                                "count":        {"type": "integer"},
                                "top_domains":  {"type": "keyword"},
                            },
                        },
                        "cookies": {
                            "type": "nested",
                            "properties": {
                                "browser":        {"type": "keyword"},
                                "profile":        {"type": "keyword"},
                                "domain":         {"type": "keyword"},
                                "name":           {"type": "keyword"},
                                "value":          {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                                "path":           {"type": "keyword"},
                                "expiry_epoch":   {"type": "long"},
                                "secure":         {"type": "boolean"},
                            },
                        },
                        "credit_cards": {
                            "type": "nested",
                            "properties": {
                                "browser":          {"type": "keyword"},
                                "profile":          {"type": "keyword"},
                                "card_number":      {"type": "keyword"},
                                "cardholder_name":  {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 320}}},
                                "expiry_date":      {"type": "keyword"},
                                "cvc":              {"type": "keyword"},
                            },
                        },
                        "google_accounts": {
                            "type": "nested",
                            "properties": {
                                "browser": {"type": "keyword"},
                                "profile": {"type": "keyword"},
                                "token":   {"type": "keyword"},
                            },
                        },
                    },
                },
                "files": {
                    "properties": {
                        "scraped_count": {"type": "integer"},
                        "file_paths": {
                            "type": "nested",
                            "properties": {
                                "path": {"type": "keyword"},
                            },
                        },
                    },
                },
                "statistics": {
                    "properties": {
                        "has_credit_cards":        {"type": "boolean"},
                        "has_google_tokens":       {"type": "boolean"},
                        "has_real_credentials":    {"type": "boolean"},
                        "risk_score":              {"type": "float"},
                        "total_autofill_entries":  {"type": "integer"},
                        "total_cookies":           {"type": "integer"},
                        "total_credentials":       {"type": "integer"},
                        "total_credit_cards":      {"type": "integer"},
                        "total_empty_entries":     {"type": "integer"},
                        "total_google_tokens":     {"type": "integer"},
                        "total_passwords":         {"type": "integer"},
                        "unique_browsers":         {"type": "integer"},
                        "unique_domains_in_credentials": {"type": "integer"},
                    },
                },
            },
        },
    }


def validate_index_name(name):
    if not name.startswith(PREFIX):
        print(f"  [WARN] Name '{name}' doesn't start with '{PREFIX}'. Prepending.")
        name = f"{PREFIX}-{name}"
    return name


def get_es():
    return Elasticsearch(ES_HOST, request_timeout=120)


def wait_for_es(max_wait=60):
    print(f"  Waiting for Elasticsearch at {ES_HOST} ...")
    start = time.time()
    es = Elasticsearch(ES_HOST, request_timeout=10)
    while time.time() - start < max_wait:
        try:
            es.info()
            print("  [OK] Elasticsearch is up!")
            return es
        except Exception:
            print("  . still waiting...")
            time.sleep(3)
    print("  [FAIL] Timed out waiting for Elasticsearch")
    sys.exit(1)


def ensure_index(es, index_name):
    index_name = validate_index_name(index_name)
    if es.indices.exists(index=index_name):
        print(f"  [OK] Index '{index_name}' already exists.")
    else:
        print(f"  Creating index '{index_name}' ...")
        full = build_mapping()
        es.indices.create(index=index_name, body=full)
        print(f"  [OK] Index '{index_name}' created.")
    return index_name


def load_records(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"  [WARN] Skipping line {line_num}: {e}")
    return records


def bulk_index(es, index_name, records):
    actions = []
    for rec in records:
        actions.append({"index": {"_index": index_name}})
        actions.append(rec)

    success = 0
    failed = 0
    for i in range(0, len(actions), BULK_SIZE * 2):
        chunk = actions[i : i + BULK_SIZE * 2]
        body = "\n".join(json.dumps(a) for a in chunk) + "\n"
        try:
            resp = es.bulk(index=index_name, operations=body)
            if resp.get("errors"):
                for item in resp.get("items", []):
                    if "error" in item.get("index", {}):
                        failed += 1
                    else:
                        success += 1
            else:
                success += len(chunk) // 2
        except Exception as e:
            print(f"  [FAIL] Bulk error: {e}")
            failed += len(chunk) // 2
    return success, failed


# ─── Commands ────────────────────────────────────────────────────────────────

def cmd_start(args):
    print("Starting Elasticsearch with Docker Compose ...")
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  [FAIL] docker compose failed:\n{result.stderr}")
            print("\n  Alternative: run Docker manually:")
            print(f'  docker run -d --name infostealer-es -p 9200:9200 -e "discovery.type=single-node" -e "xpack.security.enabled=false" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" {ES_IMAGE}')
            sys.exit(1)
    except FileNotFoundError:
        print("  [FAIL] Docker not found. Install Docker Desktop for Windows first.")
        print("  Or use: python setup_elasticsearch.py  (standalone mode)")
        sys.exit(1)
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        sys.exit(1)

    print("  Docker Compose started. Waiting for Elasticsearch ...")
    es = wait_for_es(90)
    ensure_index(es, DEFAULT_INDEX)
    print("\n  [OK] Elasticsearch is ready!")


def cmd_setup(args):
    es = wait_for_es()
    index_name = ensure_index(es, args.index)
    meta = es.indices.get_mapping(index=index_name)
    props = meta.get(index_name, {}).get("mappings", {}).get("properties", {})
    print(f"\n  Index '{index_name}' has {len(props)} top-level field groups:")
    for field in sorted(props.keys()):
        m = props[field]
        mtype = m.get("type", "object")
        if mtype == "object":
            sub = len(m.get("properties", {}))
            print(f"    - {field} (object with {sub} sub-fields)")
        else:
            print(f"    - {field} ({mtype})")


def cmd_index(args):
    path = args.file
    if not os.path.isfile(path):
        print(f"  [FAIL] File not found: {path}")
        sys.exit(1)

    es = wait_for_es()
    index_name = ensure_index(es, args.index)

    print(f"\n  Reading {path} ...")
    records = load_records(path)
    if not records:
        print("  [FAIL] No valid records found.")
        sys.exit(1)
    print(f"  Loaded {len(records)} records.")

    print(f"\n  Indexing into '{index_name}' ...")
    start = time.time()
    success, failed = bulk_index(es, index_name, records)
    elapsed = time.time() - start

    es.indices.refresh(index=index_name)

    print(f"\n  [OK] Indexed {success} documents in {elapsed:.1f}s")
    if failed:
        print(f"  [WARN] {failed} documents failed")

    count = es.count(index=index_name)["count"]
    print(f"  Total documents in index: {count}")


def cmd_search(args):
    es = wait_for_es()
    index_name = validate_index_name(args.index)

    query_str = args.query
    try:
        query = json.loads(query_str)
    except json.JSONDecodeError:
        print(f"  [FAIL] Invalid JSON query: {query_str}")
        sys.exit(1)

    print(f"\n  Searching '{index_name}' ...")
    print(f"  Query: {json.dumps(query, indent=2)}")
    print()

    try:
        resp = es.search(index=index_name, body=query)
        total = resp["hits"]["total"]["value"]
        print(f"  Total hits: {total}")
        print()

        for hit in resp["hits"]["hits"][:10]:
            src = hit["_source"]
            print(f"  --- Hit ---")
            print(f"    _id:      {hit['_id']}")
            print(f"    _score:   {hit['_score']:.2f}")
            fam = src.get("metadata", {}).get("stealer_family", "?")
            login = "?"
            accounts = src.get("credentials", {}).get("accounts", [])
            if accounts:
                login = accounts[0].get("login", "?")
            username = src.get("victim", {}).get("identity", {}).get("username", "?")
            ip = src.get("victim", {}).get("network", {}).get("ip", "?")
            country = src.get("victim", {}).get("network", {}).get("country_name", "?")
            print(f"    family:   {fam}")
            print(f"    victim:   {username} ({ip} / {country})")
            if accounts:
                print(f"    credentials: {len(accounts)} accounts found")
                for acc in accounts[:3]:
                    print(f"      - {acc.get('browser','?')} | {acc.get('login','?')} | {acc.get('password','?')}")
                if len(accounts) > 3:
                    print(f"      ... and {len(accounts) - 3} more")
            cookies = src.get("browser_data", {}).get("cookies", [])
            if cookies:
                print(f"    cookies:  {len(cookies)} cookies found")
            creds = src.get("credentials", {})
            print(f"    stats:    risk_score={src.get('statistics',{}).get('risk_score','?')}")
            print()

        if total > 10:
            print(f"  ... and {total - 10} more hits")
    except Exception as e:
        print(f"  [FAIL] Search failed: {e}")
        sys.exit(1)


def cmd_status(args):
    es = wait_for_es()

    info = es.info()
    ver = info.get("version", {}).get("number", "?")
    print(f"\n  Elasticsearch v{ver}")

    cat = es.cat.indices(format="json")
    if cat:
        print(f"\n  Indices:")
        for row in cat:
            idx = row.get("index", "?")
            docs = row.get("docs.count", "?")
            store = row.get("store.size", "?")
            health = row.get("health", "?")
            print(f"    {health}  {idx:40s}  docs={docs:>10s}  size={store}")
    else:
        print("\n  No indices found.")

    cluster = es.cat.health(format="json")
    if cluster:
        print(f"\n  Cluster health: {cluster[0].get('status', '?')}")
        print(f"  Nodes: {cluster[0].get('node.count', '?')}")
        print(f"  Pending tasks: {cluster[0].get('task_max_pending', '?')}")


def cmd_delete(args):
    es = wait_for_es()
    index_name = validate_index_name(args.index)
    if es.indices.exists(index=index_name):
        es.indices.delete(index=index_name)
        print(f"  [OK] Index '{index_name}' deleted.")
    else:
        print(f"  [INFO] Index '{index_name}' does not exist.")


def cmd_reset(args):
    es = wait_for_es()
    index_name = validate_index_name(args.index)
    if es.indices.exists(index=index_name):
        print(f"  Deleting '{index_name}' ...")
        es.indices.delete(index=index_name)
    print(f"  Creating '{index_name}' ...")
    full = build_mapping()
    es.indices.create(index=index_name, body=full)
    print(f"  [OK] Index '{index_name}' reset.")


# ─── CLI Parser ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Infostealer Log Indexer CLI",
    )
    sub = parser.add_subparsers(dest="command", help="Command to run")

    sub.add_parser("start", help="Start Elasticsearch (Docker) + create index")
    s_setup = sub.add_parser("setup", help="Create/verify the index")
    s_setup.add_argument("--index", default=DEFAULT_INDEX, help=f"Index name (must start with '{PREFIX}')")

    s_idx = sub.add_parser("index", help="Index a JSONL file")
    s_idx.add_argument("file", help="Path to victims.jsonl file")
    s_idx.add_argument("--index", default=DEFAULT_INDEX, help=f"Index name (must start with '{PREFIX}')")

    s_search = sub.add_parser("search", help="Run a search query (JSON)")
    s_search.add_argument("query", help='Search query as JSON')
    s_search.add_argument("--index", default=DEFAULT_INDEX, help=f"Index name (default: {DEFAULT_INDEX})")

    sub.add_parser("status", help="Show cluster and index status")
    s_del = sub.add_parser("delete", help="Delete the index")
    s_del.add_argument("--index", default=DEFAULT_INDEX, help="Index name")
    s_reset = sub.add_parser("reset", help="Delete and recreate the index")
    s_reset.add_argument("--index", default=DEFAULT_INDEX, help="Index name")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "start": cmd_start,
        "setup": cmd_setup,
        "index": cmd_index,
        "search": cmd_search,
        "status": cmd_status,
        "delete": cmd_delete,
        "reset": cmd_reset,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
