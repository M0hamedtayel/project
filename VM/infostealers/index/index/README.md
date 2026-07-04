# Infostealer Log Indexer

Elasticsearch-based indexer for infostealer victim data (Lumma, RED, Vidar, Remus, etc.).

## Setup

### 1. Start Elasticsearch

Choose one method:

**Standalone (no Docker required)**
```powershell
python setup_elasticsearch.py
```

**Docker**
```powershell
python indexer.py start
```

> Elasticsearch runs in the background on `http://localhost:9200`. It stays running until you restart or reboot.

### 2. Create the Index

```powershell
python indexer.py setup
```

### 3. Index Data

```powershell
# Default: uses victims.jsonl in the same directory
python indexer.py index victims.jsonl

# Specify any file
python indexer.py index "C:\path\to\your\victims.jsonl"

# Custom index name (must start with infostealer-logs)
python indexer.py index victims.jsonl --index infostealer-logs-prod
```

### 4. Search

```powershell
# Match query
python indexer.py search '{"query":{"match":{"metadata.stealer_family":"Lumma"}}}'

# Term filter
python indexer.py search '{"query":{"term":{"victim.network.country_code":"AR"}}}'

# Nested search (credentials)
python indexer.py search '{"query":{"nested":{"path":"credentials.accounts","query":{"term":{"credentials.accounts.browser":"Google Chrome"}}}}}'

# Range query
python indexer.py search '{"query":{"range":{"statistics.risk_score":{"gte":5}}}}'
```

### 5. Other Commands

```powershell
python indexer.py status     # Cluster and index stats
python indexer.py reset      # Delete + recreate index
python indexer.py delete     # Delete the index
```

---

## Schema Overview

The mapping is derived from `victims.jsonl` and covers 6 top-level objects:

| Object | Fields | Special Types |
|---|---|---|
| `metadata` | stealer_family, parse_version, parse_timestamp, source_file, source_log_date, build_date, build_tag | keyword, date |
| `victim` | id, identity, network, os, hardware, anti_virus | ip, nested arrays |
| `credentials` | total_entries, with_valid_credentials, empty_entries, unique_domains, accounts[] | nested |
| `browser_data` | autofill[], cookie_summaries[], cookies[], credit_cards[], google_accounts[] | all nested |
| `files` | scraped_count, file_paths[] | nested |
| `statistics` | risk_score, boolean flags, integer counts | float, boolean, integer |

### Nested Fields (searchable per-element)

- `credentials.accounts` — browser, profile, url, login, password, date
- `browser_data.cookies` — browser, profile, domain, name, value, path, expiry_epoch, secure
- `browser_data.autofill` — browser, profile, name, value
- `browser_data.credit_cards` — browser, profile, card_number, cardholder_name, expiry_date, cvc
- `browser_data.google_accounts` — browser, profile, token
- `browser_data.cookie_summaries` — browser, profile, count, top_domains
- `victim.anti_virus` — name, state
- `victim.hardware.gpu` — manufacturer, product, size, core_count, core_enabled, thread_count
- `victim.hardware.ram` — manufacturer, product, size, core_count, core_enabled, thread_count
- `files.file_paths` — path

---

## Validation

After indexing, the system verified:

- 49 documents indexed, 0 failures
- 388,816 total nested documents (cookies, credentials, etc.)
- All 13 search validations passed: term filters, nested queries, match queries, range queries, IP filters, CPU searches, credit card searches, timezone filters, username searches

---

## Stop Elasticsearch

```powershell
taskkill /F /IM java.exe
```

Or find the PID and kill it specifically. The setup script reports the PID when starting.

---

## Files

| File | Purpose |
|---|---|
| `indexer.py` | Main CLI tool |
| `setup_elasticsearch.py` | Standalone ES installer |
| `docker-compose.yml` | Docker-based ES setup |
| `victims.jsonl` | Victim data (JSONL) |
