# Breach Processing Engine

Python-based breach data ingestion pipeline. Runs as a daemon on Kali Linux,
consuming messages from RabbitMQ and indexing parsed records into Elasticsearch.

## Architecture

```
RabbitMQ (ingest_queue)
    │
    ▼
main.py ──► structural_index_handler ──► ES: leaks-structure-{name}
    │
    ├─► dedup check (SHA-256)
    │
    ├─► classifier ──► parser type
    │       │
    │       ├─► archive_extractor ──► re-queue contents
    │       ├─► forensic_asset_handler ──► ES: leaks-assets-{name}
    │       ├─► streaming pipeline ──► ES: leaks-{name}-live
    │       └─► batch parser ──► normalizer ──► ES: leaks-{name}
    │
    ▼
ACK / NACK
```

## Quick Start

### 1. Prerequisites

- Python 3.11+
- Elasticsearch running on `192.168.56.1:9200`
- RabbitMQ running on `192.168.56.1:5672`
- Ollama (optional, for AI column detection on Arabic data)

### 2. Install Dependencies

```bash
cd breach_processor
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure

Edit `config/settings.py` or set environment variables:

```bash
export HOST_IP="192.168.56.1"
export ARCHIVE_ROOT="/vols/archive_leaks/"
export PARALLEL_WORKERS="4"
```

### 4. Run

**Daemon mode** (RabbitMQ consumer):
```bash
python main.py --daemon
```

**One-shot file processing:**
```bash
python main.py --file /path/to/file.csv --breach "my-breach"
```

**Directory scan:**
```bash
python main.py --scan /path/to/breach_folder --breach "my-breach"
```

**Verbose logging:**
```bash
python main.py --daemon -v
```

## Supported Datasets

| Dataset | Parser | Index |
|---|---|---|
| 7.6k combo lists | `text_ulp_parser` | `leaks-{domain}` |
| Egypt Facebook scrape | `structured_table_parser` (positional) | `leaks-egypt-facebook-scrape` |
| forum.kaspersky | `structured_table_parser` (semicolon) | `leaks-forum-kaspersky` |
| Nafham SQL dump | `sql_dump_parser` | `leaks-nafham-com` |
| Bazookaegy CSV | `structured_table_parser` | `leaks-bazookaegy-com` |
| Udemy transactions | `structured_table_parser` (transaction mode) | `leaks-udemy-transactions` |
| Instagram combo | `structured_table_parser` (positional) | `leaks-instagram-coneticlarp` |
| Student records | `structured_table_parser` (AI mode) | `leaks-sample-students` |
| Russian passports | `structural_index_handler` only | `leaks-structure-ru-pasporta` |

## Publishing Messages to RabbitMQ

To enqueue a file for processing:

```python
import pika, json

connection = pika.BlockingConnection(pika.URLParameters("amqp://guest:guest@192.168.56.1:5672/"))
channel = connection.channel()

message = {
    "file_path": "/vols/archive_leaks/breach_name/data.csv",
    "breach_name": "breach-name",
    "options": {}  # optional: {"needs_ai": true, "depth": 0, "from_archive": "..."}
}

channel.basic_publish(
    exchange="",
    routing_key="ingest_queue",
    body=json.dumps(message),
    properties=pika.BasicProperties(delivery_mode=2),  # persistent
)
connection.close()
```

## Stream Index Naming

- Batch index: `leaks-udemy-transactions`
- Stream index: `leaks-udemy-transactions-live`
- Query both: `leaks-udemy-transactions*`

## Project Structure

```
breach_processor/
├── config/settings.py          # All configuration
├── pipeline/
│   ├── classifier.py           # File type routing
│   ├── normalizer.py           # Record normalization
│   └── uploader.py             # ES bulk uploader
├── parsers/
│   ├── base_parser.py          # Abstract base
│   ├── text_ulp_parser.py      # Combo list parser
│   ├── structured_table_parser.py  # CSV/TSV parser
│   ├── sql_dump_parser.py      # MySQL dump parser
│   └── json_parser.py          # JSON/JSONL parser
├── handlers/
│   ├── forensic_asset_handler.py    # Binary file indexer
│   └── structural_index_handler.py # Directory tree indexer
├── extractors/
│   └── archive_extractor.py    # Safe archive extraction
├── streaming/
│   ├── live_stream_consumer.py # inotify file tail
│   ├── stream_normalizer.py    # Low-latency normalizer
│   └── stream_uploader.py      # Buffered ES uploader
├── utils/
│   ├── hash_utils.py           # File hashing
│   ├── dedup.py                # Dedup registry
│   └── index_utils.py          # ES index helpers
├── main.py                     # Entry point
└── requirements.txt
```
