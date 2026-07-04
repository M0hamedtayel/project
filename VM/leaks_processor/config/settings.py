"""
Breach Processing Engine — Central Configuration
All settings are read from environment variables with sensible defaults.
"""

import os
from pathlib import Path


# Project root — the directory that contains this settings.py file's parent
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Network — Elasticsearch & RabbitMQ (Windows host from ubuntu VM)
# ---------------------------------------------------------------------------
HOST_IP = os.getenv("HOST_IP", "192.168.52.1")
RABBITMQ_URL = os.getenv("RABBITMQ_URL", f"amqp://guest:guest@127.0.0.1:5672/leaks_processor_vhost")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", f"http://{HOST_IP}:9200")

# ---------------------------------------------------------------------------
# AI — Ollama (runs locally on Kali)
# ---------------------------------------------------------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
AI_CONFIDENCE_THRESHOLD = float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.85"))

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Default archive root: <project_root>/archive_leaks/
# Override with ARCHIVE_ROOT env var if you have a dedicated volume.
ARCHIVE_ROOT = os.getenv(
    "ARCHIVE_ROOT",
    str(_PROJECT_ROOT / "archive_leaks"),
)
INDEX_PREFIX = os.getenv("INDEX_PREFIX", "leaks-")

# ---------------------------------------------------------------------------
# Dynamic system resource sniffing & performance scaling
# ---------------------------------------------------------------------------
import sys
import subprocess

def _get_system_ram_gb() -> float:
    try:
        import psutil
        return psutil.virtual_memory().total / (1024 ** 3)
    except ImportError:
        pass
    try:
        if sys.platform == "win32":
            # Windows memory check
            out = subprocess.check_output("wmic OS get TotalVisibleMemorySize /Value", shell=True).decode()
            for line in out.splitlines():
                if "TotalVisibleMemorySize" in line:
                    return int(line.split("=")[1].strip()) / (1024 * 1024)
        else:
            # Linux memory check
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if "MemTotal" in line:
                        return int(line.split()[1]) / (1024 * 1024)
    except Exception:
        pass
    return 8.0 # default fallback

def _get_cpu_cores() -> int:
    return os.cpu_count() or 4

SYSTEM_RAM_GB = _get_system_ram_gb()
SYSTEM_CPU_CORES = _get_cpu_cores()

# Scale performance parameters dynamically
if SYSTEM_RAM_GB < 4.0:
    # Low-spec VM
    DEFAULT_BULK_BATCH_SIZE = 200
    DEFAULT_PARALLEL_WORKERS = max(1, SYSTEM_CPU_CORES - 1)
    DEFAULT_SQL_CHUNK_SIZE = 512 * 1024 # 512 KB
elif SYSTEM_RAM_GB < 8.0:
    # Medium-spec VM
    DEFAULT_BULK_BATCH_SIZE = 500
    DEFAULT_PARALLEL_WORKERS = max(2, SYSTEM_CPU_CORES - 1)
    DEFAULT_SQL_CHUNK_SIZE = 1 * 1024 * 1024 # 1 MB
elif SYSTEM_RAM_GB < 16.0:
    # High-spec VM
    DEFAULT_BULK_BATCH_SIZE = 1500
    DEFAULT_PARALLEL_WORKERS = max(4, SYSTEM_CPU_CORES - 1)
    DEFAULT_SQL_CHUNK_SIZE = 2 * 1024 * 1024 # 2 MB
else:
    # Ultra-spec VM / Server
    DEFAULT_BULK_BATCH_SIZE = 3000
    DEFAULT_PARALLEL_WORKERS = max(8, SYSTEM_CPU_CORES - 1)
    DEFAULT_SQL_CHUNK_SIZE = 4 * 1024 * 1024 # 4 MB

PARALLEL_WORKERS = int(os.getenv("PARALLEL_WORKERS", str(DEFAULT_PARALLEL_WORKERS)))
BULK_BATCH_SIZE = int(os.getenv("BULK_BATCH_SIZE", str(DEFAULT_BULK_BATCH_SIZE)))


# ---------------------------------------------------------------------------
# Archive extraction safety limits
# ---------------------------------------------------------------------------
ARCHIVE_MAX_UNCOMPRESSED_BYTES = int(
    os.getenv("ARCHIVE_MAX_UNCOMPRESSED_BYTES", str(10 * 1024 ** 3))  # 10 GB
)
ARCHIVE_MAX_COMPRESSION_RATIO = int(os.getenv("ARCHIVE_MAX_COMPRESSION_RATIO", "100"))
ARCHIVE_MAX_FILE_COUNT = int(os.getenv("ARCHIVE_MAX_FILE_COUNT", "100_000"))
ARCHIVE_MAX_SINGLE_FILE_BYTES = int(
    os.getenv("ARCHIVE_MAX_SINGLE_FILE_BYTES", str(2 * 1024 ** 3))  # 2 GB
)
ARCHIVE_MAX_NESTING_DEPTH = int(os.getenv("ARCHIVE_MAX_NESTING_DEPTH", "3"))

# ---------------------------------------------------------------------------
# Live streaming pipeline
# ---------------------------------------------------------------------------
STREAM_BUFFER_SIZE = int(os.getenv("STREAM_BUFFER_SIZE", "200"))
STREAM_FLUSH_INTERVAL_SECS = float(os.getenv("STREAM_FLUSH_INTERVAL_SECS", "2"))
STREAM_RETRY_ATTEMPTS = int(os.getenv("STREAM_RETRY_ATTEMPTS", "5"))
STREAM_RETRY_BACKOFF_BASE = float(os.getenv("STREAM_RETRY_BACKOFF_BASE", "0.5"))
STREAM_LIVE_FILE_AGE_SECS = int(os.getenv("STREAM_LIVE_FILE_AGE_SECS", "60"))
STREAM_LIVE_FILE_MIN_BYTES = int(os.getenv("STREAM_LIVE_FILE_MIN_BYTES", str(50 * 1024 ** 2)))
STREAM_SPILL_DIR = os.getenv(
    "STREAM_SPILL_DIR",
    str(_PROJECT_ROOT / "archive_leaks" / "spill"),
)
STREAM_INDEX_SUFFIX = os.getenv("STREAM_INDEX_SUFFIX", "-live")

# ---------------------------------------------------------------------------
# Structural index — directories to skip during walk
# ---------------------------------------------------------------------------
STRUCTURAL_SKIP_DIRS = {"__MACOSX", "venv", ".git", "__pycache__"}

# ---------------------------------------------------------------------------
# Positional column maps for no-header datasets
# ---------------------------------------------------------------------------
COLUMN_MAPS = {
    "egypt_facebook": {
        0: "facebook_uid", 3: "phone", 5: "birthdate",
        6: "first_name", 7: "last_name", 8: "gender",
        9: "profile_url", 11: "username", 12: "full_name",
        14: "employer", 15: "job_title", 16: "hometown",
        17: "current_city", 18: "education",
        19: "facebook_generated_email",
    },
    "instagram_coneticlarp": {
        0: "handle", 1: "numeric_id", 2: "email", 3: "phone",
    },
    "udemy_sus": {
        1: "purchase_reference_id",
        4: "charge_amount",
        7: "currency_code",
        12: "payment_method",
        18: "ip_address",
        25: "transaction_timestamp",
        29: "visitor_tracking_context",
    },
    "sample_students": {
        0: "national_id", 1: "full_name", 3: "national_id_dup",
        4: "password", 5: "email", 6: "grade_group",
        7: "university", 8: "faculty", 9: "grade",
        10: "enrollment_status", 11: "year", 12: "courses",
    },
}

# ---------------------------------------------------------------------------
# Transaction-mode detection triggers
# ---------------------------------------------------------------------------
TRANSACTION_MODE_TRIGGERS = [
    "purchase_reference_id", "purchase_revenue_id",
    "buyable_object_type", "charge_amount", "payment_vendor",
]

# ---------------------------------------------------------------------------
# Transaction searchable field mapping (header → ES dot-path)
# ---------------------------------------------------------------------------
TRANSACTION_SEARCHABLE_FIELDS = {
    "user_id":                "extra_data.user_id",
    "visitor_uuid":           "extra_data.visitor_uuid",
    "purchase_reference_id":  "extra_data.purchase_ref",
    "payment_country":        "extra_data.country",
    "payment_country_code":   "extra_data.country",
    "revenue_country":        "extra_data.country",
    "payment_vendor":         "extra_data.payment_vendor",
    "payment_vendor_name":    "extra_data.payment_vendor",
    "payment_method":         "extra_data.payment_method",
    "charge_amount":          "extra_data.charge_amount",
    "purchase_amount":        "extra_data.charge_amount",
    "currency":               "extra_data.currency",
    "currency_code":          "extra_data.currency",
    "organization_id":        "extra_data.organization_id",
    "attribution_coupon_code": "extra_data.coupon_code",
    "transaction_time":       "extra_data.transaction_date",
    "transaction_timestamp":  "extra_data.transaction_date",
}

# ---------------------------------------------------------------------------
# Embedded JSON columns that need inline extraction
# ---------------------------------------------------------------------------
EMBEDDED_JSON_FIELDS = {
    "visitor_tracking_context": [
        ("ip_address",   "extra_data.ip_address"),
        ("visitor_uuid", "extra_data.visitor_uuid"),
    ],
    "additional_data": [
        ("title", "extra_data.purchase_title"),
    ],
}

# ---------------------------------------------------------------------------
# SQL dump parser
# ---------------------------------------------------------------------------
# Chunk size for streaming reads (bytes). 1 MiB balances I/O and memory.
SQL_CHUNK_SIZE = int(os.getenv("SQL_CHUNK_SIZE", str(DEFAULT_SQL_CHUNK_SIZE)))
# Per-row byte ceiling — skips pathological rows (prevents OOM on huge blobs)
SQL_MAX_ROW_BYTES = int(os.getenv("SQL_MAX_ROW_BYTES", str(16 << 20)))
# Safety valve — stop a single table after this many rows
SQL_MAX_ROWS_PER_TABLE = int(os.getenv("SQL_MAX_ROWS_PER_TABLE", str(50_000_000)))

# Table-name → index-suffix routing for SQL dumps.
# When a record's `_source_table` (lowercased) matches a key, it is routed to
# ``leaks-{breach_name}-{suffix}``. Tables not listed here go to the default
# identity index ``leaks-{breach_name}``. Suffix "" means the main index.
#
# Identity-bearing tables (users/customers/addresses) keep their data in the
# main identity index so email/phone searches hit them directly.
# Transaction/order tables get their own index to keep mappings clean.
SQL_TABLE_INDEX_ROUTING = {
    # ---- Magento 2 (homzmart) ----
    "customer_entity":         "",                 # → leaks-homzmart (identity)
    "customer_address_entity": "",                 # → leaks-homzmart (identity)
    "admin_user":              "admin",            # → leaks-homzmart-admin
    "sales_order":             "orders",           # → leaks-homzmart-orders
    "sales_order_address":     "",                 # identity (has phone/email)
    "sales_order_payment":     "payments",         # → leaks-homzmart-payments
    "sales_order_grid":        "orders-grid",      # → leaks-homzmart-orders-grid
    "sales_invoice_grid":      "invoices",         # → leaks-homzmart-invoices
    # ---- generic Laravel/legacy ----
    "user":                    "",                 # → leaks-{breach}
    "users":                   "",
    "customers":               "",
    "members":                 "",
    "accounts":                "",
}

# ---------------------------------------------------------------------------
# RabbitMQ queue names
# ---------------------------------------------------------------------------
INGEST_QUEUE = os.getenv("INGEST_QUEUE", "ingest_queue")
DEAD_LETTER_QUEUE = os.getenv("DEAD_LETTER_QUEUE", "ingest_dlq")
