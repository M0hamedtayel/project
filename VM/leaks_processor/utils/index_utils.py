"""
Elasticsearch index helper utilities.

Provides index creation with explicit mappings, bulk helpers, and
structural-doc status patching.
"""

import json
import logging
from typing import Any

import requests

from config.settings import ELASTICSEARCH_URL, INDEX_PREFIX

logger = logging.getLogger(__name__)

# Pre-defined index mappings -------------------------------------------------

TRANSACTION_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "breach_source":               {"type": "keyword"},
            "indexed_at":                  {"type": "date"},
            "extra_data.user_id":          {"type": "keyword"},
            "extra_data.visitor_uuid":     {"type": "keyword"},
            "extra_data.purchase_ref":      {"type": "keyword"},
            "extra_data.ip_address":        {"type": "ip"},
            "extra_data.country":           {"type": "keyword"},
            "extra_data.payment_vendor":    {"type": "keyword"},
            "extra_data.payment_method":    {"type": "keyword"},
            "extra_data.charge_amount":     {"type": "float"},
            "extra_data.currency":          {"type": "keyword"},
            "extra_data.organization_id":   {"type": "keyword"},
            "extra_data.coupon_code":       {"type": "keyword"},
            "extra_data.transaction_date":  {"type": "date"},
        }
    }
}

STRUCTURAL_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "breach_source":      {"type": "keyword"},
            "relative_path":      {"type": "keyword"},
            "filename":           {"type": "keyword"},
            "extension":          {"type": "keyword"},
            "file_size_bytes":    {"type": "long"},
            "parent_directory":   {"type": "keyword"},
            "depth_level":        {"type": "integer"},
            "is_directory":       {"type": "boolean"},
            "estimated_type":     {"type": "keyword"},
            "processing_status":  {"type": "keyword"},
            "city_region":        {"type": "keyword"},
            "indexed_at":         {"type": "date"},
        }
    }
}

IDENTITY_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "breach_source":          {"type": "keyword"},
            "indexed_at":             {"type": "date"},
            "email":                  {"type": "keyword"},
            "username":               {"type": "keyword"},
            "phone":                  {"type": "keyword"},
            "url":                    {"type": "keyword"},
            "facebook_uid":          {"type": "keyword"},
            "facebook_generated_email": {"type": "keyword"},
            "password_raw":          {"type": "keyword"},
            "password_hash":          {"type": "keyword"},
            "first_name":            {"type": "keyword"},
            "last_name":             {"type": "keyword"},
            "full_name":             {"type": "keyword"},
            "extra_data":            {"type": "object", "enabled": True},
        }
    }
}

DATABASE_SCHEMA_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "file_path":          {"type": "keyword"},
            "breach_source":      {"type": "keyword"},
            "file_type":          {"type": "keyword"},
            "tables": {
                "type": "nested",
                "properties": {
                    "table_name":         {"type": "keyword"},
                    "columns":            {"type": "keyword"},
                    "row_count_estimate": {"type": "integer"},
                    "is_important":       {"type": "boolean"},
                }
            },
            "delimiter":          {"type": "keyword"},
            "columns":            {"type": "keyword"},
            "method":             {"type": "keyword"},
            "scanned_at":         {"type": "date"},
        }
    }
}

# Mapping type registry (classifier returns a "mode" string) ---------------

MAPPING_REGISTRY = {
    "transaction": TRANSACTION_INDEX_MAPPING,
    "structural": STRUCTURAL_INDEX_MAPPING,
    "identity": IDENTITY_INDEX_MAPPING,
    "schema": DATABASE_SCHEMA_INDEX_MAPPING,
}


# ---------------------------------------------------------------------------
def ensure_index(index_name: str, mapping: dict | None = None) -> bool:
    """
    Create an Elasticsearch index if it doesn't already exist.
    Returns True if created or already exists, False on error.
    """
    try:
        resp = requests.head(f"{ELASTICSEARCH_URL}/{index_name}", timeout=5)
        if resp.status_code == 200:
            return True
        body = mapping or {}
        resp = requests.put(f"{ELASTICSEARCH_URL}/{index_name}", json=body, timeout=10)
        if resp.status_code in (200, 201):
            logger.info("Created index: %s", index_name)
            return True
        logger.error("Failed to create index %s: %s", index_name, resp.text)
        return False
    except Exception as exc:
        logger.error("ensure_index(%s) error: %s", index_name, exc)
        return False


def bulk_upload(index_name: str, documents: list[dict],
                id_field: str | None = None, timeout: int = 60) -> tuple[int, int]:
    """
    Upload a batch of documents to an Elasticsearch index via the _bulk API.

    Args:
        index_name: Target ES index.
        documents: List of dicts to index.
        id_field: If set, use this field's value as the ES _id (for upsert/dedup).
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (success_count, failure_count).
    """
    if not documents:
        return 0, 0

    ndjson_lines = []
    for doc in documents:
        action = {"index": {"_index": index_name}}
        if id_field and id_field in doc:
            action["index"]["_id"] = str(doc[id_field])
        ndjson_lines.append(json.dumps(action))
        ndjson_lines.append(json.dumps(doc, default=str))

    payload = "\n".join(ndjson_lines) + "\n"

    try:
        resp = requests.post(
            f"{ELASTICSEARCH_URL}/_bulk",
            data=payload,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=timeout,
        )
        resp.raise_for_status()
        result = resp.json()

        # Parse bulk response items
        ok = 0
        fail = 0
        for item in result.get("items", []):
            status = list(item.values())[0].get("status", 0)
            if 200 <= status < 300:
                ok += 1
            else:
                fail += 1
                error_info = list(item.values())[0]
                logger.warning("Bulk item error: %s", error_info.get("error", {}))

        return ok, fail
    except Exception as exc:
        logger.error("bulk_upload to %s failed: %s", index_name, exc)
        return 0, len(documents)


def patch_structural_status(index_name: str, relative_path: str,
                            status: str) -> bool:
    """
    Update the processing_status field of a structural document.
    """
    try:
        resp = requests.post(
            f"{ELASTICSEARCH_URL}/{index_name}/_update_by_query",
            json={
                "query": {"term": {"relative_path": relative_path}},
                "script": {
                    "source": f"ctx._source.processing_status = '{status}'; "
                               f"ctx._source.updated_at = params.now",
                    "params": {"now": __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ).isoformat()},
                },
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as exc:
        logger.warning("patch_structural_status failed for %s: %s", relative_path, exc)
        return False


def single_doc_upload(index_name: str, doc: dict,
                      doc_id: str | None = None) -> bool:
    """Index a single document (used by streaming uploader)."""
    try:
        url = f"{ELASTICSEARCH_URL}/{index_name}/_doc"
        if doc_id:
            url += f"/{doc_id}"
        resp = requests.post(url, json=doc, timeout=10)
        if 200 <= resp.status_code < 300:
            return True
        logger.warning("single_doc_upload %s failed: %s", doc_id, resp.text)
        return False
    except Exception as exc:
        logger.error("single_doc_upload error: %s", exc)
        return False
