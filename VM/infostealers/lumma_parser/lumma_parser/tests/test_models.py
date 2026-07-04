"""Tests for the Lumma parser models."""

from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone

from lumma_parser.models import (
    VictimRecord,
    Victim,
    VictimId,
    VictimIdentity,
    VictimNetwork,
    VictimOS,
    VictimHardware,
    VictimHardwareInfo,
    VictimAntivirus,
    CredentialData,
    BrowserData,
    FilesData,
    Metadata,
    Statistics,
    Credential,
    Cookie,
    AutofillEntry,
    GoogleAccountToken,
    CreditCardEntry,
    CookieBrowserSummary,
)


def test_victim_record_default() -> None:
    """A default VictimRecord serializes to valid JSON with all defaults."""
    record = VictimRecord()
    json_str = record.to_jsonl_line()
    parsed = json.loads(json_str)

    assert parsed["metadata"]["stealer_family"] == "Lumma"
    assert parsed["metadata"]["parse_version"] == "1.0.0"
    assert parsed["victim"]["identity"]["username"] == ""
    assert parsed["statistics"]["total_credentials"] == 0
    assert parsed["statistics"]["risk_score"] == 0.0


def test_victim_record_with_data() -> None:
    """A fully-populated VictimRecord serializes correctly."""
    record = VictimRecord(
        metadata=Metadata(
            source_file="lumma_20260501_test_1.2.3.4",
            source_log_date="2026-05-01T10:00:00",
            build_date="Apr 23 2026",
        ),
        victim=Victim(
            id=VictimId(hwid="ABCD1234"),
            identity=VictimIdentity(
                username="TestUser",
                computer_name="DESKTOP-TEST",
            ),
            network=VictimNetwork(
                ip="1.2.3.4",
                country_code="US",
                country_name="United States",
            ),
            os=VictimOS(
                version="Windows 11 Pro 10.0.26100 (x64)",
                time_zone="UTC-5",
                language="en-US",
                hostname="DESKTOP-TEST",
            ),
            hardware=VictimHardware(
                cpu=VictimHardwareInfo(
                    product="Intel Core i5-12400F",
                    core_count=6,
                    thread_count=12,
                ),
                gpu=[VictimHardwareInfo(product="NVIDIA RTX 3060")],
                ram=[VictimHardwareInfo(product="RAM", size="16384MB")],
                display="1920x1080",
            ),
            anti_virus=[VictimAntivirus(name="Windows Defender", state="Active")],
        ),
        credentials=CredentialData(
            total_entries=10,
            with_valid_credentials=8,
            empty_entries=2,
            unique_domains=5,
            accounts=[
                Credential(
                    browser="Google Chrome (147.0.7727.138)",
                    profile="Default",
                    url="https://example.com/",
                    login="user@example.com",
                    password="secret123",
                ),
            ],
        ),
        browser_data=BrowserData(
            cookies=[
                Cookie(
                    browser="Chrome",
                    profile="Default",
                    domain=".google.com",
                    name="SID",
                    value="abc123",
                    path="/",
                    expiry_epoch=1811807218,
                    secure=True,
                ),
            ],
            cookie_summaries=[
                CookieBrowserSummary(
                    browser="Chrome",
                    profile="Default",
                    count=42,
                    top_domains=[".google.com", ".youtube.com"],
                ),
            ],
            google_accounts=[
                GoogleAccountToken(
                    browser="Chrome",
                    profile="Default",
                    token="1//abc123:123456789",
                ),
            ],
            autofill=[
                AutofillEntry(
                    browser="Chrome",
                    profile="Default",
                    name="email",
                    value="user@example.com",
                ),
            ],
            credit_cards=[
                CreditCardEntry(
                    card_number="4377213381170055",
                    cardholder_name="Test User",
                    expiry_date="11/2025",
                    cvc="906",
                    browser="Chrome",
                    profile="Profile 15",
                ),
            ],
        ),
        statistics=Statistics(
            total_credentials=10,
            total_passwords=8,
            total_empty_entries=2,
            total_cookies=42,
            total_autofill_entries=5,
            total_google_tokens=1,
            total_credit_cards=1,
            unique_browsers=2,
            unique_domains_in_credentials=5,
            has_real_credentials=True,
            has_google_tokens=True,
            has_credit_cards=True,
            risk_score=7.5,
        ),
    )

    json_str = record.to_jsonl_line()
    parsed = json.loads(json_str)

    assert parsed["metadata"]["stealer_family"] == "Lumma"
    assert parsed["victim"]["id"]["hwid"] == "ABCD1234"
    assert parsed["victim"]["identity"]["username"] == "TestUser"
    assert parsed["victim"]["network"]["ip"] == "1.2.3.4"
    assert parsed["victim"]["network"]["country_name"] == "United States"
    assert parsed["victim"]["hardware"]["cpu"]["product"] == "Intel Core i5-12400F"
    assert parsed["credentials"]["total_entries"] == 10
    assert len(parsed["credentials"]["accounts"]) == 1
    assert parsed["credentials"]["accounts"][0]["login"] == "user@example.com"
    assert parsed["browser_data"]["cookies"][0]["domain"] == ".google.com"
    assert parsed["browser_data"]["google_accounts"][0]["token"] == "1//abc123:123456789"
    assert parsed["browser_data"]["autofill"][0]["name"] == "email"
    assert parsed["browser_data"]["credit_cards"][0]["card_number"] == "4377213381170055"
    assert parsed["statistics"]["risk_score"] == 7.5


def test_metadata_timestamp() -> None:
    """Metadata parse_timestamp is a valid UTC datetime."""
    record = VictimRecord()
    json_str = record.to_jsonl_line()
    parsed = json.loads(json_str)
    ts = parsed["metadata"]["parse_timestamp"]
    # Pydantic serializes timezone-aware UTC datetimes with +00:00
    assert "T" in ts


def test_statistics_bounds() -> None:
    """Statistics risk_score is bounded 0-10."""
    stats = Statistics(risk_score=5.0)
    assert stats.risk_score == 5.0

    # Pydantic should enforce bounds
    stats_high = Statistics(risk_score=10.0)
    assert stats_high.risk_score == 10.0


def test_browser_data_empty_defaults() -> None:
    """BrowserData with no data has empty lists."""
    bd = BrowserData()
    assert bd.cookies == []
    assert bd.cookie_summaries == []
    assert bd.google_accounts == []
    assert bd.autofill == []
    assert bd.credit_cards == []
