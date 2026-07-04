"""Tests for the data models."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remus_parser.models import (
    VictimRecord,
    Victim,
    VictimIdentity,
    VictimNetwork,
    VictimOS,
    VictimHardware,
    VictimAntivirus,
    Metadata,
    Statistics,
    CredentialData,
    BrowserData,
    TelegramData,
    DiscordData,
    FilesData,
    WalletData,
    Credential,
    Cookie,
    HistoryEntry,
    AutofillEntry,
    GoogleAccountToken,
    DiscordToken,
    TelegramSession,
    WalletEntry,
)


class TestVictimRecord:
    """Tests for VictimRecord model."""

    def test_default_values(self):
        """Test that all fields have proper defaults."""
        record = VictimRecord()
        assert record.metadata.stealer_family == "Remus"
        assert record.metadata.parse_version == "1.0.0"
        assert record.victim.identity.username == ""
        assert record.credentials.total_entries == 0
        assert record.statistics.risk_score == 0.0

    def test_to_jsonl_line(self):
        """Test JSON serialization."""
        record = VictimRecord()
        record.metadata.source_file = "remus_20260501_AR_45.178.2.162"
        record.victim.identity.username = "testuser"
        record.victim.network.ip = "45.178.2.162"
        record.victim.network.country_code = "AR"

        line = record.to_jsonl_line()
        parsed = json.loads(line)
        assert parsed["metadata"]["stealer_family"] == "Remus"
        assert parsed["victim"]["identity"]["username"] == "testuser"
        assert parsed["victim"]["network"]["ip"] == "45.178.2.162"
        assert parsed["victim"]["network"]["country_code"] == "AR"

    def test_full_record(self):
        """Test a full record with all sections."""
        record = VictimRecord()

        record.metadata = Metadata(
            source_file="test",
            source_log_date="2026-05-01T12:00:00",
            build_date="25.04.2026",
            build_tag="abc123",
        )

        record.victim = Victim(
            identity=VictimIdentity(username="testuser", computer_name="TESTPC"),
            network=VictimNetwork(ip="1.2.3.4", country_code="US"),
            anti_virus=[VictimAntivirus(name="Windows Defender", state="active")],
        )

        record.credentials = CredentialData(
            total_entries=5,
            with_valid_credentials=3,
            accounts=[
                Credential(
                    browser="Google Chrome",
                    profile="Default",
                    url="https://example.com",
                    login="user@example.com",
                    password="pass123",
                )
            ],
        )

        record.browser_data = BrowserData(
            cookies=[
                Cookie(
                    browser="Chrome",
                    profile="Default",
                    domain=".example.com",
                    name="session",
                    value="abc123",
                )
            ],
        )

        record.discord = DiscordData(
            present=True,
            tokens=[DiscordToken(token="eyJ0...")],
        )

        record.telegram = TelegramData(
            present=True,
            sessions=[TelegramSession(user_hash="ABCDEF1234567890")],
        )

        record.files = FilesData(
            scraped_count=10,
        )

        record.wallets = WalletData(
            wallets=[
                WalletEntry(
                    wallet_name="MetaMask",
                    browser="Chrome",
                    profile="Default",
                )
            ],
            total_wallets=1,
        )

        record.statistics = Statistics(
            total_credentials=5,
            total_passwords=3,
            risk_score=5.0,
        )

        line = record.to_jsonl_line()
        parsed = json.loads(line)
        assert parsed["metadata"]["stealer_family"] == "Remus"
        assert parsed["credentials"]["total_entries"] == 5
        assert parsed["discord"]["present"] is True
        assert parsed["telegram"]["present"] is True
        assert parsed["wallets"]["total_wallets"] == 1
        assert parsed["statistics"]["risk_score"] == 5.0
