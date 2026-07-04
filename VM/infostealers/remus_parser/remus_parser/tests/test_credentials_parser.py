"""Tests for the Credentials parser."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remus_parser.parsers.credentials import CredentialsParser


@pytest.fixture
def mock_log_dir(tmp_path: Path) -> Path:
    """Create a mock Remus log directory with All Passwords.txt."""
    pwd_content = textwrap.dedent(
        """\
        Browser: Edge 147.0.3912.86
        Url: https://www.example.com/login
        Login: user@example.com
        Password: secret123
        Profile: Default
        Date: 01.05.2026, 12:00:00

        Browser: Edge 147.0.3912.86
        Url: https://discord.com/login
        Login:
        Password: 9RVtaqYh5ym3-je
        Profile: Default
        Date: 01.05.2026, 12:01:00

        Browser: Chrome 147.0.7727.138
        Url: https://www.github.com/login
        Login: dev@github.com
        Password: gh_secret_token
        Profile: Profile 1
        Date: 01.05.2026, 12:02:00
        """
    )
    (tmp_path / "All Passwords.txt").write_text(pwd_content, encoding="utf-8")
    return tmp_path


def test_parse_all_passwords(mock_log_dir: Path):
    """Test parsing All Passwords.txt."""
    parser = CredentialsParser(mock_log_dir)
    result = parser.parse()

    assert result["total_entries"] == 3
    assert result["with_valid_credentials"] == 3

    accounts = result["accounts"]
    assert len(accounts) == 3

    # First entry
    assert accounts[0]["browser"] == "Edge 147.0.3912.86"
    assert accounts[0]["url"] == "https://www.example.com/login"
    assert accounts[0]["login"] == "user@example.com"
    assert accounts[0]["password"] == "secret123"
    assert accounts[0]["profile"] == "Default"

    # Second entry (empty login)
    assert accounts[1]["login"] == ""
    assert accounts[1]["password"] == "9RVtaqYh5ym3-je"

    # Third entry (different browser)
    assert accounts[2]["browser"] == "Chrome 147.0.7727.138"
    assert accounts[2]["profile"] == "Profile 1"

    # Domains
    assert result["unique_domains"] == 3


def test_empty_all_passwords(tmp_path: Path):
    """Test parsing empty All Passwords.txt."""
    (tmp_path / "All Passwords.txt").write_text("", encoding="utf-8")
    parser = CredentialsParser(tmp_path)
    result = parser.parse()
    assert result["total_entries"] == 0


def test_missing_all_passwords(tmp_path: Path):
    """Test when All Passwords.txt is missing."""
    parser = CredentialsParser(tmp_path)
    result = parser.parse()
    assert result["total_entries"] == 0


def test_domain_extraction(mock_log_dir: Path):
    """Test domain count from URLs."""
    parser = CredentialsParser(mock_log_dir)
    result = parser.parse()
    assert result["unique_domains"] == 3
