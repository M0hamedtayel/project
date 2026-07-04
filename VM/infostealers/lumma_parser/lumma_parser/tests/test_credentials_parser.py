"""Tests for the CredentialsParser."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path
from textwrap import dedent

from lumma_parser.parsers.credentials import CredentialsParser


_PASSWORDS_DATA = dedent("""\
SOFT: Chrome Default (147.0.7727.138)
URL: https://example.com/login
USER: user@example.com
PASS: password123

SOFT: Chrome Default (147.0.7727.138)
URL: https://accounts.google.com/
USER: admin@gmail.com
PASS: g00gle!sec

SOFT: Edge (147.0.3912.86)
URL: https://github.com/login
USER: devuser
PASS: d3v_p@ss!
""")


_WATERMARKD_PASSWORDS = dedent("""\



x Usernames @kir3cloud are NO LONGER managed by us.
==========================================================================================
SOFT: Chrome Default (147.0.7727.138)
URL: https://ecolejeans.com.ar/
USER: faculeon16@gmail.com
PASS: Maxi.2210

SOFT: Chrome Profile 1 (147.0.7727.138)
URL: https://www.netflix.com/ar/login
USER: luisilva358@gmail.com
PASS: Xnorz4092
""")


def test_all_passwords(tmp_path: Path) -> None:
    """Parser extracts credentials from All Passwords.txt."""
    all_pwd_file = tmp_path / "All Passwords.txt"
    all_pwd_file.write_text(_PASSWORDS_DATA, encoding="utf-8")

    parser = CredentialsParser(tmp_path)
    result = parser.parse()

    assert result["total_entries"] == 3
    assert result["with_valid_credentials"] == 3
    assert result["empty_entries"] == 0
    assert len(result["accounts"]) == 3

    assert result["accounts"][0]["browser"] == "Chrome Default (147.0.7727.138)"
    assert result["accounts"][0]["url"] == "https://example.com/login"
    assert result["accounts"][0]["login"] == "user@example.com"
    assert result["accounts"][0]["password"] == "password123"

    assert result["accounts"][2]["browser"] == "Edge (147.0.3912.86)"
    assert result["accounts"][2]["login"] == "devuser"


def test_watermarked_passwords(tmp_path: Path) -> None:
    """Parser extracts credentials from watermarked files."""
    all_pwd_file = tmp_path / "All Passwords.txt"
    all_pwd_file.write_text(_WATERMARKD_PASSWORDS, encoding="utf-8")

    parser = CredentialsParser(tmp_path)
    result = parser.parse()

    assert result["total_entries"] == 2
    assert result["with_valid_credentials"] == 2


def test_per_browser_passwords(tmp_path: Path) -> None:
    """Parser extracts credentials from per-browser directories."""
    # Create Chrome/Default/Passwords.txt
    chrome_dir = tmp_path / "Chrome" / "Default"
    chrome_dir.mkdir(parents=True)
    (chrome_dir / "Passwords.txt").write_text(_PASSWORDS_DATA, encoding="utf-8")

    parser = CredentialsParser(tmp_path)
    result = parser.parse()

    assert result["total_entries"] == 3


def test_no_credentials_file(tmp_path: Path) -> None:
    """Parser returns empty result when no credential files exist."""
    parser = CredentialsParser(tmp_path)
    result = parser.parse()

    assert result["total_entries"] == 0
    assert result["accounts"] == []
