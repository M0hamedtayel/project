"""Tests for the Cookies parser."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remus_parser.parsers.cookies import CookiesParser


@pytest.fixture
def mock_log_dir(tmp_path: Path) -> Path:
    """Create a mock Remus log directory with Cookies/."""
    cookies_dir = tmp_path / "Cookies"
    cookies_dir.mkdir()

    cookie_content = textwrap.dedent(
        """.bing.com	TRUE	/	TRUE	1810489325	SRCHD	AF=NOFORM
    .google.com	TRUE	/	TRUE	1810489326	SSID	ABCD1234
    .example.com	FALSE	/	FALSE	1810489327	SessionID	xyz789
    """
    )
    (cookies_dir / "Cookies_Edge_Default.txt").write_text(cookie_content, encoding="utf-8")
    return tmp_path


def test_parse_cookies(mock_log_dir: Path):
    """Test parsing Netscape-format cookies."""
    parser = CookiesParser(mock_log_dir)
    result = parser.parse()

    cookies = result["cookies"]
    assert len(cookies) == 3
    assert result["total_count"] == 3

    # First cookie
    assert cookies[0]["browser"] == "Edge"
    assert cookies[0]["profile"] == "Default"
    assert cookies[0]["domain"] == ".bing.com"
    assert cookies[0]["name"] == "SRCHD"
    assert cookies[0]["secure"] is True
    assert cookies[0]["expiry_epoch"] == 1810489325

    # Second cookie
    assert cookies[1]["domain"] == ".google.com"
    assert cookies[1]["name"] == "SSID"


def test_cookie_summaries(mock_log_dir: Path):
    """Test cookie browser summaries."""
    parser = CookiesParser(mock_log_dir)
    result = parser.parse()

    summaries = result["cookie_summaries"]
    assert len(summaries) == 1
    assert summaries[0]["browser"] == "Edge"
    assert summaries[0]["profile"] == "Default"
    assert summaries[0]["count"] == 3
    assert ".bing.com" in summaries[0]["top_domains"]
    assert ".google.com" in summaries[0]["top_domains"]


def test_missing_cookies_dir(tmp_path: Path):
    """Test when Cookies/ directory doesn't exist."""
    parser = CookiesParser(tmp_path)
    result = parser.parse()
    assert result["total_count"] == 0
