"""Tests for the CookiesParser."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path
from textwrap import dedent

from lumma_parser.parsers.cookies import CookiesParser


_COOKIES_DATA = dedent("""\
.accounts.google.com	FALSE	/	TRUE	1811807218	ACCOUNT_CHOOSER	AFx_qI6njnNQq1NqxO6SF5L_zR6ICCC41zSaXPbe
.google.com	TRUE	/	FALSE	1811807218	APISID	gvqBuqh_SUD5TWVa/A0c00j7NKj7-Glx7O
.google.com	TRUE	/	TRUE	1811807218	SID	g.a0009QjS98FNs7oNSKhDZLBbqbD0SrV9cEFf3h4C3luNKX3dOTRrAdtPHhrip3jxXK0K4hvqxAACgYKATUSARUSFQHGX2MiLgwXVMdxS_9odUNr-QAEgRoVAUF8yKqdlQz8nOUmhibKAFMm5Myg0076
.instagram.com	TRUE	/	TRUE	1811807277	csrftoken	K_mPR3R4oS_02mw9wrh5sN
""")


def test_cookies_directory(tmp_path: Path) -> None:
    """Parser extracts cookies from Cookies/ directory."""
    cookies_dir = tmp_path / "Cookies"
    cookies_dir.mkdir()
    (cookies_dir / "Cookies_Chrome_Default.txt").write_text(_COOKIES_DATA, encoding="utf-8")

    parser = CookiesParser(tmp_path)
    result = parser.parse()

    assert result["total_count"] == 4
    assert len(result["cookies"]) == 4

    assert result["cookies"][0]["browser"] == "Chrome"
    assert result["cookies"][0]["profile"] == "Default"
    assert result["cookies"][0]["domain"] == ".accounts.google.com"
    assert result["cookies"][0]["name"] == "ACCOUNT_CHOOSER"
    assert result["cookies"][0]["secure"] is True
    assert result["cookies"][0]["expiry_epoch"] == 1811807218

    assert result["cookies"][3]["name"] == "csrftoken"
    assert result["cookies"][3]["domain"] == ".instagram.com"


def test_per_browser_cookies(tmp_path: Path) -> None:
    """Parser extracts cookies from per-browser directories."""
    chrome_dir = tmp_path / "Chrome" / "Default"
    chrome_dir.mkdir(parents=True)
    (chrome_dir / "Cookies.txt").write_text(_COOKIES_DATA, encoding="utf-8")

    parser = CookiesParser(tmp_path)
    result = parser.parse()

    assert result["total_count"] == 4
    assert result["cookies"][0]["browser"] == "Chrome"
    assert result["cookies"][0]["profile"] == "Default"


def test_cookie_summaries(tmp_path: Path) -> None:
    """Cookie summaries are generated per browser/profile."""
    cookies_dir = tmp_path / "Cookies"
    cookies_dir.mkdir()
    (cookies_dir / "Cookies_Chrome_Default.txt").write_text(_COOKIES_DATA, encoding="utf-8")

    parser = CookiesParser(tmp_path)
    result = parser.parse()

    summaries = result["cookie_summaries"]
    assert len(summaries) == 1
    assert summaries[0]["browser"] == "Chrome"
    assert summaries[0]["profile"] == "Default"
    assert summaries[0]["count"] == 4
    assert ".google.com" in summaries[0]["top_domains"]
