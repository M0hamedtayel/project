"""Tests for normalizer functions."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lumma_parser.normalizers.country import normalize_country, COUNTRY_MAP
from lumma_parser.normalizers.timestamp import normalize_timestamp
from lumma_parser.normalizers.browser import normalize_browser


class TestCountryNormalizer:
    """Tests for country code normalization."""

    def test_known_country(self) -> None:
        assert normalize_country("US") == "United States"
        assert normalize_country("AR") == "Argentina"
        assert normalize_country("BD") == "Bangladesh"
        assert normalize_country("DE") == "Germany"
        assert normalize_country("CA") == "Canada"

    def test_unknown_country(self) -> None:
        assert normalize_country("ZZ") is None
        assert normalize_country("") is None

    def test_case_insensitive(self) -> None:
        assert normalize_country("us") == "United States"
        assert normalize_country("br") == "Brazil"

    def test_all_countries_mapped(self) -> None:
        """Every 2-letter code in COUNTRY_MAP returns a non-None name."""
        for code, name in COUNTRY_MAP.items():
            assert normalize_country(code) == name
            assert len(name) > 0


class TestTimestampNormalizer:
    """Tests for timestamp normalization."""

    def test_valid_timestamp(self) -> None:
        result = normalize_timestamp("01.05.2026 19:18:16")
        assert result == "2026-05-01T19:18:16"

    def test_invalid_timestamp(self) -> None:
        assert normalize_timestamp("") is None
        assert normalize_timestamp("not a date") is None
        assert normalize_timestamp("2026-05-01T19:18:16") is None

    def test_leading_zeros(self) -> None:
        result = normalize_timestamp("18.05.2026 21:12:43")
        assert result == "2026-05-18T21:12:43"


class TestBrowserNormalizer:
    """Tests for browser name normalization."""

    def test_known_browsers(self) -> None:
        assert normalize_browser("Google Chrome") == "Google Chrome"
        assert normalize_browser("Chrome") == "Google Chrome"
        assert normalize_browser("Microsoft Edge") == "Microsoft Edge"
        assert normalize_browser("Edge") == "Microsoft Edge"
        assert normalize_browser("Brave") == "Brave"
        assert normalize_browser("Opera GX") == "Opera GX"
        assert normalize_browser("Opera GX Stable") == "Opera GX"
        assert normalize_browser("Vivaldi") == "Vivaldi"
        assert normalize_browser("AVG Secure Browser") == "AVG Secure Browser"

    def test_unknown_browser(self) -> None:
        assert normalize_browser("Unknown Browser") == "Unknown Browser"
        assert normalize_browser("") == "Unknown"

    def test_version_in_name(self) -> None:
        assert normalize_browser("Chrome 147.0.7727.138") == "Google Chrome"
