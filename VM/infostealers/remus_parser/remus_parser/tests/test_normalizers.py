"""Tests for normalizer modules."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remus_parser.normalizers.country import normalize_country
from remus_parser.normalizers.timestamp import normalize_timestamp
from remus_parser.normalizers.browser import normalize_browser


class TestCountryNormalizer:
    """Tests for country code normalization."""

    def test_known_country(self):
        assert normalize_country("US") == "United States"
        assert normalize_country("AR") == "Argentina"
        assert normalize_country("GB") == "United Kingdom"
        assert normalize_country("DE") == "Germany"

    def test_lowercase(self):
        assert normalize_country("us") == "United States"
        assert normalize_country("ar") == "Argentina"

    def test_unknown_country(self):
        assert normalize_country("XX") is None

    def test_empty(self):
        assert normalize_country("") is None


class TestTimestampNormalizer:
    """Tests for timestamp normalization."""

    def test_dd_mm_yyyy_format(self):
        result = normalize_timestamp("18.05.2026 21:12:43")
        assert result == "2026-05-18T21:12:43"

    def test_invalid_format(self):
        assert normalize_timestamp("2026-05-18") is None
        assert normalize_timestamp("") is None
        assert normalize_timestamp("invalid") is None

    def test_edge_cases(self):
        assert normalize_timestamp("01.01.2026 00:00:00") == "2026-01-01T00:00:00"
        assert normalize_timestamp("31.12.2026 23:59:59") == "2026-12-31T23:59:59"


class TestBrowserNormalizer:
    """Tests for browser name normalization."""

    def test_known_browsers(self):
        assert normalize_browser("Google Chrome") == "Google Chrome"
        assert normalize_browser("Chrome") == "Google Chrome"
        assert normalize_browser("Microsoft Edge") == "Microsoft Edge"
        assert normalize_browser("Edge") == "Microsoft Edge"
        assert normalize_browser("Mozilla Firefox") == "Mozilla Firefox"
        assert normalize_browser("Firefox") == "Mozilla Firefox"
        assert normalize_browser("Brave") == "Brave"
        assert normalize_browser("Opera") == "Opera"
        assert normalize_browser("Opera GX") == "Opera GX"

    def test_version_in_browser_name(self):
        assert normalize_browser("Edge 147.0.3912.86") == "Microsoft Edge"
        assert normalize_browser("Chrome 147.0.7727.138") == "Google Chrome"

    def test_unknown_browser(self):
        assert normalize_browser("Unknown Browser") == "Unknown Browser"
        assert normalize_browser("") == "Unknown"
