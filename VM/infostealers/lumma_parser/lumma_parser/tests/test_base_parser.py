"""Tests for the BaseParser watermark stripping logic."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lumma_parser.parsers.base import BaseParser


class TestWatermarkStripping:
    """Tests for the Lumma watermark stripping logic."""

    def test_clean_content(self) -> None:
        """Content without watermark is returned as-is."""
        text = "SOFT: Chrome Default (147.0.7727.138)\nURL: https://example.com\n"
        result = BaseParser._strip_watermark(text)
        assert result == text

    def test_watermark_with_separator(self) -> None:
        """Content with watermark separator is cleaned."""
        text = """



x Usernames @kir3cloud are NO LONGER managed.
==========================================================================================
SOFT: Chrome Default (147.0.7727.138)
URL: https://example.com
PASS: secret123
  ASCII art block here
@kiri3nfo
"""
        result = BaseParser._strip_watermark(text)
        assert "SOFT:" in result
        assert "URL:" in result
        assert "PASS:" in result
        assert "===========" not in result
        assert "@kir3cloud" not in result

    def test_spam_line_detection(self) -> None:
        """Lines with >50% non-ASCII characters are detected as spam."""
        spam_line = "@𝓴𝓲𝓻3𝓲𝓷𝓯𝓸 @𝒌𝒊𝒓3𝒊𝓷𝓯𝓸 @𝐤𝐢𝐫3𝐢𝓷𝓯𝓸"
        assert BaseParser._is_spam_line(spam_line) is True

        normal_line = "SOFT: Chrome Default (147.0.7727.138)"
        assert BaseParser._is_spam_line(normal_line) is False

    def test_ascii_art_detection(self) -> None:
        """Lines with many box-drawing characters are detected as ASCII art."""
        art_line = "  " + "█" * 20 + "  "
        assert BaseParser._is_ascii_art_block(art_line) is True

        normal_line = "Processor: Intel Core i5-12400F"
        assert BaseParser._is_ascii_art_block(normal_line) is False
