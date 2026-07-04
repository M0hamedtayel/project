"""Tests for the Information parser."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remus_parser.parsers.information import InformationParser


@pytest.fixture
def mock_log_dir(tmp_path: Path) -> Path:
    """Create a mock Remus log directory with Info.txt."""
    info_content = textwrap.dedent(
        """\
        # REMUS LOG

        build:
          date: 25.04.2026
          tag: ee9a05623c6f
          path: C:\\Users\\isaia\\OneDrive\\Escritorio\\Вооstаррес__х64\\Sеt_Up [UРD].exe
          elevated: false
          ip-address: 45.178.2.162
          country: AR
          time: 01.05.2026, 22:17:02
        os:
          version: Windows 11 Home (10.0.26200) x64
          time-zone: UTC-3
          local-date: 01.05.2026 19:16:56
          install-date: 11.04.2026 09:16:14
          language: es-AR
          computer-name: ISAIAS
          user-name: isaia
          netbios: ISAIAS
          domain:
          hostname: isaias
          anti-virus:
          - name: Windows Defender
            state: active
        hardware:
          motherboard:
            manufacturer: HP
            product: HP Laptop 14-dk1xxx
          cpu:
          - manufacturer: Advanced Micro Devices, Inc.
            product: AMD Ryzen 3 3250U with Radeon Graphics
            core count: 2
            core enabled: 2
            thread count: 4
          ram:
          - product: M471A5244CB0-CWE
            size: 4096MB
          - product: 4ATF51264HZ-3G2J1
            size: 4096MB
          gpu:
          - AMD Radeon(TM) Graphics
          display: 1366x768
        """
    )
    (tmp_path / "Info.txt").write_text(info_content, encoding="utf-8")
    return tmp_path


def test_parse_info_file(mock_log_dir: Path):
    """Test parsing a standard Info.txt file."""
    parser = InformationParser(mock_log_dir)
    result = parser.parse()

    assert result["build_date"] == "25.04.2026"
    assert result["build_tag"] == "ee9a05623c6f"
    assert result["ip_address"] == "45.178.2.162"
    assert result["country"] == "AR"
    assert result["time"] == "01.05.2026, 22:17:02"
    assert result["os_version"] == "Windows 11 Home (10.0.26200) x64"
    assert result["time_zone"] == "UTC-3"
    assert result["local_date"] == "01.05.2026 19:16:56"
    assert result["install_date"] == "11.04.2026 09:16:14"
    assert result["language"] == "es-AR"
    assert result["computer_name"] == "ISAIAS"
    assert result["user_name"] == "isaia"
    assert result["hostname"] == "isaias"
    assert result["elevated"] is False


def test_parse_antivirus(mock_log_dir: Path):
    """Test parsing anti-virus entries."""
    parser = InformationParser(mock_log_dir)
    result = parser.parse()

    av = result["antivirus"]
    assert len(av) == 1
    assert av[0]["name"] == "Windows Defender"
    assert av[0]["state"] == "active"


def test_parse_hardware(mock_log_dir: Path):
    """Test parsing hardware section."""
    parser = InformationParser(mock_log_dir)
    result = parser.parse()

    hw = result["hardware"]

    # Motherboard
    mb = hw.get("motherboard", [])
    assert len(mb) == 1
    assert mb[0]["manufacturer"] == "HP"
    assert mb[0]["product"] == "HP Laptop 14-dk1xxx"

    # CPU
    cpu = hw.get("cpu", [])
    assert len(cpu) == 1
    assert cpu[0]["manufacturer"] == "Advanced Micro Devices, Inc."
    assert cpu[0]["product"] == "AMD Ryzen 3 3250U with Radeon Graphics"
    assert cpu[0]["core_count"] == 2
    assert cpu[0]["core_enabled"] == 2
    assert cpu[0]["thread_count"] == 4

    # RAM
    ram = hw.get("ram", [])
    assert len(ram) == 2
    assert ram[0]["size"] == "4096MB"
    assert ram[1]["size"] == "4096MB"

    # GPU
    gpu = hw.get("gpu", [])
    assert len(gpu) == 1
    assert gpu[0]["product"] == "AMD Radeon(TM) Graphics"


def test_missing_info_file(tmp_path: Path):
    """Test that missing Info.txt returns empty dict."""
    parser = InformationParser(tmp_path)
    result = parser.parse()
    assert result == {}


def test_empty_info_file(tmp_path: Path):
    """Test that empty Info.txt returns empty dict with no valid data."""
    (tmp_path / "Info.txt").write_text("", encoding="utf-8")
    parser = InformationParser(tmp_path)
    result = parser.parse()
    assert result["build_date"] == ""
    assert result["ip_address"] == ""
    assert result["antivirus"] == []
    assert result["hardware"] == {}


def test_multiple_antivirus(tmp_path: Path):
    """Test parsing multiple anti-virus entries."""
    info_content = textwrap.dedent(
        """\
        build:
          date: 01.05.2026
          tag: abc123
          ip-address: 1.2.3.4
          country: US
          time: 01.05.2026, 12:00:00
        os:
          version: Windows 11 Pro
          time-zone: UTC-5
          local-date: 01.05.2026 09:00:00
          install-date: 01.01.2024 00:00:00
          language: en-US
          computer-name: TESTPC
          user-name: testuser
          netbios: TESTPC
          domain:
          hostname: testpc
          anti-virus:
          - name: Windows Defender
            state: active
          - name: Malwarebytes
            state: inactive
        hardware:
          cpu:
          - manufacturer: Intel
            product: Intel Core i7
            core count: 8
            core enabled: 8
            thread count: 16
        """
    )
    (tmp_path / "Info.txt").write_text(info_content, encoding="utf-8")

    parser = InformationParser(tmp_path)
    result = parser.parse()

    av = result["antivirus"]
    assert len(av) == 2
    assert av[0]["name"] == "Windows Defender"
    assert av[0]["state"] == "active"
    assert av[1]["name"] == "Malwarebytes"
    assert av[1]["state"] == "inactive"
