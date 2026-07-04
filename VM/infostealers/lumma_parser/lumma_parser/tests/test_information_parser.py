"""Tests for the InformationParser."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path
from textwrap import dedent

from lumma_parser.parsers.information import InformationParser


# A clean Info.txt without watermark
_CLEAN_INFO = dedent("""\
Build Date: Apr 23 2026
Configuration:
Execution Path: C:\\Users\\21TECH~1\\AppData\\Local\\Temp\\k7JtF5wTA7.exe
Elevated: No
Computer Name: DESKTOP-80AFJGA
User Name: 21Technology
User Language: en-US
Netbios: DESKTOP-80AFJGA
Operation System: Windows 11 Pro 10.0.26100 (x64)
Install Date: 28.01.2025 14:35:29
System Date: 01.05.2026 19:18:16
Time Zone: UTC+6
Antivirus: Windows Defender
HWID: 147CC54D868FDF5C4764B84878CA866D
Processor: AMD Ryzen 7 PRO 4750U with Radeon Graphics
Processor Threads: 16
Processor Cores: 8
Graphics Card:
\tAMD Radeon(TM) Graphics
Installed RAM: 16384MB
Display Resolution: 1920x1080

IP Address: 203.76.222.155
Time: 01.05.2026 16:18:09 (sig:1777641489.c8ae78aa4c86cf727f4e045fa54ccf8c)
Country: BD
""")


# Info.txt with Lumma watermark header
_INFO_WITH_WATERMARK = dedent("""\



x Usernames @kir3cloud are NO LONGER managed by us.
Please be careful to AVOID SCAMS.
@kiri3nfo
==========================================================================================
Build Date: Apr 23 2026
Configuration:
Execution Path: C:\\Users\\test\\AppData\\Roaming\\abc.exe
Elevated: Yes
Computer Name: DESKTOP-TEST
User Name: testuser
User Language: en-CA
Netbios: DESKTOP-TEST
Operation System: Windows 11 Home 10.0.26200 (x64)
Install Date: 15.02.2026 15:47:32
System Date: 01.05.2026 00:14:12
Time Zone: UTC-4
Antivirus: Windows Defender
HWID: BAC4B0C2CAF21F67FE8C5DFCF4CB9103
Processor: Intel(R) Core(TM) i5-14400F
Processor Threads: 16
Processor Cores: 8
Graphics Card:
\tNVIDIA GeForce RTX 4060
Installed RAM: 16384MB
Display Resolution: 1920x1080
@kir3info
IP Address: 99.225.254.241
Time: 01.05.2026 07:14:13 (sig:1777608853.3d60fdbf2219a6926fabb32784e463fe)
Country: CA
  ASCII art banner
@kiri3nfo
""")


def test_clean_info(tmp_path: Path) -> None:
    """Parser extracts fields from a clean Info.txt."""
    info_file = tmp_path / "Info.txt"
    info_file.write_text(_CLEAN_INFO, encoding="utf-8")

    parser = InformationParser(tmp_path)
    result = parser.parse()

    assert result["build_date"] == "Apr 23 2026"
    assert result["execution_path"] == "C:\\Users\\21TECH~1\\AppData\\Local\\Temp\\k7JtF5wTA7.exe"
    assert result["elevated"] is False
    assert result["computer_name"] == "DESKTOP-80AFJGA"
    assert result["user_name"] == "21Technology"
    assert result["language"] == "en-US"
    assert result["hostname"] == "DESKTOP-80AFJGA"
    assert result["os_version"] == "Windows 11 Pro 10.0.26100 (x64)"
    assert result["install_date"] == "28.01.2025 14:35:29"
    assert result["local_date"] == "01.05.2026 19:18:16"
    assert result["time_zone"] == "UTC+6"
    assert result["antivirus"] == "Windows Defender"
    assert result["hwid"] == "147CC54D868FDF5C4764B84878CA866D"
    assert result["processor"] == "AMD Ryzen 7 PRO 4750U with Radeon Graphics"
    assert result["processor_threads"] == "16"
    assert result["processor_cores"] == "8"
    assert result["gpu"] == "AMD Radeon(TM) Graphics"
    assert result["ram"] == "16384MB"
    assert result["display"] == "1920x1080"
    assert result["ip_address"] == "203.76.222.155"
    assert result["country"] == "BD"


def test_info_with_watermark(tmp_path: Path) -> None:
    """Parser extracts fields from Info.txt with watermark."""
    info_file = tmp_path / "Info.txt"
    info_file.write_text(_INFO_WITH_WATERMARK, encoding="utf-8")

    parser = InformationParser(tmp_path)
    result = parser.parse()

    assert result["build_date"] == "Apr 23 2026"
    assert result["computer_name"] == "DESKTOP-TEST"
    assert result["user_name"] == "testuser"
    assert result["elevated"] is True
    assert result["os_version"] == "Windows 11 Home 10.0.26200 (x64)"
    assert result["ip_address"] == "99.225.254.241"
    assert result["country"] == "CA"
    assert result["hwid"] == "BAC4B0C2CAF21F67FE8C5DFCF4CB9103"


def test_missing_info_file(tmp_path: Path) -> None:
    """Parser returns empty dict when Info.txt is missing."""
    parser = InformationParser(tmp_path)
    result = parser.parse()

    assert result == {}
