"""Parser for information.txt — system profile, hardware, processes, software."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vidar_parser.parsers.base import BaseParser

# Hardcoded values to detect and exclude
HARDCODED_VALUES: set[str] = {"Russia 34", "Admin @logslead", "C:\\Windows\\SysWOW32\\install.exe"}

# System processes to filter out when building notable list
SYSTEM_PROCESSES: frozenset[str] = frozenset({
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    "spoolsv.exe", "conhost.exe", "amdfendrsr.exe", "atiesrxx.exe",
    "AsusCertService.exe", "atieclxx.exe", "Memory Compression", "WMIRegistrationService.exe",
    "MpDefenderCoreService.exe", "MsMpEng.exe", "GameSDK.exe", "ArmouryCrate.Service.exe",
    "OnScreenControlControlService.exe", "FoxitPDFEditorUpdateService.exe",
    "atkexComSvc.exe", "AsusFanControlService.exe", "jhi_service.exe",
    "RtkAudUService64.exe", "RstMwService.exe", "LightingService.exe",
    "OfficeClickToRun.exe", "SearchIndexer.exe", "wlanext.exe", "unsecapp.exe",
    "AggregatorHost.exe", "sihost.exe", "ShellHost.exe", "AcPowerNotification.exe",
    "ArmourySocketServer.exe", "SearchHost.exe", "StartMenuExperienceHost.exe",
    "WidgetBoard.exe", "RuntimeBroker.exe", "crashpad_handler.exe", "WidgetService.exe",
    "msedgewebview2.exe", "MicrosoftStartFeedProvider.exe", "ASUS DriverHub.exe",
    "ctfmon.exe", "asus_framework.exe", "SecurityHealthSystray.exe",
    "SecurityHealthService.exe", "TextInputHostHost.exe", "AppMarket.exe",
    "OneDrive.exe", "steamservice.exe", "wmpf_installer.exe", "IDMan.exe",
    "RadeonSoftware.exe", "fdm.exe", "ce-installer_7.14.2_vbox-7.2.8.exe",
    "VC_redist.x64.exe", "VSSVC.exe", "backgroundTaskHost.exe", "msiexec.exe",
    "starter.exe", "GameBarPresenceWriter.exe", "GameBar.exe",
    "GameBarFTServer.exe", "XboxGameBarWidgets.exe", "SearchProtocolHost.exe",
    "audiodg.exe", "SearchFilterHost.exe", "smartscreen.exe",
    "SecHealthUI.exe", "SecurityHealthHost.exe", "OpenConsole.exe",
    "brave.exe", "brave.exe", "Explorer.exe", "explorer.exe",
    "ShellExperienceHost.exe", "ApplicationFrameHost.exe", "SystemSettings.exe",
    "XboxPcAppFT.exe", "FileCoAuth.exe", "AppActions.exe",
    "SDXHelper.exe", "acrotray.exe", "LockApp.exe", "RuntimeBroker.exe",
    "YouTube Video Downloader 2025 (YTD) 8.11.3.3 Pro & Portable.exe",
    "SDXHelper.exe", "cam_helper.exe", "acpowernotification.exe",
    "upc.exe", "set_1.exe", "hwqULSIIc95.exe",
    "9mHVM3jTgKj.exe", "upc.exe",
    "CHXSmartScreen.exe", "upc.exe",
    "BrowserHelperObject.exe", "RuntimeBroker.exe", "svchost.exe",
})

# Software categories for classification
SOFTWARE_CATEGORIES: dict[str, str] = {
    # Browsers
    "Chrome": "browser", "Firefox": "browser", "Edge": "browser",
    "Brave": "browser", "Opera": "browser", "Safari": "browser",
    "CefRendererProcess": "browser", "cef_frame_render": "browser",
    "msedgewebview2": "browser",
    # Gaming
    "Steam": "gaming", "EpicGamesLauncher": "gaming", "UplayWebCore": "gaming",
    "GameLoop": "gaming", "NARAKA": "gaming", "Metro": "gaming",
    "Ghost": "gaming", "Tom Clancy": "gaming", "Where Winds Meet": "gaming",
    "Metro Exodus": "gaming", "Metro 2033": "gaming", "Metro: Last Light": "gaming",
    "The Division": "gaming", "ArmouryCrate": "gaming", "ROG": "gaming",
    "AURA": "gaming", "ASUS": "gaming",
    # Office
    "Office": "office", "Microsoft Office": "office", "Adobe": "office",
    "Foxit": "office", "PDF": "office", "WinRAR": "office", "DiskGenius": "office",
    "Revo": "office", "pdf24": "office",
    # Security
    "Avira": "security", "UrbanVPN": "security", "SoftEther": "security",
    "vpncmgr": "security", "vpnclient": "security", "AnyDesk": "security",
    "Smartscreen": "security", "SecHealth": "security", "MsMpEng": "security",
    "NisSrv": "security",
    # Communication
    "Discord": "communication", "Telegram": "communication", "Zoom": "communication",
    "Slack": "communication", "WhatsApp": "communication",
    # Development
    "Python": "development", "Node.js": "development", "Visual Studio": "development",
    "PyCharm": "development", "VS Code": "development",
    # VPN
    "VPN": "vpn", "VPN Client": "vpn", "SoftEther VPN": "vpn",
    "UrbanVPN": "vpn",
    # FTP
    "FileZilla": "ftp", "WinSCP": "ftp", "Free Download Manager": "ftp",
    "IDMan": "ftp",
    # Other
    "AMD": "other", "Intel": "other", "NVIDIA": "other", "ASUS": "other",
    "NZXT": "other", "Maxon": "other", "MediaTek": "other",
    "Dynamic Application Loader": "other",
    "Branding64": "other", "Dynamic Application Loader": "other",
    "WiFi Explorer": "other", "Topaz": "other",
}


class InformationParser(BaseParser):
    """Parses information.txt from Vidar logs."""

    supported_file_pattern = "information.txt"

    def parse(self) -> dict[str, Any]:
        """Parse information.txt and return structured data."""
        info_file = self.log_dir / "information.txt"
        content = self.read_file_with_timeout(info_file)
        if content is None:
            return {}

        return {
            "ip": self._extract_field(content, "Ip"),
            "country": self._extract_field(content, "Country"),
            "date": self._extract_field(content, "Date"),
            "machine_id": self._extract_field(content, "MachineID"),
            "guid": self._extract_field(content, "GUID"),
            "hwid": self._extract_field(content, "HWID"),
            "computer_name": self._extract_field(content, "Computer Name"),
            "username": self._extract_field(content, "User Name"),
            "windows": self._extract_field(content, "Windows"),
            "display_resolution": self._extract_field(content, "Display Resolution"),
            "local_time": self._extract_field(content, "Local Time"),
            "hardware": self._parse_hardware(content),
            "processes": self._parse_processes(content),
            "software": self._parse_software(content),
        }

    @staticmethod
    def _extract_field(content: str, field_name: str) -> str:
        """Extract a key: value field from the content."""
        pattern = rf"^{re.escape(field_name)}:\s*(.+)$"
        match = re.search(pattern, content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return ""

    def _parse_hardware(self, content: str) -> dict[str, Any]:
        """Parse the [Hardware] section."""
        hardware: dict[str, Any] = {}
        in_section = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[Hardware]":
                in_section = True
                continue
            if stripped.startswith("[") and in_section:
                break
            if in_section and ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "RAM":
                    # "RAM: 32504 MB"
                    ram_match = re.search(r"(\d+)", value)
                    if ram_match:
                        hardware["ram_mb"] = int(ram_match.group(1))
                    else:
                        hardware["ram_mb"] = 0
                elif key in ("Cores", "Threads"):
                    try:
                        hardware[key.lower()] = int(value)
                    except ValueError:
                        hardware[key.lower()] = 0
                else:
                    hardware[key.lower()] = value

        return hardware

    def _parse_processes(self, content: str) -> list[dict[str, Any]]:
        """Parse the [Processes] section, returning all process entries."""
        processes: list[dict[str, Any]] = []
        in_section = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[Processes]":
                in_section = True
                continue
            if in_section:
                # Section headers look like "[Software]" — break on those
                if re.match(r"^\[[A-Za-z]+\]$", stripped):
                    break
                # Process entries look like "  [1234] process.exe"
                match = re.match(r"\[(\d+)\]\s+(.+)", stripped)
                if match:
                    processes.append({
                        "pid": int(match.group(1)),
                        "name": match.group(2).strip(),
                    })

        return processes

    def _parse_software(self, content: str) -> list[str]:
        """Parse the [Software] section, returning raw software names."""
        software: list[str] = []
        in_section = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[Software]":
                in_section = True
                continue
            if in_section:
                if re.match(r"^\[[A-Za-z]+\]$", stripped):
                    break
                if stripped:
                    software.append(stripped)

        return software

    def filter_notable_software(self, software_list: list[str]) -> list[dict[str, str]]:
        """Filter software list to notable entries with categories.

        Skips runtime redistributables, driver packages, and generic services.
        """
        notable: list[dict[str, str]] = []
        seen: set[str] = set()

        for sw in software_list:
            sw_lower = sw.lower()
            category = None

            # Check known categories
            for keyword, cat in SOFTWARE_CATEGORIES.items():
                if keyword.lower() in sw_lower:
                    category = cat
                    break

            # Skip if no category matched or it's a runtime/redist
            if category is None:
                continue
            if "redistributable" in sw_lower or "runtime" in sw_lower:
                continue
            if "driver" in sw_lower and "chipset" not in sw_lower:
                continue
            if "service" in sw_lower:
                continue
            if "components" in sw_lower:
                continue
            if "additional" in sw_lower:
                continue
            if "minimum" in sw_lower:
                continue

            # Deduplicate by name
            if sw in seen:
                continue
            seen.add(sw)

            notable.append({"name": sw, "category": category})

        return notable

    def filter_notable_processes(
        self, process_list: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Filter processes to notable (non-system) entries."""
        notable: list[dict[str, Any]] = []
        seen: set[str] = set()

        for proc in process_list:
            name = proc["name"].lower()

            # Skip known system processes
            if name in SYSTEM_PROCESSES:
                continue

            # Skip generic svchost, conhost, RuntimeBroker, etc.
            if name in ("svchost.exe", "conhost.exe", "runtimebroker.exe"):
                continue

            # Skip crash handlers and helper services
            if "crashhandler" in name or "helperservice" in name:
                continue

            # Skip duplicate names
            if name in seen:
                continue
            seen.add(name)

            notable.append({
                "name": proc["name"],
                "pid": proc["pid"],
            })

        # Sort by PID for consistency
        notable.sort(key=lambda p: p["pid"])

        return notable
