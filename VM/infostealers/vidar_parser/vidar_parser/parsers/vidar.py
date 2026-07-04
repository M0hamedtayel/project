"""Vidar stealer-specific parser — orchestrates all per-file-type parsers."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from vidar_parser.models import (
    VictimRecord,
    Victim,
    VictimId,
    VictimIdentity,
    VictimNetwork,
    VictimOS,
    VictimHardware,
    Metadata,
    Statistics,
    CredentialData,
    BrowserData,
    SteamData,
    TelegramData,
    DiscordData,
    FilesData,
    Credential,
    Cookie,
    HistoryEntry,
    AutofillEntry,
    GoogleAccountToken,
    NotableSoftware,
    NotableProcess,
    SteamAccount,
    SteamLibraryFolder,
    SteamToken,
    TelegramSession,
    DiscordToken,
    Extension2FA,
    BrowserSource,
    CookieBrowserSummary,
    HistoryBrowserSummary,
)
from vidar_parser.normalizers.country import normalize_country
from vidar_parser.normalizers.timestamp import normalize_timestamp
from vidar_parser.normalizers.browser import normalize_browser

from .information import InformationParser
from .passwords import PasswordsParser
from .cookies import CookiesParser
from .google_accounts import GoogleAccountsParser
from .steam import SteamParser
from .telegram import TelegramParser
from .discord import DiscordParser
from .history import HistoryParser
from .plugins import PluginsParser
from .files import FilesParser
from .autofill import AutofillParser


class VidarParser:
    """Orchestrates parsing of a single Vidar log directory.

    Collects data from all per-file-type parsers and assembles
    a unified VictimRecord.
    """

    def __init__(self, log_dir: Path, source_file: str = "") -> None:
        self.log_dir = log_dir
        self.source_file = source_file

    def parse(self) -> VictimRecord:
        """Parse all files in the log directory and return a VictimRecord."""
        record = VictimRecord()

        # Parse all data sources
        data = self._run_all_parsers()

        # Assemble victim profile
        record.victim = self._build_victim(data)

        # Assemble credentials
        record.credentials = self._build_credentials(data)

        # Assemble browser data
        record.browser_data = self._build_browser_data(data)

        # Assemble applications
        record.steam = self._build_steam(data)
        record.telegram = self._build_telegram(data)
        record.discord = self._build_discord(data)

        # Assemble extensions
        record.extensions = self._build_extensions(data)

        # Assemble files
        record.files = self._build_files(data)

        # Assemble notable software and processes
        record.notable_software = self._build_notable_software(data)
        record.notable_processes = self._build_notable_processes(data)

        # Compute statistics
        record.statistics = self._compute_statistics(data)

        # Set metadata
        record.metadata = self._build_metadata(data)

        return record

    def _run_all_parsers(self) -> dict[str, Any]:
        """Run all per-file-type parsers and merge results."""
        data: dict[str, Any] = {}

        try:
            data["information"] = InformationParser(self.log_dir).parse()
        except Exception as e:
            data["information"] = {}
            data["_info_error"] = str(e)

        try:
            data["passwords"] = PasswordsParser(self.log_dir).parse()
        except Exception as e:
            data["passwords"] = {}
            data["_pwd_error"] = str(e)

        try:
            data["cookies"] = CookiesParser(self.log_dir).parse()
        except Exception as e:
            data["cookies"] = {}
            data["_cookies_error"] = str(e)

        try:
            data["google_accounts"] = GoogleAccountsParser(self.log_dir).parse()
        except Exception as e:
            data["google_accounts"] = {}
            data["_google_error"] = str(e)

        try:
            data["steam"] = SteamParser(self.log_dir).parse()
        except Exception as e:
            data["steam"] = {}
            data["_steam_error"] = str(e)

        try:
            data["telegram"] = TelegramParser(self.log_dir).parse()
        except Exception as e:
            data["telegram"] = {}
            data["_telegram_error"] = str(e)

        try:
            data["discord"] = DiscordParser(self.log_dir).parse()
        except Exception as e:
            data["discord"] = {}
            data["_discord_error"] = str(e)

        try:
            data["history"] = HistoryParser(self.log_dir).parse()
        except Exception as e:
            data["history"] = {}
            data["_history_error"] = str(e)

        try:
            data["plugins"] = PluginsParser(self.log_dir).parse()
        except Exception as e:
            data["plugins"] = {}
            data["_plugins_error"] = str(e)

        try:
            data["files"] = FilesParser(self.log_dir).parse()
        except Exception as e:
            data["files"] = {}
            data["_files_error"] = str(e)

        try:
            data["autofill"] = AutofillParser(self.log_dir).parse()
        except Exception as e:
            data["autofill"] = {}
            data["_autofill_error"] = str(e)

        return data

    def _build_metadata(self, data: dict[str, Any]) -> Metadata:
        """Build the metadata section."""
        info = data.get("information", {})
        date_str = info.get("date", "")
        return Metadata(
            parse_timestamp=datetime.utcnow(),
            source_file=self.source_file,
            source_log_date=normalize_timestamp(date_str) or date_str,
        )

    def _build_victim(self, data: dict[str, Any]) -> Victim:
        """Build the victim profile from parsed data."""
        info = data.get("information", {})
        hw = info.get("hardware", {})

        # Parse OS info
        windows_str = info.get("windows", "")
        os_info = self._parse_windows_version(windows_str)

        # Detect hardcoded computer name
        computer_name = info.get("computer_name", "")
        if computer_name in ("Russia 34", ""):
            computer_name = None

        return Victim(
            id=VictimId(
                machine_id=info.get("machine_id", ""),
                guid=info.get("guid", ""),
                hwid=info.get("hwid", ""),
            ),
            identity=VictimIdentity(
                username=info.get("username", ""),
                computer_name=computer_name,
            ),
            network=VictimNetwork(
                ip=info.get("ip", ""),
                country_code=info.get("country", ""),
                country_name=normalize_country(info.get("country", "")),
            ),
            os=VictimOS(
                name=os_info["name"],
                edition=os_info["edition"],
                version=os_info["version"],
                build=os_info["build"],
                display_resolution=info.get("display_resolution", ""),
            ),
            hardware=VictimHardware(
                processor=hw.get("processor", ""),
                cores=hw.get("cores", 0),
                threads=hw.get("threads", 0),
                ram_mb=hw.get("ram_mb", 0),
                video_card=hw.get("videocard", ""),
            ),
        )

    @staticmethod
    def _parse_windows_version(windows_str: str) -> dict[str, str]:
        """Parse 'Windows 11 Pro 25H2 (Build 26200)' into components."""
        name = windows_str.strip()
        edition = ""
        version = ""
        build = ""

        # Extract build number
        build_match = re.search(r"Build\s+(\d+)", windows_str)
        if build_match:
            build = build_match.group(1)

        # Extract version (10 or 11)
        if "Windows 11" in windows_str:
            version = "11"
            name = windows_str.replace("Windows 11", "").strip()
        elif "Windows 10" in windows_str:
            version = "10"
            name = windows_str.replace("Windows 10", "").strip()
        else:
            name = windows_str.replace("Windows ", "").strip()

        # Remove build suffix from name
        name = re.sub(r"\s*\(Build\s+\d+\)", "", name).strip()

        # Edition is what remains (e.g., "Pro", "Home Single Language")
        edition = name
        if version:
            name = f"Windows {version}"

        return {"name": name, "edition": edition, "version": version, "build": build}

    def _build_credentials(self, data: dict[str, Any]) -> CredentialData:
        """Build the credentials section."""
        pwd = data.get("passwords", {})
        accounts_raw = pwd.get("accounts", [])

        # Filter to only entries with actual credentials
        valid_accounts = [
            a for a in accounts_raw
            if a.get("login") and a.get("password")
        ]

        accounts = [
            Credential(
                browser=normalize_browser(a.get("soft", "").split("(")[0].strip() if "(" in a.get("soft", "") else a.get("soft", "")),
                profile=a.get("soft", "").split("(")[-1].rstrip(")") if "(" in a.get("soft", "") else "Unknown",
                url=a.get("url", ""),
                login=a.get("login", ""),
                password=a.get("password", ""),
                credential_type=a.get("credential_type", "website"),
            )
            for a in valid_accounts
        ]

        browser_sources = [
            BrowserSource(
                browser=normalize_browser(s.get("browser", "")),
                profile=s.get("profile", ""),
                credential_count=s.get("count", 0),
            )
            for s in pwd.get("browser_sources", [])
        ]

        return CredentialData(
            total_entries=pwd.get("total_entries", 0),
            with_valid_credentials=len(accounts),
            empty_entries=pwd.get("empty_entries", 0),
            unique_domains=pwd.get("unique_domains", 0),
            browser_sources=browser_sources,
            accounts=accounts,
        )

    def _build_browser_data(self, data: dict[str, Any]) -> BrowserData:
        """Build the browser data section."""
        cookies_data = data.get("cookies", {})
        history_data = data.get("history", {})
        google_data = data.get("google_accounts", {})
        autofill_data = data.get("autofill", {})

        cookies = [
            Cookie(
                browser=c.get("browser", ""),
                profile=c.get("profile", ""),
                domain=c.get("domain", ""),
                name=c.get("name", ""),
                value=c.get("value", ""),
                path=c.get("path", "/"),
                expiry_epoch=c.get("expiry_epoch"),
            )
            for c in cookies_data.get("cookies", [])
        ]

        cookie_summaries = [
            CookieBrowserSummary(
                browser=s.get("browser", ""),
                profile=s.get("profile", ""),
                count=s.get("count", 0),
                top_domains=s.get("top_domains", []),
            )
            for s in cookies_data.get("cookie_summaries", [])
        ]

        history = [
            HistoryEntry(
                browser=h.get("browser", ""),
                profile=h.get("profile", ""),
                url=h.get("url", ""),
            )
            for h in history_data.get("urls", [])
        ]

        history_summaries = [
            HistoryBrowserSummary(
                browser=s.get("browser", ""),
                profile=s.get("profile", ""),
                url_count=s.get("url_count", 0),
            )
            for s in history_data.get("history_summaries", [])
        ]

        google_tokens = [
            GoogleAccountToken(
                browser=t.get("browser", ""),
                profile=t.get("profile", ""),
                token=t.get("token", ""),
            )
            for t in google_data.get("tokens", [])
        ]

        autofill_entries = [
            AutofillEntry(
                browser=e.get("browser", ""),
                profile=e.get("profile", ""),
                entry=e.get("entry", ""),
            )
            for e in autofill_data.get("entries", [])
        ]

        return BrowserData(
            cookies=cookies,
            cookie_summaries=cookie_summaries,
            history=history,
            history_summaries=history_summaries,
            google_accounts=google_tokens,
            autofill=autofill_entries,
        )

    def _build_steam(self, data: dict[str, Any]) -> SteamData:
        """Build the Steam section."""
        steam_data = data.get("steam", {})

        accounts = [
            SteamAccount(
                account_name=a.get("account_name", ""),
                persona_name=a.get("persona_name", ""),
                steam_id=a.get("steam_id", ""),
                remember_password=a.get("remember_password", False),
                library_folders=[
                    SteamLibraryFolder(
                        path=f.get("path", ""),
                        total_size_gb=f.get("total_size_gb", 0),
                        installed_games_count=f.get("installed_games_count", 0),
                    )
                    for f in steam_data.get("library_folders", [])
                ],
                installed_games_count=sum(
                    f.get("installed_games_count", 0)
                    for f in steam_data.get("library_folders", [])
                ),
                has_token=bool(steam_data.get("tokens")),
            )
            for a in steam_data.get("accounts", [])
        ]

        tokens = [
            SteamToken(
                account_name=t.get("account_name", ""),
                steam_id=t.get("steam_id", ""),
                persona_name=t.get("persona_name", ""),
                token=t.get("token", ""),
            )
            for t in steam_data.get("tokens", [])
        ]

        return SteamData(
            present=bool(steam_data),
            accounts=accounts,
            tokens=tokens,
        )

    def _build_telegram(self, data: dict[str, Any]) -> TelegramData:
        """Build the Telegram section."""
        tg_data = data.get("telegram", {})

        if not tg_data:
            return TelegramData()

        sessions = [
            TelegramSession(
                user_hash=hash_id,
                session_files=[],  # Encrypted, no content extraction
            )
            for hash_id in tg_data.get("user_hashes", [])
        ]

        return TelegramData(
            present=True,
            sessions=sessions,
        )

    def _build_discord(self, data: dict[str, Any]) -> DiscordData:
        """Build the Discord section."""
        dc_data = data.get("discord", {})

        if not dc_data:
            return DiscordData()

        tokens = [
            DiscordToken(token=t.get("token", ""))
            for t in dc_data.get("tokens", [])
        ]

        return DiscordData(
            present=True,
            tokens=tokens,
        )

    def _build_extensions(self, data: dict[str, Any]) -> list[Extension2FA]:
        """Build the extensions section."""
        plugin_data = data.get("plugins", {})

        return [
            Extension2FA(
                browser=e.get("browser", ""),
                profile=e.get("profile", ""),
                stored_secrets_count=e.get("stored_secrets_count", 0),
            )
            for e in plugin_data.get("extensions", [])
        ]

    def _build_files(self, data: dict[str, Any]) -> FilesData:
        """Build the files section."""
        files_data = data.get("files", {})

        return FilesData(
            scraped_count=files_data.get("scraped_count", 0),
            screenshots_count=files_data.get("screenshots_count", 0),
            file_types=files_data.get("file_types", []),
        )

    def _build_notable_software(self, data: dict[str, Any]) -> list[NotableSoftware]:
        """Build the notable software list."""
        info = data.get("information", {})
        info_parser = InformationParser(self.log_dir)
        software_list = info.get("software", [])

        notable = info_parser.filter_notable_software(software_list)

        return [
            NotableSoftware(name=sw["name"], category=sw["category"])
            for sw in notable
        ]

    def _build_notable_processes(self, data: dict[str, Any]) -> list[NotableProcess]:
        """Build the notable processes list."""
        info = data.get("information", {})
        info_parser = InformationParser(self.log_dir)
        process_list = info.get("processes", [])

        notable = info_parser.filter_notable_processes(process_list)

        return [
            NotableProcess(name=p["name"], pid=p["pid"])
            for p in notable
        ]

    def _compute_statistics(self, data: dict[str, Any]) -> Statistics:
        """Compute statistics and risk score."""
        pwd = data.get("passwords", {})
        cookies = data.get("cookies", {})
        history = data.get("history", {})
        google = data.get("google_accounts", {})
        steam = data.get("steam", {})
        telegram = data.get("telegram", {})
        discord = data.get("discord", {})
        plugins = data.get("plugins", {})
        info = data.get("information", {})

        # Count unique browsers from credentials
        browsers = set()
        for bs in pwd.get("browser_sources", []):
            browsers.add(bs.get("browser", ""))

        # Count 2FA secrets
        total_2fa = plugins.get("total_2fa_secrets", 0)

        stats = Statistics(
            total_credentials=pwd.get("total_entries", 0),
            total_passwords=pwd.get("with_valid_credentials", 0),
            total_empty_entries=pwd.get("empty_entries", 0),
            total_cookies=cookies.get("total_count", 0),
            total_history_urls=history.get("total_count", 0),
            total_google_tokens=google.get("total_count", 0),
            total_autofill_entries=plugins.get("total_count", 0),
            total_wallets=0,
            total_discord_tokens=len(discord.get("tokens", [])),
            total_telegram_sessions=len(telegram.get("user_hashes", [])),
            total_steam_accounts=len(steam.get("accounts", [])),
            total_2fa_secrets=total_2fa,
            unique_browsers=len(browsers),
            unique_domains_in_credentials=pwd.get("unique_domains", 0),
            notable_software_count=len(
                self._build_notable_software(data)
            ),
            notable_process_count=len(
                self._build_notable_processes(data)
            ),
            has_real_credentials=pwd.get("with_valid_credentials", 0) > 0,
            has_google_tokens=google.get("total_count", 0) > 0,
            has_steam_access=bool(steam.get("accounts")),
            has_telegram_access=bool(telegram.get("present")),
            has_2fa_tokens=total_2fa > 0,
            has_discord_access=bool(discord.get("tokens")),
        )

        # Compute risk score (0-10)
        score = 0.0
        if stats.total_passwords > 0:
            score += min(3.0, stats.total_passwords * 0.1)
        if stats.total_google_tokens > 0:
            score += 2.0
        if stats.has_steam_access:
            score += 1.0
        if stats.has_telegram_access:
            score += 1.5
        if stats.has_discord_access:
            score += 1.0
        if stats.total_2fa_secrets > 0:
            score += min(2.0, stats.total_2fa_secrets * 0.2)
        if stats.total_cookies > 0:
            score += min(1.0, stats.total_cookies * 0.001)
        stats.risk_score = round(min(10.0, score), 1)

        return stats
