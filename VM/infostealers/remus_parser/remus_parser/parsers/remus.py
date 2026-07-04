"""Remus stealer-specific parser — orchestrates all per-file-type parsers."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from remus_parser.models import (
    VictimRecord,
    Victim,
    VictimId,
    VictimIdentity,
    VictimNetwork,
    VictimOS,
    VictimHardware,
    VictimHardwareInfo,
    VictimAntivirus,
    Metadata,
    Statistics,
    CredentialData,
    BrowserData,
    TelegramData,
    DiscordData,
    FilesData,
    WalletData,
    Credential,
    Cookie,
    HistoryEntry,
    AutofillEntry,
    GoogleAccountToken,
    TelegramSession,
    DiscordToken,
    CookieBrowserSummary,
    HistoryBrowserSummary,
)
from remus_parser.normalizers.country import normalize_country
from remus_parser.normalizers.timestamp import normalize_timestamp
from remus_parser.normalizers.browser import normalize_browser

from .information import InformationParser
from .credentials import CredentialsParser
from .cookies import CookiesParser
from .google_accounts import GoogleAccountsParser
from .telegram import TelegramParser
from .discord import DiscordParser
from .history import HistoryParser
from .autofill import AutofillParser
from .important_files import ImportantFilesParser
from .wallets import WalletsParser
from .credit_cards import CreditCardsParser


class RemusParser:
    """Orchestrates parsing of a single Remus log directory.

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
        record.telegram = self._build_telegram(data)
        record.discord = self._build_discord(data)

        # Assemble files
        record.files = self._build_files(data)

        # Assemble wallets
        record.wallets = self._build_wallets(data)

        # Assemble credit cards
        self._build_credit_cards(data, record)

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
            data["credentials"] = CredentialsParser(self.log_dir).parse()
        except Exception as e:
            data["credentials"] = {}
            data["_cred_error"] = str(e)

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
            data["autofill"] = AutofillParser(self.log_dir).parse()
        except Exception as e:
            data["autofill"] = {}
            data["_autofill_error"] = str(e)

        try:
            data["files"] = ImportantFilesParser(self.log_dir).parse()
        except Exception as e:
            data["files"] = {}
            data["_files_error"] = str(e)

        try:
            data["wallets"] = WalletsParser(self.log_dir).parse()
        except Exception as e:
            data["wallets"] = {}
            data["_wallets_error"] = str(e)

        try:
            data["credit_cards"] = CreditCardsParser(self.log_dir).parse()
        except Exception as e:
            data["credit_cards"] = {}
            data["_credit_cards_error"] = str(e)

        return data

    def _build_metadata(self, data: dict[str, Any]) -> Metadata:
        """Build the metadata section."""
        info = data.get("information", {})
        date_str = info.get("time", "")
        return Metadata(
            parse_timestamp=datetime.utcnow(),
            source_file=self.source_file,
            source_log_date=normalize_timestamp(date_str) or date_str,
            build_date=info.get("build_date", ""),
            build_tag=info.get("build_tag", ""),
        )

    def _build_victim(self, data: dict[str, Any]) -> Victim:
        """Build the victim profile from parsed data."""
        info = data.get("information", {})

        return Victim(
            id=VictimId(
                machine_id="",
                guid="",
                hwid="",
            ),
            identity=VictimIdentity(
                username=info.get("user_name", ""),
                computer_name=info.get("computer_name", ""),
            ),
            network=VictimNetwork(
                ip=info.get("ip_address", ""),
                country_code=info.get("country", ""),
                country_name=normalize_country(info.get("country", "")),
            ),
            os=VictimOS(
                version=info.get("os_version", ""),
                time_zone=info.get("time_zone", ""),
                local_date=info.get("local_date", ""),
                install_date=info.get("install_date", ""),
                language=info.get("language", ""),
                hostname=info.get("hostname", ""),
            ),
            hardware=self._build_hardware(info.get("hardware", {})),
            anti_virus=[
                VictimAntivirus(name=av.get("name", ""), state=av.get("state", ""))
                for av in info.get("antivirus", [])
            ],
        )

    def _build_hardware(self, hw_data: dict[str, Any]) -> VictimHardware:
        """Build the hardware section from parsed Info data."""
        motherboard = VictimHardwareInfo()
        cpu = VictimHardwareInfo()
        ram_list: list[VictimHardwareInfo] = []
        gpu_list: list[VictimHardwareInfo] = []
        display = ""

        # Parse motherboard
        mb_entries = hw_data.get("motherboard", [])
        if mb_entries:
            mb = mb_entries[0]
            motherboard = VictimHardwareInfo(
                manufacturer=mb.get("manufacturer", ""),
                product=mb.get("product", ""),
            )

        # Parse CPU
        cpu_entries = hw_data.get("cpu", [])
        if cpu_entries:
            c = cpu_entries[0]
            cpu = VictimHardwareInfo(
                manufacturer=c.get("manufacturer", ""),
                product=c.get("product", ""),
                core_count=c.get("core_count", 0),
                core_enabled=c.get("core_enabled", 0),
                thread_count=c.get("thread_count", 0),
            )

        # Parse RAM
        ram_entries = hw_data.get("ram", [])
        for r in ram_entries:
            ram_list.append(VictimHardwareInfo(
                product=r.get("product", ""),
                size=r.get("size", ""),
            ))

        # Parse GPU
        gpu_entries = hw_data.get("gpu", [])
        for g in gpu_entries:
            gpu_list.append(VictimHardwareInfo(
                product=g.get("product", ""),
            ))

        # Parse display resolution from OS version string if available
        # We need to look at the raw OS version for display
        # For now, it's not available from parsed hardware dict

        return VictimHardware(
            motherboard=motherboard,
            cpu=cpu,
            ram=ram_list,
            gpu=gpu_list,
            display=display,
        )

    def _build_credentials(self, data: dict[str, Any]) -> CredentialData:
        """Build the credentials section."""
        cred = data.get("credentials", {})
        accounts_raw = cred.get("accounts", [])

        accounts = [
            Credential(
                browser=normalize_browser(a.get("browser", "")),
                profile=a.get("profile", "Default"),
                url=a.get("url", ""),
                login=a.get("login", ""),
                password=a.get("password", ""),
                date=a.get("date", ""),
            )
            for a in accounts_raw
        ]

        return CredentialData(
            total_entries=cred.get("total_entries", 0),
            with_valid_credentials=cred.get("with_valid_credentials", 0),
            empty_entries=cred.get("empty_entries", 0),
            unique_domains=cred.get("unique_domains", 0),
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
                secure=c.get("secure", False),
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
                title=h.get("title", ""),
                timestamp=h.get("timestamp", ""),
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
                name=e.get("name", ""),
                value=e.get("value", ""),
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

    def _build_telegram(self, data: dict[str, Any]) -> TelegramData:
        """Build the Telegram section."""
        tg_data = data.get("telegram", {})

        if not tg_data:
            return TelegramData()

        sessions = [
            TelegramSession(
                user_hash=hash_id,
                session_files=[],
                decrypted=False,
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

    def _build_files(self, data: dict[str, Any]) -> FilesData:
        """Build the files section."""
        files_data = data.get("files", {})

        return FilesData(
            scraped_count=files_data.get("scraped_count", 0),
            file_paths=files_data.get("file_paths", []),
        )

    def _build_wallets(self, data: dict[str, Any]) -> WalletData:
        """Build the wallets section."""
        wallet_data = data.get("wallets", {})

        from remus_parser.models.types_ import WalletEntry

        wallets = [
            WalletEntry(
                wallet_name=w.get("wallet_name", ""),
                browser=w.get("browser", ""),
                profile=w.get("profile", ""),
                files=w.get("files", []),
            )
            for w in wallet_data.get("wallets", [])
        ]

        return WalletData(
            wallets=wallets,
            total_wallets=wallet_data.get("total_wallets", 0),
        )

    def _build_credit_cards(
        self, data: dict[str, Any], record: VictimRecord,
    ) -> None:
        """Build the credit cards section inside browser data."""
        cc_data = data.get("credit_cards", {})

        from remus_parser.models.types_ import CreditCardEntry

        record.browser_data.credit_cards = [
            CreditCardEntry(
                card_number=e.get("card_number", ""),
                cardholder_name=e.get("cardholder_name", ""),
                expiry_date=e.get("expiry_date", ""),
                cvc=e.get("cvc", ""),
                browser=e.get("browser", ""),
                profile=e.get("profile", ""),
            )
            for e in cc_data.get("credit_cards", [])
        ]

    def _compute_statistics(self, data: dict[str, Any]) -> Statistics:
        """Compute statistics and risk score."""
        cred = data.get("credentials", {})
        cookies = data.get("cookies", {})
        history = data.get("history", {})
        google = data.get("google_accounts", {})
        telegram = data.get("telegram", {})
        discord = data.get("discord", {})
        wallets = data.get("wallets", {})
        autofill = data.get("autofill", {})
        credit_cards = data.get("credit_cards", {})

        # Count unique browsers
        browsers = set()
        for b in cred.get("unique_browsers", []):
            browsers.add(normalize_browser(b))

        stats = Statistics(
            total_credentials=cred.get("total_entries", 0),
            total_passwords=cred.get("with_valid_credentials", 0),
            total_empty_entries=cred.get("empty_entries", 0),
            total_cookies=cookies.get("total_count", 0),
            total_history_urls=history.get("total_count", 0),
            total_google_tokens=google.get("total_count", 0),
            total_autofill_entries=autofill.get("total_count", 0),
            total_credit_cards=credit_cards.get("total_count", 0),
            total_wallets=wallets.get("total_wallets", 0),
            total_discord_tokens=len(discord.get("tokens", [])),
            total_telegram_sessions=len(telegram.get("user_hashes", [])),
            unique_browsers=len(browsers),
            unique_domains_in_credentials=cred.get("unique_domains", 0),
            has_real_credentials=cred.get("with_valid_credentials", 0) > 0,
            has_google_tokens=google.get("total_count", 0) > 0,
            has_telegram_access=bool(telegram.get("present")),
            has_discord_access=bool(discord.get("tokens")),
        )

        # Compute risk score (0-10)
        score = 0.0
        if stats.total_passwords > 0:
            score += min(3.0, stats.total_passwords * 0.1)
        if stats.total_google_tokens > 0:
            score += 2.0
        if stats.has_telegram_access:
            score += 1.5
        if stats.has_discord_access:
            score += 1.0
        if stats.total_wallets > 0:
            score += 1.0
        if stats.total_credit_cards > 0:
            score += 1.0
        if stats.total_cookies > 0:
            score += min(1.0, stats.total_cookies * 0.001)
        stats.risk_score = round(min(10.0, score), 1)

        return stats
