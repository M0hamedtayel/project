"""Lumma stealer-specific parser — orchestrates all per-file-type parsers."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from lumma_parser.models import (
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
    FilesData,
    Credential,
    Cookie,
    CookieBrowserSummary,
    AutofillEntry,
    GoogleAccountToken,
    CreditCardEntry,
)
from lumma_parser.normalizers.country import normalize_country
from lumma_parser.normalizers.timestamp import normalize_timestamp
from lumma_parser.normalizers.browser import normalize_browser

from .information import InformationParser
from .credentials import CredentialsParser
from .cookies import CookiesParser
from .google_accounts import GoogleAccountsParser
from .autofill import AutofillParser
from .credit_cards import CreditCardsParser


class LummaParser:
    """Orchestrates parsing of a single Lumma log directory.

    Collects data from all per-file-type parsers and assembles
    a unified VictimRecord compatible with the existing MongoDB schema.
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

        # Assemble files
        record.files = self._build_files(data)

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
            data["autofill"] = AutofillParser(self.log_dir).parse()
        except Exception as e:
            data["autofill"] = {}
            data["_autofill_error"] = str(e)

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

        # Parse hardware info from raw fields
        cpu_info = self._parse_cpu(info)
        gpu_list = self._parse_gpu(info)
        ram_info = self._parse_ram(info)
        display = info.get("display", "")

        # Parse antivirus
        av_name = info.get("antivirus", "")
        antivirus = []
        if av_name and av_name.lower() not in ("none", "not detected", ""):
            antivirus = [
                VictimAntivirus(name=av_name, state="Active")
            ]

        return Victim(
            id=VictimId(
                machine_id="",
                guid="",
                hwid=info.get("hwid", ""),
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
            hardware=VictimHardware(
                cpu=cpu_info,
                gpu=gpu_list,
                ram=ram_info,
                display=display,
            ),
            anti_virus=antivirus,
        )

    def _parse_cpu(self, info: dict[str, Any]) -> VictimHardwareInfo:
        """Parse CPU information from raw fields."""
        processor = info.get("processor", "")
        threads = info.get("processor_threads", "")
        cores = info.get("processor_cores", "")

        thread_count = 0
        core_count = 0
        try:
            thread_count = int(threads) if threads else 0
        except (ValueError, TypeError):
            pass
        try:
            core_count = int(cores) if cores else 0
        except (ValueError, TypeError):
            pass

        return VictimHardwareInfo(
            manufacturer="",
            product=processor,
            size="",
            core_count=core_count,
            core_enabled=core_count,
            thread_count=thread_count,
        )

    def _parse_gpu(self, info: dict[str, Any]) -> list[VictimHardwareInfo]:
        """Parse GPU information from raw fields."""
        gpu = info.get("gpu", "")
        if not gpu:
            return []
        return [VictimHardwareInfo(product=gpu)]

    def _parse_ram(self, info: dict[str, Any]) -> list[VictimHardwareInfo]:
        """Parse RAM information from raw fields."""
        ram = info.get("ram", "")
        if not ram:
            return []
        return [VictimHardwareInfo(product="RAM", size=ram)]

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
        google_data = data.get("google_accounts", {})
        autofill_data = data.get("autofill", {})
        credit_cards_data = data.get("credit_cards", {})

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

        credit_cards = [
            CreditCardEntry(
                card_number=e.get("card_number", ""),
                cardholder_name=e.get("cardholder_name", ""),
                expiry_date=e.get("expiry_date", ""),
                cvc=e.get("cvc", ""),
                browser=e.get("browser", ""),
                profile=e.get("profile", ""),
            )
            for e in credit_cards_data.get("credit_cards", [])
        ]

        return BrowserData(
            cookies=cookies,
            cookie_summaries=cookie_summaries,
            google_accounts=google_tokens,
            autofill=autofill_entries,
            credit_cards=credit_cards,
        )

    def _build_files(self, data: dict[str, Any]) -> FilesData:
        """Build the files section.

        Lumma does not have a dedicated Important/ scraped files directory
        in this dataset. Return empty files data.
        """
        return FilesData(
            scraped_count=0,
            file_paths=[],
        )

    def _compute_statistics(self, data: dict[str, Any]) -> Statistics:
        """Compute statistics and risk score."""
        cred = data.get("credentials", {})
        cookies = data.get("cookies", {})
        google = data.get("google_accounts", {})
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
            total_autofill_entries=autofill.get("total_count", 0),
            total_google_tokens=google.get("total_count", 0),
            total_credit_cards=credit_cards.get("total_count", 0),
            unique_browsers=len(browsers),
            unique_domains_in_credentials=cred.get("unique_domains", 0),
            has_real_credentials=cred.get("with_valid_credentials", 0) > 0,
            has_google_tokens=google.get("total_count", 0) > 0,
            has_credit_cards=credit_cards.get("total_count", 0) > 0,
        )

        # Compute risk score (0-10)
        score = 0.0
        if stats.total_passwords > 0:
            score += min(3.0, stats.total_passwords * 0.1)
        if stats.total_google_tokens > 0:
            score += 2.0
        if stats.total_credit_cards > 0:
            score += 1.0
        if stats.total_cookies > 0:
            score += min(1.0, stats.total_cookies * 0.001)
        if stats.total_autofill_entries > 0:
            score += min(0.5, stats.total_autofill_entries * 0.01)
        stats.risk_score = round(min(10.0, score), 1)

        return stats
