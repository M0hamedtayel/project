"""Main victim record model — unified output schema."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .browser import (
    AutofillEntry,
    Cookie,
    CookieBrowserSummary,
    GoogleAccountToken,
    HistoryBrowserSummary,
    HistoryEntry,
)
from .credential import BrowserSource, Credential
from .steam import SteamAccount, SteamToken
from .types_ import DiscordToken, Extension2FA, TelegramSession
from .statistics import Statistics


class VictimId(BaseModel):
    """Victim identifiers for cross-log correlation."""

    machine_id: str = Field(default="", description="Unique machine ID (UUID)")
    guid: str = Field(default="", description="Windows GUID")
    hwid: str = Field(default="", description="Hardware fingerprint")


class VictimIdentity(BaseModel):
    """Victim identity information."""

    username: str = Field(default="", description="Windows username")
    computer_name: str | None = Field(
        default=None,
        description="Computer name (null if hardcoded/fake)",
    )


class VictimNetwork(BaseModel):
    """Network and geolocation info."""

    ip: str = Field(default="", description="Exfiltrating IP address")
    country_code: str = Field(default="", description="2-letter ISO country code")
    country_name: str | None = Field(default=None, description="Full country name")
    city: str | None = Field(default=None)
    isp: str | None = Field(default=None)
    timezone: str | None = Field(default=None)


class VictimOS(BaseModel):
    """Operating system info."""

    name: str = Field(default="", description="Full OS name, e.g. Windows 11 Pro")
    edition: str = Field(default="", description="Edition, e.g. Pro, Home")
    version: str = Field(default="", description="Short version, e.g. 11, 10")
    build: str = Field(default="", description="Build number")
    display_resolution: str = Field(default="")


class VictimHardware(BaseModel):
    """Hardware fingerprint."""

    processor: str = Field(default="")
    cores: int = 0
    threads: int = 0
    ram_mb: int = 0
    video_card: str = Field(default="")


class Victim(BaseModel):
    """Complete victim profile."""

    id: VictimId = Field(default_factory=VictimId)
    identity: VictimIdentity = Field(default_factory=VictimIdentity)
    network: VictimNetwork = Field(default_factory=VictimNetwork)
    os: VictimOS = Field(default_factory=VictimOS)
    hardware: VictimHardware = Field(default_factory=VictimHardware)


class NotableSoftware(BaseModel):
    """A categorized software entry."""

    name: str
    category: str  # browser, gaming, office, security, ftp, vpn, communication, development, other


class NotableProcess(BaseModel):
    """A notable running process (non-system)."""

    name: str
    pid: int = 0


class CredentialData(BaseModel):
    """Credentials section with accounts and summaries."""

    total_entries: int = 0
    with_valid_credentials: int = 0
    empty_entries: int = 0
    unique_domains: int = 0
    browser_sources: list[BrowserSource] = Field(default_factory=list)
    accounts: list[Credential] = Field(default_factory=list)


class BrowserData(BaseModel):
    """Browser data section."""

    cookies: list[Cookie] = Field(default_factory=list)
    cookie_summaries: list[CookieBrowserSummary] = Field(default_factory=list)
    history: list[HistoryEntry] = Field(default_factory=list)
    history_summaries: list[HistoryBrowserSummary] = Field(default_factory=list)
    google_accounts: list[GoogleAccountToken] = Field(default_factory=list)
    autofill: list[AutofillEntry] = Field(default_factory=list)


class SteamData(BaseModel):
    """Steam application data."""

    present: bool = False
    accounts: list[SteamAccount] = Field(default_factory=list)
    tokens: list[SteamToken] = Field(default_factory=list)


class TelegramData(BaseModel):
    """Telegram session data."""

    present: bool = False
    sessions: list[TelegramSession] = Field(default_factory=list)


class DiscordData(BaseModel):
    """Discord token data."""

    present: bool = False
    tokens: list[DiscordToken] = Field(default_factory=list)


class FilesData(BaseModel):
    """Scraped files data."""

    scraped_count: int = 0
    screenshots_count: int = 0
    file_types: list[str] = Field(default_factory=list)


class Metadata(BaseModel):
    """Parse metadata."""

    stealer_family: str = "Vidar"
    parse_version: str = "1.0.0"
    parse_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_file: str = ""
    source_log_date: str = ""


class VictimRecord(BaseModel):
    """Complete parsed victim record — the unified output schema."""

    metadata: Metadata = Field(default_factory=Metadata)
    victim: Victim = Field(default_factory=Victim)
    credentials: CredentialData = Field(default_factory=CredentialData)
    browser_data: BrowserData = Field(default_factory=BrowserData)
    steam: SteamData = Field(default_factory=SteamData)
    telegram: TelegramData = Field(default_factory=TelegramData)
    discord: DiscordData = Field(default_factory=DiscordData)
    extensions: list[Extension2FA] = Field(default_factory=list)
    files: FilesData = Field(default_factory=FilesData)
    notable_software: list[NotableSoftware] = Field(default_factory=list)
    notable_processes: list[NotableProcess] = Field(default_factory=list)
    statistics: Statistics = Field(default_factory=Statistics)

    def to_jsonl_line(self) -> str:
        """Serialize to a single JSONL line (no trailing newline)."""
        return self.model_dump_json()
