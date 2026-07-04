"""Main victim record model — unified output schema."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .browser import (
    AutofillEntry,
    Cookie,
    CookieBrowserSummary,
    GoogleAccountToken,
)
from .credential import Credential
from .statistics import Statistics
from .types_ import CreditCardEntry


class VictimId(BaseModel):
    """Victim identifiers for cross-log correlation."""

    machine_id: str = Field(default="", description="Unique machine ID (UUID)")
    guid: str = Field(default="", description="Windows GUID")
    hwid: str = Field(default="", description="Hardware fingerprint")


class VictimIdentity(BaseModel):
    """Victim identity information."""

    username: str = Field(default="", description="Windows username")
    computer_name: str = Field(default="", description="Computer name")


class VictimNetwork(BaseModel):
    """Network and geolocation info."""

    ip: str = Field(default="", description="Exfiltrating IP address")
    country_code: str = Field(default="", description="2-letter ISO country code")
    country_name: str | None = Field(default=None, description="Full country name")


class VictimOS(BaseModel):
    """Operating system info."""

    version: str = Field(default="", description="Full OS version string")
    time_zone: str = Field(default="", description="OS time zone")
    local_date: str = Field(default="", description="Local date when log was generated")
    install_date: str = Field(default="", description="Windows install date")
    language: str = Field(default="", description="OS language code")
    hostname: str = Field(default="", description="Hostname")


class VictimHardwareInfo(BaseModel):
    """A single hardware component entry."""

    manufacturer: str = Field(default="", description="Manufacturer name")
    product: str = Field(default="", description="Product name")
    size: str = Field(default="", description="Size/spec (e.g. '8192MB')")
    core_count: int = 0
    core_enabled: int = 0
    thread_count: int = 0


class VictimHardware(BaseModel):
    """Hardware fingerprint."""

    motherboard: VictimHardwareInfo = Field(default_factory=VictimHardwareInfo)
    cpu: VictimHardwareInfo = Field(default_factory=VictimHardwareInfo)
    ram: list[VictimHardwareInfo] = Field(default_factory=list)
    gpu: list[VictimHardwareInfo] = Field(default_factory=list)
    display: str = Field(default="", description="Display resolution")


class VictimAntivirus(BaseModel):
    """An antivirus entry."""

    name: str = Field(default="", description="AV product name")
    state: str = Field(default="", description="Active/inactive status")


class Victim(BaseModel):
    """Complete victim profile."""

    id: VictimId = Field(default_factory=VictimId)
    identity: VictimIdentity = Field(default_factory=VictimIdentity)
    network: VictimNetwork = Field(default_factory=VictimNetwork)
    os: VictimOS = Field(default_factory=VictimOS)
    hardware: VictimHardware = Field(default_factory=VictimHardware)
    anti_virus: list[VictimAntivirus] = Field(default_factory=list)


class CredentialData(BaseModel):
    """Credentials section with accounts and summaries."""

    total_entries: int = 0
    with_valid_credentials: int = 0
    empty_entries: int = 0
    unique_domains: int = 0
    accounts: list[Credential] = Field(default_factory=list)


class BrowserData(BaseModel):
    """Browser data section."""

    cookies: list[Cookie] = Field(default_factory=list)
    cookie_summaries: list[CookieBrowserSummary] = Field(default_factory=list)
    google_accounts: list[GoogleAccountToken] = Field(default_factory=list)
    autofill: list[AutofillEntry] = Field(default_factory=list)
    credit_cards: list[CreditCardEntry] = Field(default_factory=list)


class FilesData(BaseModel):
    """Scraped files data."""

    scraped_count: int = 0
    file_paths: list[str] = Field(default_factory=list)


class Metadata(BaseModel):
    """Parse metadata."""

    stealer_family: str = "Lumma"
    parse_version: str = "1.0.0"
    parse_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source_file: str = ""
    source_log_date: str = ""
    build_date: str = ""
    build_tag: str = ""


class VictimRecord(BaseModel):
    """Complete parsed victim record — the unified output schema."""

    metadata: Metadata = Field(default_factory=Metadata)
    victim: Victim = Field(default_factory=Victim)
    credentials: CredentialData = Field(default_factory=CredentialData)
    browser_data: BrowserData = Field(default_factory=BrowserData)
    files: FilesData = Field(default_factory=FilesData)
    statistics: Statistics = Field(default_factory=Statistics)

    def to_jsonl_line(self) -> str:
        """Serialize to a single JSONL line (no trailing newline)."""
        return self.model_dump_json()
