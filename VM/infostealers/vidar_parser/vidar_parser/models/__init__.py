"""All data models for the Vidar parser."""

from .credential import Credential, BrowserSource
from .browser import (
    Cookie,
    CookieBrowserSummary,
    HistoryEntry,
    HistoryBrowserSummary,
    GoogleAccountToken,
    AutofillEntry,
)
from .steam import SteamAccount, SteamLibraryFolder, SteamToken
from .types_ import DiscordToken, Extension2FA, TelegramSession
from .statistics import Statistics
from .victim import (
    VictimRecord,
    Victim,
    VictimId,
    VictimIdentity,
    VictimNetwork,
    VictimOS,
    VictimHardware,
    NotableSoftware,
    NotableProcess,
    CredentialData,
    BrowserData,
    SteamData,
    TelegramData,
    DiscordData,
    FilesData,
    Metadata,
)

__all__ = [
    # Core model
    "VictimRecord",
    # Victim sub-models
    "Victim",
    "VictimId",
    "VictimIdentity",
    "VictimNetwork",
    "VictimOS",
    "VictimHardware",
    # Data section models
    "CredentialData",
    "BrowserData",
    "SteamData",
    "TelegramData",
    "DiscordData",
    "FilesData",
    # Credential models
    "Credential",
    "BrowserSource",
    # Browser models
    "Cookie",
    "CookieBrowserSummary",
    "HistoryEntry",
    "HistoryBrowserSummary",
    "GoogleAccountToken",
    "AutofillEntry",
    # Steam models
    "SteamAccount",
    "SteamLibraryFolder",
    "SteamToken",
    # Session models
    "DiscordToken",
    "Extension2FA",
    "TelegramSession",
    # Metadata & stats
    "Metadata",
    "Statistics",
    # Utility models
    "NotableSoftware",
    "NotableProcess",
]
