"""All data models for the Remus parser."""

from .credential import Credential
from .browser import (
    Cookie,
    CookieBrowserSummary,
    HistoryEntry,
    HistoryBrowserSummary,
    GoogleAccountToken,
    AutofillEntry,
)
from .types_ import CreditCardEntry, DiscordToken, TelegramSession, WalletEntry
from .statistics import Statistics
from .victim import (
    VictimRecord,
    Victim,
    VictimId,
    VictimIdentity,
    VictimNetwork,
    VictimOS,
    VictimHardware,
    VictimAntivirus,
    VictimHardwareInfo,
    CredentialData,
    BrowserData,
    TelegramData,
    DiscordData,
    FilesData,
    WalletData,
    Metadata,
)

__all__ = [
    "VictimRecord",
    "Victim",
    "VictimId",
    "VictimIdentity",
    "VictimNetwork",
    "VictimOS",
    "VictimHardware",
    "VictimAntivirus",
    "VictimHardwareInfo",
    "CredentialData",
    "BrowserData",
    "TelegramData",
    "DiscordData",
    "FilesData",
    "WalletData",
    "Metadata",
    "Statistics",
    # Credential models
    "Credential",
    # Browser models
    "Cookie",
    "CookieBrowserSummary",
    "HistoryEntry",
    "HistoryBrowserSummary",
    "GoogleAccountToken",
    "AutofillEntry",
    # Session models
    "DiscordToken",
    "TelegramSession",
    "WalletEntry",
    # Credit card models
    "CreditCardEntry",
    # Metadata & stats
    "Metadata",
    "Statistics",
]
