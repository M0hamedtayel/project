"""Browser data models (cookies, history, Google accounts, autofill)."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class Cookie(BaseModel):
    """A single Netscape-format cookie entry."""

    browser: str = Field(description="Browser name")
    profile: str = Field(description="Browser profile")
    domain: str = Field(description="Cookie domain, e.g. '.google.com'")
    name: str = Field(description="Cookie name")
    value: str = Field(description="Cookie value")
    path: str = Field(default="/")
    expiry_epoch: int | None = Field(default=None, description="Unix timestamp expiry")
    secure: bool = Field(default=False)


class CookieBrowserSummary(BaseModel):
    """Per-browser cookie summary."""

    browser: str
    profile: str
    count: int = 0
    top_domains: list[str] = Field(default_factory=list)


class HistoryEntry(BaseModel):
    """A single browser history URL entry."""

    browser: str
    profile: str
    url: str = Field(description="Visited URL")
    title: str = Field(default="", description="Page title")
    timestamp: str = Field(default="", description="Visit timestamp")


class HistoryBrowserSummary(BaseModel):
    """Per-browser history summary."""

    browser: str
    profile: str
    url_count: int = 0


class GoogleAccountToken(BaseModel):
    """A Google OAuth access token."""

    browser: str
    profile: str
    token: str = Field(description="Google OAuth access token string")


class AutofillEntry(BaseModel):
    """Browser autofill / search query entry."""

    browser: str
    profile: str
    name: str = Field(default="", description="Field name")
    value: str = Field(description="Field value")
