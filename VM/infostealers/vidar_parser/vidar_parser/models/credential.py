"""Credential and browser login data models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Credential(BaseModel):
    """A single browser credential entry."""

    browser: str = Field(description="Browser name, e.g. 'Google Chrome'")
    profile: str = Field(description="Browser profile, e.g. 'Default', 'Profile 3'")
    url: str = Field(description="The URL/Host associated with the credential")
    login: str = Field(default="", description="Saved username/email/phone")
    password: str = Field(default="", description="Saved password")
    credential_type: str = Field(
        default="website",
        description="Type: website, android_app, router",
    )


class BrowserSource(BaseModel):
    """Summary of credentials from a single browser profile."""

    browser: str
    profile: str
    credential_count: int = 0
