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
    date: str = Field(default="", description="Date when credential was saved")
