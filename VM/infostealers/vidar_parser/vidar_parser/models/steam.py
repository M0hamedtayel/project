"""Steam account data models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SteamLibraryFolder(BaseModel):
    """A Steam library folder."""

    path: str
    total_size_gb: float = 0.0
    installed_games_count: int = 0


class SteamAccount(BaseModel):
    """A Steam account with login info and library."""

    account_name: str = Field(description="Steam account username")
    persona_name: str = Field(description="Steam display name")
    steam_id: str = Field(description="Steam64 ID, e.g. 76561199220173435")
    remember_password: bool = False
    library_folders: list[SteamLibraryFolder] = Field(default_factory=list)
    installed_games_count: int = 0
    has_token: bool = False


class SteamToken(BaseModel):
    """A Steam authentication token."""

    account_name: str
    steam_id: str
    persona_name: str
    token: str = Field(description="Steam JWT token")
