"""Application session and wallet models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TelegramSession(BaseModel):
    """Telegram session data (presence detection only — files are encrypted)."""

    user_hash: str = Field(description="Telegram user hash identifier")
    session_files: list[str] = Field(
        default_factory=list,
        description="List of session file names found",
    )
    decrypted: bool = False


class DiscordToken(BaseModel):
    """A Discord authentication token."""

    token: str = Field(description="Discord auth token")
    email: str = ""
    username: str = ""


class WalletEntry(BaseModel):
    """A cryptocurrency wallet entry."""

    wallet_name: str = Field(description="Wallet name, e.g. 'MetaMask', 'Phantom'")
    browser: str = Field(description="Browser hosting the wallet extension")
    profile: str = Field(description="Browser profile")
    files: list[str] = Field(default_factory=list, description="Wallet file paths found")


class CreditCardEntry(BaseModel):
    """A credit card entry extracted from browser autofill / credit card stores."""

    card_number: str = Field(
        description="Masked or full card number",
    )
    cardholder_name: str = Field(
        description="Name printed on the card",
    )
    expiry_date: str = Field(
        description="Card expiry date as stored (e.g. '5/2030', '12/2027')",
    )
    cvc: str = Field(
        description="Card verification code",
    )
    browser: str = Field(
        description="Browser that stored the card",
    )
    profile: str = Field(
        description="Browser profile where the card was stored",
    )
