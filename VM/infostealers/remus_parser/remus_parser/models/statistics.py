"""Statistics model for each parsed victim."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Statistics(BaseModel):
    """Computed statistics for a parsed victim log."""

    # Credentials
    total_credentials: int = 0
    total_passwords: int = 0
    total_empty_entries: int = 0
    # Browser data
    total_cookies: int = 0
    total_history_urls: int = 0
    total_google_tokens: int = 0
    total_autofill_entries: int = 0
    total_credit_cards: int = 0
    # Sessions
    total_wallets: int = 0
    total_discord_tokens: int = 0
    total_telegram_sessions: int = 0
    # Context
    unique_browsers: int = 0
    unique_domains_in_credentials: int = 0
    # Flags
    has_real_credentials: bool = False
    has_google_tokens: bool = False
    has_telegram_access: bool = False
    has_discord_access: bool = False
    # Risk scoring
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Composite risk score 0-10",
    )
