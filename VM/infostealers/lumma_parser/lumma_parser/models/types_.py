"""Types and supplementary models for the Lumma parser."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CreditCardEntry(BaseModel):
    """A credit card entry extracted from browser credit card stores."""

    card_number: str = Field(
        description="Full card number",
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
