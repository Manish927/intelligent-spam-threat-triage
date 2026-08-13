from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Optional, Set

from .models import SenderFeatures


FREE_EMAIL_PROVIDERS: Set[str] = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.in",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "zoho.com",
}


EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$",
    re.IGNORECASE,
)


def analyze_sender(
    sender: str | None,
) -> SenderFeatures:
    """
    Extract deterministic sender-related security evidence.

    This analyzer performs local parsing only.

    It does not:
        - perform DNS queries,
        - check SPF/DKIM/DMARC,
        - query reputation services,
        - infer maliciousness,
        - assign a risk score.
    """

    sender_address = extract_sender_address(
        sender
    )

    sender_domain = extract_sender_domain(
        sender_address
    )

    return SenderFeatures(
        sender_present=bool(sender_address),

        sender_address=sender_address,

        sender_domain=sender_domain,

        sender_domain_has_digits=(
            domain_has_digits(sender_domain)
        ),

        sender_domain_has_hyphen=(
            domain_has_hyphen(sender_domain)
        ),

        free_email_provider=(
            is_free_email_provider(
                sender_domain
            )
        ),

        possible_display_name_mismatch=(
            detect_display_name_mismatch(
                sender
            )
        ),
    )


def extract_sender_address(
    sender: str | None,
) -> Optional[str]:
    """
    Extract and normalize the sender email address.

    Examples:

        "Alice <alice@example.com>"
            -> alice@example.com

        "alice@example.com"
            -> alice@example.com

        None
            -> None
    """

    if not sender:
        return None

    _, address = parseaddr(
        sender.strip()
    )

    address = address.strip().lower()

    if not address:
        return None

    if not EMAIL_PATTERN.match(address):
        return None

    return address


def extract_sender_domain(
    sender_address: str | None,
) -> Optional[str]:
    """
    Extract the normalized domain from a sender address.
    """

    if not sender_address:
        return None

    if "@" not in sender_address:
        return None

    _, domain = sender_address.rsplit(
        "@",
        1,
    )

    domain = domain.strip().lower().rstrip(".")

    return domain or None


def domain_has_digits(
    domain: str | None,
) -> bool:
    """
    Return True when the sender domain contains a digit.
    """

    if not domain:
        return False

    return any(
        character.isdigit()
        for character in domain
    )


def domain_has_hyphen(
    domain: str | None,
) -> bool:
    """
    Return True when the sender domain contains a hyphen.
    """

    if not domain:
        return False

    return "-" in domain


def is_free_email_provider(
    domain: str | None,
) -> bool:
    """
    Return True when the sender domain belongs to a configured
    consumer/free-email provider.

    This is evidence only.

    A free email provider is not inherently suspicious.
    """

    if not domain:
        return False

    normalized_domain = domain.lower()

    return (
        normalized_domain
        in FREE_EMAIL_PROVIDERS
    )


def extract_display_name(
    sender: str | None,
) -> Optional[str]:
    """
    Extract the display-name component from a sender string.

    Example:

        "PayPal Security <support@example.com>"
            -> "PayPal Security"
    """

    if not sender:
        return None

    display_name, _ = parseaddr(
        sender.strip()
    )

    display_name = display_name.strip()

    return (
        display_name
        if display_name
        else None
    )


def detect_display_name_mismatch(
    sender: str | None,
) -> bool:
    """
    Detect a weak display-name/domain inconsistency heuristic.

    Example:

        "Gmail Security <alert@random-domain.example>"

    may be flagged because the display name references a known
    provider/brand token that is not represented in the sender domain.

    This is intentionally conservative and should not be interpreted
    as proof of impersonation.
    """

    if not sender:
        return False

    display_name = extract_display_name(
        sender
    )

    sender_address = extract_sender_address(
        sender
    )

    sender_domain = extract_sender_domain(
        sender_address
    )

    if not display_name or not sender_domain:
        return False

    display_tokens = _normalize_tokens(
        display_name
    )

    domain_tokens = _normalize_tokens(
        sender_domain
    )

    known_identity_tokens = {
        "google",
        "gmail",
        "microsoft",
        "outlook",
        "paypal",
        "apple",
        "amazon",
        "yahoo",
        "icloud",
        "facebook",
        "meta",
        "linkedin",
        "dropbox",
        "docusign",
    }

    claimed_tokens = (
        display_tokens
        & known_identity_tokens
    )

    if not claimed_tokens:
        return False

    return not bool(
        claimed_tokens
        & domain_tokens
    )


def _normalize_tokens(
    value: str,
) -> Set[str]:
    """
    Normalize a string into lowercase alphanumeric tokens.
    """

    return {
        token
        for token in re.split(
            r"[^a-z0-9]+",
            value.lower(),
        )
        if token
    }