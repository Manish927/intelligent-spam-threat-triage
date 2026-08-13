from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class URLFeatures:
    """
    Deterministic URL-related security evidence extracted from an email.

    These fields describe observable characteristics only.
    They do not assign a risk score or make a triage decision.
    """

    has_url: bool
    url_count: int

    uses_ip_address_url: bool
    uses_url_shortener: bool
    suspicious_tld: bool
    punycode_domain: bool
    excessive_subdomains: bool
    domain_contains_digits: bool
    domain_contains_hyphen: bool
    credential_path_keyword: bool

    extracted_urls: List[str] = field(default_factory=list)

    matched_credential_terms: List[str] = field(
        default_factory=list
    )


@dataclass(frozen=True)
class SenderFeatures:
    """
    Deterministic sender-related security evidence.
    """

    sender_present: bool

    sender_address: Optional[str]
    sender_domain: Optional[str]

    sender_domain_has_digits: bool
    sender_domain_has_hyphen: bool

    free_email_provider: bool = False
    possible_display_name_mismatch: bool = False


@dataclass(frozen=True)
class LanguageFeatures:
    """
    Deterministic linguistic and social-engineering evidence.
    """

    urgency_language: bool
    credential_request: bool
    financial_request: bool
    verification_request: bool
    account_suspension_language: bool
    password_reset_language: bool

    matched_urgency_terms: List[str] = field(
        default_factory=list
    )

    matched_credential_terms: List[str] = field(
        default_factory=list
    )

    matched_financial_terms: List[str] = field(
        default_factory=list
    )

    matched_verification_terms: List[str] = field(
        default_factory=list
    )

    matched_suspension_terms: List[str] = field(
        default_factory=list
    )

    matched_password_terms: List[str] = field(
        default_factory=list
    )


@dataclass(frozen=True)
class SecurityFeatures:
    """
    Complete deterministic security-evidence bundle for one email.

    This object is intended to become an input to:

        - risk scoring
        - Agentic AI reasoning
        - explainability
        - human-in-the-loop review

    It intentionally contains evidence rather than final security decisions.
    """

    message_id: str

    url: URLFeatures
    sender: SenderFeatures
    language: LanguageFeatures