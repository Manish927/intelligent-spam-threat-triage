from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from threat_triage.security.language_analyzer import (
    analyze_language,
)


@dataclass(frozen=True)
class LanguageToolResult:
    """
    Structured result returned by the agent-facing language inspection tool.

    The result contains deterministic social-engineering evidence only.

    It does not:
        - classify the message as malicious or benign,
        - assign a risk score,
        - make a routing decision,
        - invoke an LLM.
    """

    subject: Optional[str]
    body_preview: Optional[str]

    signal_count: int

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

    evidence: List[str] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        if self.signal_count < 0:
            raise ValueError(
                "signal_count must not be negative"
            )


def inspect_language_evidence(
    *,
    subject: Optional[str],
    body: Optional[str],
) -> LanguageToolResult:
    """
    Inspect message subject/body using the platform's deterministic
    language analyzer.

    This function is suitable for future Google ADK / Gemini
    function calling.

    Parameters
    ----------
    subject:
        Email subject supplied as untrusted message evidence.

    body:
        Email body or bounded body preview supplied as untrusted
        message evidence.

    Returns
    -------
    LanguageToolResult
        Structured linguistic/social-engineering evidence.
    """

    normalized_subject = _normalize_text(
        subject,
        max_length=1000,
    )

    normalized_body = _normalize_text(
        body,
        max_length=8000,
    )

    features = analyze_language(
        subject=normalized_subject,
        body=normalized_body,
    )

    evidence = _build_evidence(
        urgency_language=(
            features.urgency_language
        ),
        credential_request=(
            features.credential_request
        ),
        financial_request=(
            features.financial_request
        ),
        verification_request=(
            features.verification_request
        ),
        account_suspension_language=(
            features.account_suspension_language
        ),
        password_reset_language=(
            features.password_reset_language
        ),
    )

    return LanguageToolResult(
        subject=normalized_subject,
        body_preview=normalized_body,

        signal_count=len(
            evidence
        ),

        urgency_language=(
            features.urgency_language
        ),

        credential_request=(
            features.credential_request
        ),

        financial_request=(
            features.financial_request
        ),

        verification_request=(
            features.verification_request
        ),

        account_suspension_language=(
            features.account_suspension_language
        ),

        password_reset_language=(
            features.password_reset_language
        ),

        matched_urgency_terms=list(
            features.matched_urgency_terms
        ),

        matched_credential_terms=list(
            features.matched_credential_terms
        ),

        matched_financial_terms=list(
            features.matched_financial_terms
        ),

        matched_verification_terms=list(
            features.matched_verification_terms
        ),

        matched_suspension_terms=list(
            features.matched_suspension_terms
        ),

        matched_password_terms=list(
            features.matched_password_terms
        ),

        evidence=evidence,
    )


def inspect_language_evidence_dict(
    *,
    subject: Optional[str],
    body: Optional[str],
) -> Dict[str, object]:
    """
    JSON-friendly wrapper around inspect_language_evidence().
    """

    result = inspect_language_evidence(
        subject=subject,
        body=body,
    )

    return asdict(
        result
    )


def _normalize_text(
    value: Optional[str],
    *,
    max_length: int,
) -> Optional[str]:
    """
    Normalize bounded untrusted message text.

    This is context preparation only.

    Content that resembles instructions is preserved as message data
    and must not be treated as control instructions by the future agent.
    """

    if value is None:
        return None

    normalized = (
        str(value)
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\x00", "")
        .strip()
    )

    if not normalized:
        return None

    if len(normalized) > max_length:
        normalized = normalized[
            :max_length
        ]

    return normalized


def _build_evidence(
    *,
    urgency_language: bool,
    credential_request: bool,
    financial_request: bool,
    verification_request: bool,
    account_suspension_language: bool,
    password_reset_language: bool,
) -> List[str]:
    """
    Convert language feature flags into stable human-readable evidence.

    These are observations, not a final threat verdict.
    """

    evidence: List[str] = []

    if urgency_language:
        evidence.append(
            "Urgency language detected"
        )

    if credential_request:
        evidence.append(
            "Credential-related language detected"
        )

    if financial_request:
        evidence.append(
            "Financial-request language detected"
        )

    if verification_request:
        evidence.append(
            "Verification language detected"
        )

    if account_suspension_language:
        evidence.append(
            "Account-suspension language detected"
        )

    if password_reset_language:
        evidence.append(
            "Password-reset language detected"
        )

    return evidence