from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List, Optional

from threat_triage.security.sender_analyzer import (
    analyze_sender,
    extract_display_name,
)


@dataclass(frozen=True)
class SenderToolResult:
    """
    Structured result returned by the agent-facing sender inspection tool.

    The result contains deterministic sender evidence only.

    It does not:
        - perform DNS lookups,
        - query WHOIS,
        - query sender/domain reputation services,
        - validate SPF/DKIM/DMARC,
        - classify the sender as malicious or benign.
    """

    sender_input: str

    sender_present: bool

    display_name: Optional[str]

    sender_address: Optional[str]

    sender_domain: Optional[str]

    sender_domain_has_digits: bool

    sender_domain_has_hyphen: bool

    free_email_provider: bool

    possible_display_name_mismatch: bool

    signal_count: int

    evidence: List[str] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        if not self.sender_input:
            raise ValueError(
                "sender_input must not be empty"
            )

        if self.signal_count < 0:
            raise ValueError(
                "signal_count must not be negative"
            )


def inspect_sender_evidence(
    sender: str,
) -> SenderToolResult:
    """
    Inspect one sender value using the platform's deterministic
    sender analyzer.

    This function is suitable for future Google ADK / Gemini
    function calling.

    Parameters
    ----------
    sender:
        RFC-style sender value or plain email address supplied
        as untrusted message evidence.

    Returns
    -------
    SenderToolResult
        Structured deterministic evidence about the sender.

    Security
    --------
    The sender/domain is never dereferenced or queried externally.

    This tool performs local parsing and lexical inspection only.
    """

    normalized_sender = _normalize_sender_input(
        sender
    )

    features = analyze_sender(
        sender=normalized_sender
    )

    display_name = extract_display_name(
        normalized_sender
    )

    evidence = _build_evidence(
        sender_present=(
            features.sender_present
        ),
        sender_domain_has_digits=(
            features.sender_domain_has_digits
        ),
        sender_domain_has_hyphen=(
            features.sender_domain_has_hyphen
        ),
        free_email_provider=(
            features.free_email_provider
        ),
        possible_display_name_mismatch=(
            features.possible_display_name_mismatch
        ),
    )

    return SenderToolResult(
        sender_input=normalized_sender,

        sender_present=(
            features.sender_present
        ),

        display_name=display_name,

        sender_address=(
            features.sender_address
        ),

        sender_domain=(
            features.sender_domain
        ),

        sender_domain_has_digits=(
            features.sender_domain_has_digits
        ),

        sender_domain_has_hyphen=(
            features.sender_domain_has_hyphen
        ),

        free_email_provider=(
            features.free_email_provider
        ),

        possible_display_name_mismatch=(
            features.possible_display_name_mismatch
        ),

        signal_count=len(
            evidence
        ),

        evidence=evidence,
    )


def inspect_sender_evidence_dict(
    sender: str,
) -> dict:
    """
    JSON-friendly wrapper around inspect_sender_evidence().

    This wrapper is intended for agent/function-calling integrations
    where plain dictionaries are easier to serialize than dataclasses.
    """

    result = inspect_sender_evidence(
        sender
    )

    return asdict(
        result
    )


def _normalize_sender_input(
    sender: str,
) -> str:
    """
    Normalize agent-supplied sender input.

    The value remains untrusted message evidence.
    """

    if sender is None:
        raise ValueError(
            "sender must not be None"
        )

    normalized = str(
        sender
    ).strip()

    if not normalized:
        raise ValueError(
            "sender must not be empty"
        )

    if len(normalized) > 2048:
        raise ValueError(
            "sender exceeds maximum supported length"
        )

    normalized = (
        normalized
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\x00", "")
        .strip()
    )

    if not normalized:
        raise ValueError(
            "sender must not be empty"
        )

    return normalized


def _build_evidence(
    *,
    sender_present: bool,
    sender_domain_has_digits: bool,
    sender_domain_has_hyphen: bool,
    free_email_provider: bool,
    possible_display_name_mismatch: bool,
) -> List[str]:
    """
    Convert sender feature flags into stable human-readable evidence.

    These are observations, not a security verdict.
    """

    evidence: List[str] = []

    if not sender_present:
        evidence.append(
            "Sender address could not be parsed"
        )

    if sender_domain_has_digits:
        evidence.append(
            "Sender domain contains digits"
        )

    if sender_domain_has_hyphen:
        evidence.append(
            "Sender domain contains hyphens"
        )

    if free_email_provider:
        evidence.append(
            "Sender uses a configured free-email provider"
        )

    if possible_display_name_mismatch:
        evidence.append(
            "Sender display name may conflict with sender domain"
        )

    return evidence