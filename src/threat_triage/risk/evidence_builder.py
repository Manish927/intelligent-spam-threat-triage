from __future__ import annotations

from typing import Iterable, List, Set

from threat_triage.risk.models import (
    EvidenceProvenance,
    EvidenceSummary,
    MLEvidence,
    RiskEvidence,
)
from threat_triage.security.models import SecurityFeatures


DEFAULT_MODEL_VERSION = "0.1.0"
DEFAULT_FEATURE_VERSION = "0.1.0"


STRONG_URL_SIGNALS: Set[str] = {
    "url_ip_address",
    "url_suspicious_tld",
    "url_punycode",
    "url_credential_path",
}

STRONG_SENDER_SIGNALS: Set[str] = {
    "sender_display_mismatch",
}

STRONG_LANGUAGE_SIGNALS: Set[str] = {
    "lang_urgency",
    "lang_financial",
    "lang_suspension",
}


def build_risk_evidence(
    *,
    message_id: str,
    ml_evidence: MLEvidence,
    security_features: SecurityFeatures,
    feature_version: str = DEFAULT_FEATURE_VERSION,
) -> RiskEvidence:
    """
    Build the complete RiskEvidence contract for one email.

    This function combines:
        - ML evidence
        - deterministic security evidence
        - compact evidence summary
        - provenance metadata

    It intentionally does not:
        - calculate a risk score,
        - assign severity,
        - make a routing decision,
        - call an LLM,
        - perform threat-intelligence lookups.
    """

    if not message_id:
        raise ValueError(
            "message_id must not be empty"
        )

    if security_features.message_id != message_id:
        raise ValueError(
            "message_id must match SecurityFeatures message_id"
        )

    summary = build_evidence_summary(
        security_features
    )

    provenance = EvidenceProvenance(
        model_version=ml_evidence.model_version,
        feature_version=feature_version,
    )

    return RiskEvidence(
        message_id=message_id,
        ml=ml_evidence,
        security=security_features,
        summary=summary,
        provenance=provenance,
    )


def build_evidence_summary(
    security_features: SecurityFeatures,
) -> EvidenceSummary:
    """
    Summarize deterministic security evidence into counts,
    evidence categories, and strong-signal labels.
    """

    url_signals = _collect_url_signals(
        security_features
    )

    sender_signals = _collect_sender_signals(
        security_features
    )

    language_signals = _collect_language_signals(
        security_features
    )

    evidence_categories: List[str] = []

    if url_signals:
        evidence_categories.append("URL")

    if sender_signals:
        evidence_categories.append("SENDER")

    if language_signals:
        evidence_categories.append("LANGUAGE")

    strong_signals = sorted(
        set(url_signals) & STRONG_URL_SIGNALS
        |
        set(sender_signals) & STRONG_SENDER_SIGNALS
        |
        set(language_signals) & STRONG_LANGUAGE_SIGNALS
    )

    return EvidenceSummary(
        total_signal_count=(
            len(url_signals)
            + len(sender_signals)
            + len(language_signals)
        ),
        url_signal_count=len(url_signals),
        sender_signal_count=len(sender_signals),
        language_signal_count=len(language_signals),
        evidence_categories=evidence_categories,
        strong_signals=strong_signals,
    )


def _collect_url_signals(
    security_features: SecurityFeatures,
) -> List[str]:
    """
    Convert URL feature booleans into stable signal names.
    """

    url = security_features.url

    signals: List[str] = []

    if url.uses_ip_address_url:
        signals.append("url_ip_address")

    if url.uses_url_shortener:
        signals.append("url_shortener")

    if url.suspicious_tld:
        signals.append("url_suspicious_tld")

    if url.punycode_domain:
        signals.append("url_punycode")

    if url.excessive_subdomains:
        signals.append("url_excessive_subdomains")

    if url.domain_contains_digits:
        signals.append("url_domain_digits")

    if url.domain_contains_hyphen:
        signals.append("url_domain_hyphen")

    if url.credential_path_keyword:
        signals.append("url_credential_path")

    return signals


def _collect_sender_signals(
    security_features: SecurityFeatures,
) -> List[str]:
    """
    Convert sender feature booleans into stable signal names.
    """

    sender = security_features.sender

    signals: List[str] = []

    if sender.sender_domain_has_digits:
        signals.append(
            "sender_domain_digits"
        )

    if sender.sender_domain_has_hyphen:
        signals.append(
            "sender_domain_hyphen"
        )

    if sender.free_email_provider:
        signals.append(
            "sender_free_provider"
        )

    if sender.possible_display_name_mismatch:
        signals.append(
            "sender_display_mismatch"
        )

    return signals


def _collect_language_signals(
    security_features: SecurityFeatures,
) -> List[str]:
    """
    Convert language feature booleans into stable signal names.
    """

    language = security_features.language

    signals: List[str] = []

    if language.urgency_language:
        signals.append(
            "lang_urgency"
        )

    if language.credential_request:
        signals.append(
            "lang_credentials"
        )

    if language.financial_request:
        signals.append(
            "lang_financial"
        )

    if language.verification_request:
        signals.append(
            "lang_verification"
        )

    if language.account_suspension_language:
        signals.append(
            "lang_suspension"
        )

    if language.password_reset_language:
        signals.append(
            "lang_password_reset"
        )

    return signals