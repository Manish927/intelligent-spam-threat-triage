from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from threat_triage.risk.models import (
    RiskAssessment,
    RiskEvidence,
    RiskSeverity,
)


@dataclass(frozen=True)
class RiskScoringPolicy:
    """
    Configurable deterministic scoring policy.

    The goal is not to create the final production scoring model.
    This policy provides a transparent V1 risk interpretation layer
    that can later be replaced or augmented by learned calibration,
    threat intelligence, and Agentic AI reasoning.
    """

    # ML contribution
    ml_probability_weight: float = 60.0

    # Evidence contributions
    strong_signal_weight: float = 8.0
    weak_signal_weight: float = 2.0

    # Maximum contribution from deterministic evidence
    max_security_evidence_score: float = 40.0

    # Deep-analysis triggers
    deep_analysis_probability_low: float = 0.25
    deep_analysis_probability_high: float = 0.80

    deep_analysis_min_strong_signals: int = 1
    deep_analysis_min_total_signals: int = 2


DEFAULT_POLICY = RiskScoringPolicy()


STRONG_SIGNAL_REASONS: Dict[str, str] = {
    "url_ip_address": (
        "URL uses a literal IP address"
    ),
    "url_suspicious_tld": (
        "URL uses a configured suspicious TLD"
    ),
    "url_punycode": (
        "URL contains an IDNA/punycode domain"
    ),
    "url_credential_path": (
        "URL contains credential-related path terms"
    ),
    "sender_display_mismatch": (
        "Sender display name may conflict with sender domain"
    ),
    "lang_urgency": (
        "Urgency language detected"
    ),
    "lang_financial": (
        "Financial-request language detected"
    ),
    "lang_suspension": (
        "Account-suspension language detected"
    ),
}


def score_risk(
    evidence: RiskEvidence,
    policy: RiskScoringPolicy = DEFAULT_POLICY,
) -> RiskAssessment:
    """
    Convert RiskEvidence into a deterministic RiskAssessment.

    V1 scoring model:

        ML score
            +
        deterministic evidence score
            =
        bounded risk score [0, 100]

    Important:
        - This is a transparent policy baseline.
        - It is not claimed to be statistically calibrated.
        - It does not make the final routing decision.
        - Routing is handled separately by routing_policy.py.
    """

    _validate_policy(policy)

    ml_score = _calculate_ml_score(
        evidence,
        policy,
    )

    security_score = _calculate_security_score(
        evidence,
        policy,
    )

    risk_score = min(
        100.0,
        ml_score + security_score,
    )

    severity = _severity_from_score(
        risk_score
    )

    requires_deep_analysis = (
        _requires_deep_analysis(
            evidence,
            policy,
        )
    )

    reasons = _build_reasons(
        evidence=evidence,
        ml_score=ml_score,
        security_score=security_score,
        requires_deep_analysis=(
            requires_deep_analysis
        ),
    )

    confidence = _calculate_confidence(
        evidence
    )

    return RiskAssessment(
        message_id=evidence.message_id,
        risk_score=round(
            risk_score,
            2,
        ),
        severity=severity,
        confidence=round(
            confidence,
            4,
        ),
        reasons=reasons,
        requires_deep_analysis=(
            requires_deep_analysis
        ),
    )


def _calculate_ml_score(
    evidence: RiskEvidence,
    policy: RiskScoringPolicy,
) -> float:
    """
    Convert ML threat probability into its weighted score contribution.
    """

    return (
        evidence.ml.threat_probability
        * policy.ml_probability_weight
    )


def _calculate_security_score(
    evidence: RiskEvidence,
    policy: RiskScoringPolicy,
) -> float:
    """
    Calculate deterministic evidence contribution.

    Strong signals receive larger weight.

    Remaining non-strong signals receive the weak-signal weight.
    """

    strong_signal_count = len(
        evidence.summary.strong_signals
    )

    total_signal_count = (
        evidence.summary.total_signal_count
    )

    weak_signal_count = max(
        0,
        total_signal_count
        - strong_signal_count,
    )

    raw_score = (
        strong_signal_count
        * policy.strong_signal_weight
        +
        weak_signal_count
        * policy.weak_signal_weight
    )

    return min(
        raw_score,
        policy.max_security_evidence_score,
    )


def _severity_from_score(
    risk_score: float,
) -> RiskSeverity:
    """
    Map numerical risk score to severity.

    V1 policy:

        0–24.99    LOW
        25–49.99   MEDIUM
        50–74.99   HIGH
        75–100     CRITICAL
    """

    if risk_score < 25.0:
        return RiskSeverity.LOW

    if risk_score < 50.0:
        return RiskSeverity.MEDIUM

    if risk_score < 75.0:
        return RiskSeverity.HIGH

    return RiskSeverity.CRITICAL


def _requires_deep_analysis(
    evidence: RiskEvidence,
    policy: RiskScoringPolicy,
) -> bool:
    """
    Decide whether the evidence warrants deeper reasoning.

    Important:
    This is not the workflow routing decision.

    It merely records that the risk scorer believes additional
    analysis may be valuable.
    """

    probability = (
        evidence.ml.threat_probability
    )

    probability_uncertain = (
        policy.deep_analysis_probability_low
        <= probability
        <= policy.deep_analysis_probability_high
    )

    has_strong_signal = (
        len(
            evidence.summary.strong_signals
        )
        >= policy.deep_analysis_min_strong_signals
    )

    has_multiple_signals = (
        evidence.summary.total_signal_count
        >= policy.deep_analysis_min_total_signals
    )

    return (
        probability_uncertain
        or has_strong_signal
        or has_multiple_signals
    )


def _calculate_confidence(
    evidence: RiskEvidence,
) -> float:
    """
    Calculate a simple confidence proxy.

    V1 interpretation:
        Confidence increases as ML probability moves away from 0.5.

    Deterministic evidence does not directly inflate confidence because
    Notebook 03 showed that many deterministic signals also appear in
    BENIGN messages.

    This is intentionally conservative.
    """

    probability = (
        evidence.ml.threat_probability
    )

    distance_from_boundary = abs(
        probability - 0.5
    )

    confidence = (
        distance_from_boundary * 2.0
    )

    return min(
        max(
            confidence,
            0.0,
        ),
        1.0,
    )


def _build_reasons(
    *,
    evidence: RiskEvidence,
    ml_score: float,
    security_score: float,
    requires_deep_analysis: bool,
) -> List[str]:
    """
    Produce human-readable reasons for the risk assessment.
    """

    reasons: List[str] = []

    reasons.append(
        "ML threat probability "
        f"{evidence.ml.threat_probability:.4f} "
        f"contributed {ml_score:.2f} risk points"
    )

    if evidence.summary.total_signal_count > 0:
        reasons.append(
            "Deterministic security evidence "
            f"contributed {security_score:.2f} risk points "
            f"from {evidence.summary.total_signal_count} signals"
        )

    for signal in evidence.summary.strong_signals:
        reason = STRONG_SIGNAL_REASONS.get(
            signal
        )

        if reason:
            reasons.append(reason)

    if requires_deep_analysis:
        reasons.append(
            "Evidence requires deeper analysis"
        )

    return reasons


def _validate_policy(
    policy: RiskScoringPolicy,
) -> None:
    """
    Validate scorer configuration.
    """

    non_negative_values = {
        "ml_probability_weight": (
            policy.ml_probability_weight
        ),
        "strong_signal_weight": (
            policy.strong_signal_weight
        ),
        "weak_signal_weight": (
            policy.weak_signal_weight
        ),
        "max_security_evidence_score": (
            policy.max_security_evidence_score
        ),
    }

    for name, value in (
        non_negative_values.items()
    ):
        if value < 0:
            raise ValueError(
                f"{name} must not be negative"
            )

    if not (
        0.0
        <= policy.deep_analysis_probability_low
        <= 1.0
    ):
        raise ValueError(
            "deep_analysis_probability_low "
            "must be between 0 and 1"
        )

    if not (
        0.0
        <= policy.deep_analysis_probability_high
        <= 1.0
    ):
        raise ValueError(
            "deep_analysis_probability_high "
            "must be between 0 and 1"
        )

    if (
        policy.deep_analysis_probability_low
        >
        policy.deep_analysis_probability_high
    ):
        raise ValueError(
            "deep-analysis probability lower bound "
            "must not exceed upper bound"
        )

    if (
        policy.deep_analysis_min_strong_signals
        < 0
    ):
        raise ValueError(
            "deep_analysis_min_strong_signals "
            "must not be negative"
        )

    if (
        policy.deep_analysis_min_total_signals
        < 0
    ):
        raise ValueError(
            "deep_analysis_min_total_signals "
            "must not be negative"
        )