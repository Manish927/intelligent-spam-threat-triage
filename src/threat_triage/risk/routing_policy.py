from __future__ import annotations

from dataclasses import dataclass
from typing import List

from threat_triage.risk.models import (
    RiskAssessment,
    RiskEvidence,
    RiskSeverity,
    RoutingDecision,
    RoutingResult,
)


@dataclass(frozen=True)
class RoutingPolicy:
    """
    Configurable workflow-routing policy.

    This layer decides what should happen next after risk assessment.

    It does not:
        - calculate the risk score,
        - modify ML evidence,
        - modify security evidence,
        - call Gemini / Google ADK directly.

    Instead, it maps evidence + assessment into a workflow decision.
    """

    # Numerical thresholds
    allow_max_score: float = 20.0
    monitor_max_score: float = 40.0
    agent_review_max_score: float = 75.0

    # Escalation behavior
    human_review_for_critical: bool = True
    human_review_for_high_with_strong_signals: bool = True

    # Deep-analysis handling
    agent_review_when_deep_analysis_required: bool = True

    # Strong evidence override
    human_review_min_strong_signals: int = 2


DEFAULT_ROUTING_POLICY = RoutingPolicy()


def route_message(
    *,
    evidence: RiskEvidence,
    assessment: RiskAssessment,
    policy: RoutingPolicy = DEFAULT_ROUTING_POLICY,
) -> RoutingResult:
    """
    Convert RiskEvidence + RiskAssessment into a workflow-routing decision.

    Possible outputs:

        ALLOW
        MONITOR
        AGENT_REVIEW
        HUMAN_REVIEW

    Routing is policy-driven and intentionally separate from scoring.
    """

    _validate_policy(policy)

    _validate_message_identity(
        evidence=evidence,
        assessment=assessment,
    )

    strong_signal_count = len(
        evidence.summary.strong_signals
    )

    decision = _select_decision(
        assessment=assessment,
        strong_signal_count=strong_signal_count,
        policy=policy,
    )

    reasons = _build_routing_reasons(
        evidence=evidence,
        assessment=assessment,
        decision=decision,
        strong_signal_count=strong_signal_count,
    )

    requires_human_review = (
        decision
        == RoutingDecision.HUMAN_REVIEW
    )

    return RoutingResult(
        message_id=evidence.message_id,
        decision=decision,
        reason="; ".join(reasons),
        requires_human_review=requires_human_review,
    )


def _select_decision(
    *,
    assessment: RiskAssessment,
    strong_signal_count: int,
    policy: RoutingPolicy,
) -> RoutingDecision:
    """
    Apply workflow-routing policy.

    Priority order matters:

        1. Human-review overrides
        2. Agent-review requirements
        3. Score-based routing
    """

    if (
        policy.human_review_for_critical
        and assessment.severity
        == RiskSeverity.CRITICAL
    ):
        return RoutingDecision.HUMAN_REVIEW

    if (
        policy.human_review_for_high_with_strong_signals
        and assessment.severity
        == RiskSeverity.HIGH
        and strong_signal_count
        >= policy.human_review_min_strong_signals
    ):
        return RoutingDecision.HUMAN_REVIEW

    if (
        policy.agent_review_when_deep_analysis_required
        and assessment.requires_deep_analysis
    ):
        return RoutingDecision.AGENT_REVIEW

    if (
        assessment.risk_score
        <= policy.allow_max_score
    ):
        return RoutingDecision.ALLOW

    if (
        assessment.risk_score
        <= policy.monitor_max_score
    ):
        return RoutingDecision.MONITOR

    if (
        assessment.risk_score
        <= policy.agent_review_max_score
    ):
        return RoutingDecision.AGENT_REVIEW

    return RoutingDecision.HUMAN_REVIEW


def _build_routing_reasons(
    *,
    evidence: RiskEvidence,
    assessment: RiskAssessment,
    decision: RoutingDecision,
    strong_signal_count: int,
) -> List[str]:
    """
    Produce human-readable routing rationale.
    """

    reasons: List[str] = []

    reasons.append(
        f"Risk score {assessment.risk_score:.2f} "
        f"with severity {assessment.severity.value}"
    )

    reasons.append(
        f"ML threat probability "
        f"{evidence.ml.threat_probability:.4f}"
    )

    if (
        evidence.summary.total_signal_count
        > 0
    ):
        reasons.append(
            f"{evidence.summary.total_signal_count} "
            "deterministic security signals detected"
        )

    if strong_signal_count > 0:
        reasons.append(
            f"{strong_signal_count} strong "
            "security signals detected"
        )

    if assessment.requires_deep_analysis:
        reasons.append(
            "Risk assessment requires deeper analysis"
        )

    if decision == RoutingDecision.ALLOW:
        reasons.append(
            "Risk remains below allow threshold"
        )

    elif decision == RoutingDecision.MONITOR:
        reasons.append(
            "Risk requires monitoring but not active escalation"
        )

    elif decision == RoutingDecision.AGENT_REVIEW:
        reasons.append(
            "Message requires Agentic AI review"
        )

    elif decision == RoutingDecision.HUMAN_REVIEW:
        reasons.append(
            "Message requires human security review"
        )

    return reasons


def _validate_message_identity(
    *,
    evidence: RiskEvidence,
    assessment: RiskAssessment,
) -> None:
    """
    Ensure evidence and assessment refer to the same message.
    """

    if (
        evidence.message_id
        != assessment.message_id
    ):
        raise ValueError(
            "RiskEvidence message_id must match "
            "RiskAssessment message_id"
        )


def _validate_policy(
    policy: RoutingPolicy,
) -> None:
    """
    Validate routing thresholds and policy configuration.
    """

    thresholds = {
        "allow_max_score": (
            policy.allow_max_score
        ),
        "monitor_max_score": (
            policy.monitor_max_score
        ),
        "agent_review_max_score": (
            policy.agent_review_max_score
        ),
    }

    for name, value in thresholds.items():
        if not 0.0 <= value <= 100.0:
            raise ValueError(
                f"{name} must be between 0 and 100"
            )

    if not (
        policy.allow_max_score
        <= policy.monitor_max_score
        <= policy.agent_review_max_score
    ):
        raise ValueError(
            "Routing thresholds must satisfy "
            "allow <= monitor <= agent_review"
        )

    if (
        policy.human_review_min_strong_signals
        < 0
    ):
        raise ValueError(
            "human_review_min_strong_signals "
            "must not be negative"
        )