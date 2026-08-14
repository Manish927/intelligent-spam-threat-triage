from __future__ import annotations

from typing import Optional

from threat_triage.agents.models import (
    AgentReviewInput,
)
from threat_triage.risk.models import (
    RiskAssessment,
    RiskEvidence,
    RoutingDecision,
    RoutingResult,
)


DEFAULT_MAX_SUBJECT_LENGTH = 500
DEFAULT_MAX_BODY_PREVIEW_LENGTH = 4000
DEFAULT_MAX_SENDER_LENGTH = 500


def build_agent_review_input(
    *,
    message_id: str,
    subject: Optional[str],
    body: Optional[str],
    sender: Optional[str],
    risk_evidence: RiskEvidence,
    risk_assessment: RiskAssessment,
    routing_result: RoutingResult,
    max_subject_length: int = DEFAULT_MAX_SUBJECT_LENGTH,
    max_body_preview_length: int = DEFAULT_MAX_BODY_PREVIEW_LENGTH,
    max_sender_length: int = DEFAULT_MAX_SENDER_LENGTH,
    require_agent_review_route: bool = True,
) -> AgentReviewInput:
    """
    Build the bounded context supplied to the Agentic AI layer.

    This function is the boundary between the deterministic
    risk pipeline and the future Google ADK / Gemini workflow.

    Responsibilities:
        - validate message identity,
        - optionally require AGENT_REVIEW routing,
        - normalize message text,
        - bound untrusted message content,
        - preserve structured ML/risk evidence.

    It intentionally does not:
        - call an LLM,
        - execute tools,
        - interpret message semantics,
        - modify risk scores,
        - modify routing decisions.
    """

    _validate_limits(
        max_subject_length=max_subject_length,
        max_body_preview_length=max_body_preview_length,
        max_sender_length=max_sender_length,
    )

    _validate_message_identity(
        message_id=message_id,
        risk_evidence=risk_evidence,
        risk_assessment=risk_assessment,
        routing_result=routing_result,
    )

    if (
        require_agent_review_route
        and routing_result.decision
        != RoutingDecision.AGENT_REVIEW
    ):
        raise ValueError(
            "Agent review context requires "
            "AGENT_REVIEW routing decision"
        )

    normalized_subject = _normalize_and_bound_text(
        subject,
        max_length=max_subject_length,
    )

    normalized_body = _normalize_and_bound_text(
        body,
        max_length=max_body_preview_length,
    )

    normalized_sender = _normalize_and_bound_text(
        sender,
        max_length=max_sender_length,
    )

    return AgentReviewInput(
        message_id=message_id,
        subject=normalized_subject,
        body_preview=normalized_body,
        sender=normalized_sender,
        ml_evidence=risk_evidence.ml,
        evidence_summary=risk_evidence.summary,
        risk_assessment=risk_assessment,
        routing_result=routing_result,
    )


def _normalize_and_bound_text(
    value: Optional[str],
    *,
    max_length: int,
) -> Optional[str]:
    """
    Normalize untrusted message text and enforce a maximum length.

    Normalization:
        - None remains None
        - leading/trailing whitespace is removed
        - CRLF/CR line endings become LF
        - NUL characters are removed
        - empty normalized strings become None
        - content longer than max_length is truncated

    This is context preparation, not semantic sanitization.

    Email content remains untrusted data and must still be treated
    as such by the future agent prompt and tool layer.
    """

    if value is None:
        return None

    normalized = (
        value
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\x00", "")
        .strip()
    )

    if not normalized:
        return None

    if len(normalized) > max_length:
        normalized = normalized[:max_length]

    return normalized


def _validate_message_identity(
    *,
    message_id: str,
    risk_evidence: RiskEvidence,
    risk_assessment: RiskAssessment,
    routing_result: RoutingResult,
) -> None:
    """
    Ensure every object belongs to the same message.
    """

    if not message_id:
        raise ValueError(
            "message_id must not be empty"
        )

    if risk_evidence.message_id != message_id:
        raise ValueError(
            "message_id must match "
            "RiskEvidence message_id"
        )

    if risk_assessment.message_id != message_id:
        raise ValueError(
            "message_id must match "
            "RiskAssessment message_id"
        )

    if routing_result.message_id != message_id:
        raise ValueError(
            "message_id must match "
            "RoutingResult message_id"
        )


def _validate_limits(
    *,
    max_subject_length: int,
    max_body_preview_length: int,
    max_sender_length: int,
) -> None:
    """
    Validate context-size configuration.
    """

    limits = {
        "max_subject_length": max_subject_length,
        "max_body_preview_length": (
            max_body_preview_length
        ),
        "max_sender_length": max_sender_length,
    }

    for name, value in limits.items():
        if value <= 0:
            raise ValueError(
                f"{name} must be greater than zero"
            )