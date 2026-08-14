from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from threat_triage.risk.models import (
    EvidenceSummary,
    MLEvidence,
    RiskAssessment,
    RoutingResult,
)


class AgentFindingCategory(str, Enum):
    """
    Normalized categories for findings produced during Agentic AI review.
    """

    URL = "URL"
    SENDER = "SENDER"
    LANGUAGE = "LANGUAGE"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    MESSAGE_CONTEXT = "MESSAGE_CONTEXT"
    MODEL_CONFLICT = "MODEL_CONFLICT"
    POLICY = "POLICY"


class AgentFindingSeverity(str, Enum):
    """
    Severity assigned to an individual Agentic AI finding.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AgentDisposition(str, Enum):
    """
    Final constrained recommendation produced by Agentic AI review.

    This is intentionally an enum rather than arbitrary free-form text.
    """

    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    QUARANTINE = "QUARANTINE"
    HUMAN_REVIEW = "HUMAN_REVIEW"


@dataclass(frozen=True)
class AgentReviewInput:
    """
    Structured input passed into the future Google ADK / Gemini
    review workflow.

    The agent receives contextual message information plus the
    evidence already produced by the deterministic and ML layers.

    It does not receive authority to silently modify those inputs.
    """

    message_id: str

    subject: Optional[str]
    body_preview: Optional[str]
    sender: Optional[str]

    ml_evidence: MLEvidence
    evidence_summary: EvidenceSummary
    risk_assessment: RiskAssessment
    routing_result: RoutingResult

    def __post_init__(self) -> None:
        if not self.message_id:
            raise ValueError(
                "message_id must not be empty"
            )

        if (
            self.risk_assessment.message_id
            != self.message_id
        ):
            raise ValueError(
                "AgentReviewInput message_id must match "
                "RiskAssessment message_id"
            )

        if (
            self.routing_result.message_id
            != self.message_id
        ):
            raise ValueError(
                "AgentReviewInput message_id must match "
                "RoutingResult message_id"
            )


@dataclass(frozen=True)
class AgentFinding:
    """
    One explainable finding produced during agent review.

    A finding represents an interpreted piece of evidence,
    not the final disposition.
    """

    category: AgentFindingCategory
    finding: str
    severity: AgentFindingSeverity
    confidence: float

    evidence_refs: List[str] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        if not self.finding:
            raise ValueError(
                "finding must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


@dataclass(frozen=True)
class AgentRecommendation:
    """
    Constrained recommendation produced after Agentic AI reasoning.
    """

    disposition: AgentDisposition

    confidence: float

    reasons: List[str] = field(
        default_factory=list
    )

    requires_human_review: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if not self.reasons:
            raise ValueError(
                "reasons must not be empty"
            )

        if (
            self.disposition
            == AgentDisposition.HUMAN_REVIEW
            and not self.requires_human_review
        ):
            raise ValueError(
                "HUMAN_REVIEW disposition requires "
                "requires_human_review=True"
            )


@dataclass(frozen=True)
class AgentModelMetadata:
    """
    Metadata describing the model/runtime that produced
    the Agentic AI review.

    This supports reproducibility, auditing, and evaluation.
    """

    provider: str
    model_name: str
    agent_version: str

    request_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.provider:
            raise ValueError(
                "provider must not be empty"
            )

        if not self.model_name:
            raise ValueError(
                "model_name must not be empty"
            )

        if not self.agent_version:
            raise ValueError(
                "agent_version must not be empty"
            )


@dataclass(frozen=True)
class AgentReviewResult:
    """
    Final structured output of an Agentic AI review.

    This contract is intended to become the structured-output
    boundary for Google ADK / Gemini.

    It contains:
        - individual findings,
        - constrained recommendation,
        - explanation,
        - model/runtime metadata.
    """

    message_id: str

    findings: List[AgentFinding]

    recommendation: AgentRecommendation

    explanation: str

    model_metadata: AgentModelMetadata

    def __post_init__(self) -> None:
        if not self.message_id:
            raise ValueError(
                "message_id must not be empty"
            )

        if not self.explanation:
            raise ValueError(
                "explanation must not be empty"
            )