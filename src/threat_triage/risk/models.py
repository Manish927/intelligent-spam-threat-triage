from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from threat_triage.security.models import SecurityFeatures


class RiskSeverity(str, Enum):
    """
    Normalized risk-severity levels used by the platform.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RoutingDecision(str, Enum):
    """
    High-level routing outcomes.

    These values describe workflow routing, not final enforcement.
    """

    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    AGENT_REVIEW = "AGENT_REVIEW"
    HUMAN_REVIEW = "HUMAN_REVIEW"


@dataclass(frozen=True)
class MLEvidence:
    """
    Evidence produced by the classical ML classifier.

    This object captures what the model predicted without treating
    that prediction as the final security decision.
    """

    predicted_label: str
    threat_probability: float
    decision_threshold: float

    model_name: str
    model_version: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.threat_probability <= 1.0:
            raise ValueError(
                "threat_probability must be between 0 and 1"
            )

        if not 0.0 <= self.decision_threshold <= 1.0:
            raise ValueError(
                "decision_threshold must be between 0 and 1"
            )

        if not self.predicted_label:
            raise ValueError(
                "predicted_label must not be empty"
            )

        if not self.model_name:
            raise ValueError(
                "model_name must not be empty"
            )

        if not self.model_version:
            raise ValueError(
                "model_version must not be empty"
            )


@dataclass(frozen=True)
class EvidenceSummary:
    """
    Compact summary of deterministic security evidence.

    This keeps routing/risk components from repeatedly traversing the
    full nested SecurityFeatures object.
    """

    total_signal_count: int

    url_signal_count: int
    sender_signal_count: int
    language_signal_count: int

    evidence_categories: List[str] = field(
        default_factory=list
    )

    strong_signals: List[str] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        counts = [
            self.total_signal_count,
            self.url_signal_count,
            self.sender_signal_count,
            self.language_signal_count,
        ]

        if any(value < 0 for value in counts):
            raise ValueError(
                "Evidence signal counts must not be negative"
            )

        component_total = (
            self.url_signal_count
            + self.sender_signal_count
            + self.language_signal_count
        )

        if self.total_signal_count != component_total:
            raise ValueError(
                "total_signal_count must equal the sum of "
                "url, sender, and language signal counts"
            )


@dataclass(frozen=True)
class EvidenceProvenance:
    """
    Provenance and version metadata for reproducibility and auditability.
    """

    model_version: str
    feature_version: str

    generated_at: datetime = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    def __post_init__(self) -> None:
        if not self.model_version:
            raise ValueError(
                "model_version must not be empty"
            )

        if not self.feature_version:
            raise ValueError(
                "feature_version must not be empty"
            )

        if self.generated_at.tzinfo is None:
            raise ValueError(
                "generated_at must be timezone-aware"
            )


@dataclass(frozen=True)
class RiskEvidence:
    """
    Complete evidence contract for one email.

    This is the boundary between:

        evidence generation

    and:

        risk scoring / routing / Agentic AI reasoning

    It contains no final risk score or routing decision.
    """

    message_id: str

    ml: MLEvidence
    security: SecurityFeatures
    summary: EvidenceSummary
    provenance: EvidenceProvenance

    def __post_init__(self) -> None:
        if not self.message_id:
            raise ValueError(
                "message_id must not be empty"
            )

        if self.security.message_id != self.message_id:
            raise ValueError(
                "RiskEvidence message_id must match "
                "SecurityFeatures message_id"
            )


@dataclass(frozen=True)
class RiskAssessment:
    """
    Output produced by the future risk-scoring layer.

    This object represents an interpreted risk assessment, but it does
    not itself decide workflow routing.
    """

    message_id: str

    risk_score: float
    severity: RiskSeverity

    confidence: float

    reasons: List[str] = field(
        default_factory=list
    )

    requires_deep_analysis: bool = False

    def __post_init__(self) -> None:
        if not self.message_id:
            raise ValueError(
                "message_id must not be empty"
            )

        if not 0.0 <= self.risk_score <= 100.0:
            raise ValueError(
                "risk_score must be between 0 and 100"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


@dataclass(frozen=True)
class RoutingResult:
    """
    Output produced by the future routing-policy layer.
    """

    message_id: str

    decision: RoutingDecision

    reason: str

    requires_human_review: bool = False

    def __post_init__(self) -> None:
        if not self.message_id:
            raise ValueError(
                "message_id must not be empty"
            )

        if not self.reason:
            raise ValueError(
                "reason must not be empty"
            )