from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EvaluationMode(str, Enum):
    """
    Execution mode being evaluated.

    ML_ONLY:
        Classical ML baseline only.

    GEMINI_ONLY:
        Gemini-based review without using the hybrid routing pipeline.

    HYBRID:
        Full production-style path:
        ML + deterministic security + risk + routing + Gemini when needed.
    """

    ML_ONLY = "ML_ONLY"
    GEMINI_ONLY = "GEMINI_ONLY"
    HYBRID = "HYBRID"


class EvaluationLabel(str, Enum):
    """
    Normalized ground-truth / prediction labels used by the
    evaluation layer.

    The initial evaluation remains binary at this layer so metrics
    can be compared consistently across ML-only, Gemini-only, and
    Hybrid execution modes.

    Richer threat categories may be retained separately in metadata
    or added in a later evaluation extension.
    """

    BENIGN = "BENIGN"
    THREAT = "THREAT"


class EvaluationDisposition(str, Enum):
    """
    Normalized operational outcomes used during evaluation.

    NOT_APPLICABLE is useful for ML-only evaluation where the model
    produces a classification but does not perform workflow triage.
    """

    NOT_APPLICABLE = "NOT_APPLICABLE"
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    QUARANTINE = "QUARANTINE"
    HUMAN_REVIEW = "HUMAN_REVIEW"


@dataclass(frozen=True)
class EvaluationSample:
    """
    One labeled message used by the evaluation harness.

    Message fields are treated as input evidence only.
    """

    sample_id: str

    subject: Optional[str]

    body: Optional[str]

    sender: Optional[str]

    true_label: EvaluationLabel

    urls: tuple[str, ...] = field(
        default_factory=tuple
    )

    threat_category: Optional[str] = None

    source: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.sample_id:
            raise ValueError(
                "sample_id must not be empty"
            )


@dataclass(frozen=True)
class EvaluationPrediction:
    """
    Normalized prediction returned by one evaluation mode.

    All execution modes are mapped into this common representation so
    the comparison layer does not need to understand ML/ADK internals.
    """

    predicted_label: EvaluationLabel

    confidence: float

    disposition: EvaluationDisposition = (
        EvaluationDisposition.NOT_APPLICABLE
    )

    threat_probability: Optional[float] = None

    explanation: Optional[str] = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if (
            self.threat_probability is not None
            and not (
                0.0
                <= self.threat_probability
                <= 1.0
            )
        ):
            raise ValueError(
                "threat_probability must be between 0 and 1"
            )


@dataclass(frozen=True)
class EvaluationResult:
    """
    Result of evaluating one sample in one execution mode.
    """

    sample_id: str

    mode: EvaluationMode

    true_label: EvaluationLabel

    prediction: Optional[EvaluationPrediction]

    latency_ms: float

    agent_invoked: bool

    error: Optional[str] = None

    metadata: dict[str, object] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.sample_id:
            raise ValueError(
                "sample_id must not be empty"
            )

        if self.latency_ms < 0:
            raise ValueError(
                "latency_ms must not be negative"
            )

        if (
            self.prediction is None
            and self.error is None
        ):
            raise ValueError(
                "prediction or error must be provided"
            )

        if (
            self.prediction is not None
            and self.error is not None
        ):
            raise ValueError(
                "prediction and error cannot both be provided"
            )


@dataclass(frozen=True)
class EvaluationMetrics:
    """
    Aggregate binary-classification and operational metrics for one
    evaluation mode.

    THREAT is treated as the positive class.
    """

    mode: EvaluationMode

    total_samples: int

    successful_samples: int

    failed_samples: int

    true_positive: int

    true_negative: int

    false_positive: int

    false_negative: int

    accuracy: float

    precision: float

    recall: float

    f1: float

    false_positive_rate: float

    false_negative_rate: float

    phishing_recall: Optional[float] = None

    agent_invocation_rate: float = 0.0

    average_latency_ms: float = 0.0

    def __post_init__(self) -> None:
        integer_fields = {
            "total_samples": self.total_samples,
            "successful_samples": self.successful_samples,
            "failed_samples": self.failed_samples,
            "true_positive": self.true_positive,
            "true_negative": self.true_negative,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
        }

        for name, value in integer_fields.items():
            if value < 0:
                raise ValueError(
                    f"{name} must not be negative"
                )

        if (
            self.successful_samples
            + self.failed_samples
            != self.total_samples
        ):
            raise ValueError(
                "successful_samples + failed_samples "
                "must equal total_samples"
            )

        bounded_metrics = {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": (
                self.false_positive_rate
            ),
            "false_negative_rate": (
                self.false_negative_rate
            ),
            "agent_invocation_rate": (
                self.agent_invocation_rate
            ),
        }

        if self.phishing_recall is not None:
            bounded_metrics[
                "phishing_recall"
            ] = self.phishing_recall

        for name, value in bounded_metrics.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{name} must be between 0 and 1"
                )

        if self.average_latency_ms < 0:
            raise ValueError(
                "average_latency_ms must not be negative"
            )


@dataclass(frozen=True)
class EvaluationComparison:
    """
    Compact comparison record across multiple evaluation modes.

    The detailed calculation will be implemented later in
    comparison.py.
    """

    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ]

    best_f1_mode: Optional[EvaluationMode] = None

    best_recall_mode: Optional[EvaluationMode] = None

    lowest_false_negative_mode: Optional[
        EvaluationMode
    ] = None

    lowest_latency_mode: Optional[
        EvaluationMode
    ] = None

    def __post_init__(self) -> None:
        if not self.metrics_by_mode:
            raise ValueError(
                "metrics_by_mode must not be empty"
            )