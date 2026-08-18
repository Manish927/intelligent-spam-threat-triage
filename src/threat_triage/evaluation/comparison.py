from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from threat_triage.evaluation.models import (
    EvaluationComparison,
    EvaluationMetrics,
    EvaluationMode,
)


@dataclass(frozen=True)
class MetricDelta:
    """
    Difference between two evaluation modes for one metric.

    absolute_delta:
        candidate - baseline

    relative_delta:
        (candidate - baseline) / baseline

    relative_delta is None when the baseline value is zero because
    percentage improvement is undefined in that case.
    """

    metric_name: str

    baseline_mode: EvaluationMode

    candidate_mode: EvaluationMode

    baseline_value: float

    candidate_value: float

    absolute_delta: float

    relative_delta: Optional[float]


@dataclass(frozen=True)
class ModeComparison:
    """
    Detailed comparison between two evaluation modes.

    Positive quality deltas usually indicate improvement.

    For false-positive rate, false-negative rate, latency, and agent
    invocation rate, lower values may be preferable, so callers should
    interpret those deltas according to metric semantics.
    """

    baseline_mode: EvaluationMode

    candidate_mode: EvaluationMode

    accuracy: MetricDelta

    precision: MetricDelta

    recall: MetricDelta

    f1: MetricDelta

    false_positive_rate: MetricDelta

    false_negative_rate: MetricDelta

    phishing_recall: Optional[MetricDelta]

    agent_invocation_rate: MetricDelta

    average_latency_ms: MetricDelta


def build_evaluation_comparison(
    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ],
) -> EvaluationComparison:
    """
    Build the compact cross-mode comparison defined in models.py.

    The comparison identifies:

        - best F1
        - best recall
        - lowest false-negative rate
        - lowest average latency

    Tie-breaking is deterministic and follows EvaluationMode enum order:

        ML_ONLY
        GEMINI_ONLY
        HYBRID
    """

    if not metrics_by_mode:
        raise ValueError(
            "metrics_by_mode must not be empty"
        )

    _validate_metrics_mode_identity(
        metrics_by_mode
    )

    ordered_modes = _ordered_modes(
        metrics_by_mode
    )

    best_f1_mode = max(
        ordered_modes,
        key=lambda mode: (
            metrics_by_mode[mode].f1
        ),
    )

    best_recall_mode = max(
        ordered_modes,
        key=lambda mode: (
            metrics_by_mode[mode].recall
        ),
    )

    lowest_false_negative_mode = min(
        ordered_modes,
        key=lambda mode: (
            metrics_by_mode[
                mode
            ].false_negative_rate
        ),
    )

    lowest_latency_mode = min(
        ordered_modes,
        key=lambda mode: (
            metrics_by_mode[
                mode
            ].average_latency_ms
        ),
    )

    return EvaluationComparison(
        metrics_by_mode=dict(
            metrics_by_mode
        ),
        best_f1_mode=best_f1_mode,
        best_recall_mode=best_recall_mode,
        lowest_false_negative_mode=(
            lowest_false_negative_mode
        ),
        lowest_latency_mode=(
            lowest_latency_mode
        ),
    )


def compare_modes(
    *,
    baseline: EvaluationMetrics,
    candidate: EvaluationMetrics,
) -> ModeComparison:
    """
    Produce detailed metric deltas between two evaluation modes.

    Typical uses:

        ML_ONLY      -> HYBRID
        ML_ONLY      -> GEMINI_ONLY
        GEMINI_ONLY  -> HYBRID
    """

    if (
        baseline.mode
        == candidate.mode
    ):
        raise ValueError(
            "baseline and candidate modes "
            "must be different"
        )

    phishing_delta: Optional[
        MetricDelta
    ]

    if (
        baseline.phishing_recall
        is None
        or candidate.phishing_recall
        is None
    ):
        phishing_delta = None

    else:
        phishing_delta = _build_metric_delta(
            metric_name="phishing_recall",
            baseline_mode=baseline.mode,
            candidate_mode=candidate.mode,
            baseline_value=(
                baseline.phishing_recall
            ),
            candidate_value=(
                candidate.phishing_recall
            ),
        )

    return ModeComparison(
        baseline_mode=baseline.mode,
        candidate_mode=candidate.mode,

        accuracy=_build_metric_delta(
            metric_name="accuracy",
            baseline_mode=baseline.mode,
            candidate_mode=candidate.mode,
            baseline_value=baseline.accuracy,
            candidate_value=(
                candidate.accuracy
            ),
        ),

        precision=_build_metric_delta(
            metric_name="precision",
            baseline_mode=baseline.mode,
            candidate_mode=candidate.mode,
            baseline_value=baseline.precision,
            candidate_value=(
                candidate.precision
            ),
        ),

        recall=_build_metric_delta(
            metric_name="recall",
            baseline_mode=baseline.mode,
            candidate_mode=candidate.mode,
            baseline_value=baseline.recall,
            candidate_value=(
                candidate.recall
            ),
        ),

        f1=_build_metric_delta(
            metric_name="f1",
            baseline_mode=baseline.mode,
            candidate_mode=candidate.mode,
            baseline_value=baseline.f1,
            candidate_value=candidate.f1,
        ),

        false_positive_rate=(
            _build_metric_delta(
                metric_name=(
                    "false_positive_rate"
                ),
                baseline_mode=baseline.mode,
                candidate_mode=(
                    candidate.mode
                ),
                baseline_value=(
                    baseline
                    .false_positive_rate
                ),
                candidate_value=(
                    candidate
                    .false_positive_rate
                ),
            )
        ),

        false_negative_rate=(
            _build_metric_delta(
                metric_name=(
                    "false_negative_rate"
                ),
                baseline_mode=baseline.mode,
                candidate_mode=(
                    candidate.mode
                ),
                baseline_value=(
                    baseline
                    .false_negative_rate
                ),
                candidate_value=(
                    candidate
                    .false_negative_rate
                ),
            )
        ),

        phishing_recall=(
            phishing_delta
        ),

        agent_invocation_rate=(
            _build_metric_delta(
                metric_name=(
                    "agent_invocation_rate"
                ),
                baseline_mode=baseline.mode,
                candidate_mode=(
                    candidate.mode
                ),
                baseline_value=(
                    baseline
                    .agent_invocation_rate
                ),
                candidate_value=(
                    candidate
                    .agent_invocation_rate
                ),
            )
        ),

        average_latency_ms=(
            _build_metric_delta(
                metric_name=(
                    "average_latency_ms"
                ),
                baseline_mode=baseline.mode,
                candidate_mode=(
                    candidate.mode
                ),
                baseline_value=(
                    baseline
                    .average_latency_ms
                ),
                candidate_value=(
                    candidate
                    .average_latency_ms
                ),
            )
        ),
    )


def compare_ml_to_hybrid(
    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ],
) -> ModeComparison:
    """
    Convenience comparison for the primary architecture experiment:

        ML_ONLY
            vs.
        HYBRID
    """

    return _compare_required_modes(
        metrics_by_mode,
        baseline_mode=(
            EvaluationMode.ML_ONLY
        ),
        candidate_mode=(
            EvaluationMode.HYBRID
        ),
    )


def compare_ml_to_gemini(
    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ],
) -> ModeComparison:
    """
    Compare classical ML directly with Gemini-only execution.
    """

    return _compare_required_modes(
        metrics_by_mode,
        baseline_mode=(
            EvaluationMode.ML_ONLY
        ),
        candidate_mode=(
            EvaluationMode.GEMINI_ONLY
        ),
    )


def compare_gemini_to_hybrid(
    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ],
) -> ModeComparison:
    """
    Compare Gemini-only execution with the hybrid architecture.
    """

    return _compare_required_modes(
        metrics_by_mode,
        baseline_mode=(
            EvaluationMode.GEMINI_ONLY
        ),
        candidate_mode=(
            EvaluationMode.HYBRID
        ),
    )


def _compare_required_modes(
    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ],
    *,
    baseline_mode: EvaluationMode,
    candidate_mode: EvaluationMode,
) -> ModeComparison:
    if baseline_mode not in metrics_by_mode:
        raise ValueError(
            f"Missing metrics for "
            f"{baseline_mode.value}"
        )

    if candidate_mode not in metrics_by_mode:
        raise ValueError(
            f"Missing metrics for "
            f"{candidate_mode.value}"
        )

    return compare_modes(
        baseline=metrics_by_mode[
            baseline_mode
        ],
        candidate=metrics_by_mode[
            candidate_mode
        ],
    )


def _build_metric_delta(
    *,
    metric_name: str,
    baseline_mode: EvaluationMode,
    candidate_mode: EvaluationMode,
    baseline_value: float,
    candidate_value: float,
) -> MetricDelta:
    """
    Build absolute and relative metric change.
    """

    absolute_delta = (
        candidate_value
        - baseline_value
    )

    relative_delta: Optional[
        float
    ]

    if baseline_value == 0:
        relative_delta = None

    else:
        relative_delta = (
            absolute_delta
            / baseline_value
        )

    return MetricDelta(
        metric_name=metric_name,
        baseline_mode=baseline_mode,
        candidate_mode=candidate_mode,
        baseline_value=(
            baseline_value
        ),
        candidate_value=(
            candidate_value
        ),
        absolute_delta=(
            absolute_delta
        ),
        relative_delta=(
            relative_delta
        ),
    )


def _validate_metrics_mode_identity(
    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ],
) -> None:
    """
    Ensure dictionary key and metric object's own mode agree.
    """

    for mode, metrics in (
        metrics_by_mode.items()
    ):
        if metrics.mode != mode:
            raise ValueError(
                "metrics_by_mode key must "
                "match EvaluationMetrics.mode"
            )


def _ordered_modes(
    metrics_by_mode: dict[
        EvaluationMode,
        EvaluationMetrics,
    ],
) -> list[EvaluationMode]:
    """
    Return represented modes using stable enum ordering.
    """

    return [
        mode
        for mode in EvaluationMode
        if mode in metrics_by_mode
    ]