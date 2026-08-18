import pytest

from threat_triage.evaluation.comparison import (
    MetricDelta,
    build_evaluation_comparison,
    compare_gemini_to_hybrid,
    compare_ml_to_gemini,
    compare_ml_to_hybrid,
    compare_modes,
)
from threat_triage.evaluation.models import (
    EvaluationMetrics,
    EvaluationMode,
)


def build_metrics(
    *,
    mode: EvaluationMode,
    accuracy: float = 0.90,
    precision: float = 0.90,
    recall: float = 0.90,
    f1: float = 0.90,
    false_positive_rate: float = 0.10,
    false_negative_rate: float = 0.10,
    phishing_recall: float | None = 0.90,
    agent_invocation_rate: float = 0.0,
    average_latency_ms: float = 10.0,
) -> EvaluationMetrics:
    return EvaluationMetrics(
        mode=mode,

        total_samples=100,
        successful_samples=100,
        failed_samples=0,

        true_positive=45,
        true_negative=45,
        false_positive=5,
        false_negative=5,

        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,

        false_positive_rate=(
            false_positive_rate
        ),

        false_negative_rate=(
            false_negative_rate
        ),

        phishing_recall=(
            phishing_recall
        ),

        agent_invocation_rate=(
            agent_invocation_rate
        ),

        average_latency_ms=(
            average_latency_ms
        ),
    )


def build_three_mode_metrics():
    return {
        EvaluationMode.ML_ONLY: (
            build_metrics(
                mode=(
                    EvaluationMode.ML_ONLY
                ),
                accuracy=0.88,
                precision=0.90,
                recall=0.75,
                f1=0.82,
                false_positive_rate=0.08,
                false_negative_rate=0.25,
                phishing_recall=0.70,
                agent_invocation_rate=0.0,
                average_latency_ms=3.0,
            )
        ),

        EvaluationMode.GEMINI_ONLY: (
            build_metrics(
                mode=(
                    EvaluationMode
                    .GEMINI_ONLY
                ),
                accuracy=0.91,
                precision=0.88,
                recall=0.94,
                f1=0.91,
                false_positive_rate=0.12,
                false_negative_rate=0.06,
                phishing_recall=0.96,
                agent_invocation_rate=1.0,
                average_latency_ms=850.0,
            )
        ),

        EvaluationMode.HYBRID: (
            build_metrics(
                mode=(
                    EvaluationMode.HYBRID
                ),
                accuracy=0.94,
                precision=0.93,
                recall=0.96,
                f1=0.945,
                false_positive_rate=0.07,
                false_negative_rate=0.04,
                phishing_recall=0.98,
                agent_invocation_rate=0.30,
                average_latency_ms=260.0,
            )
        ),
    }


def test_build_comparison_selects_best_f1():
    metrics = (
        build_three_mode_metrics()
    )

    comparison = (
        build_evaluation_comparison(
            metrics
        )
    )

    assert (
        comparison.best_f1_mode
        == EvaluationMode.HYBRID
    )


def test_build_comparison_selects_best_recall():
    comparison = (
        build_evaluation_comparison(
            build_three_mode_metrics()
        )
    )

    assert (
        comparison.best_recall_mode
        == EvaluationMode.HYBRID
    )


def test_build_comparison_selects_lowest_false_negative():
    comparison = (
        build_evaluation_comparison(
            build_three_mode_metrics()
        )
    )

    assert (
        comparison
        .lowest_false_negative_mode
        == EvaluationMode.HYBRID
    )


def test_build_comparison_selects_lowest_latency():
    comparison = (
        build_evaluation_comparison(
            build_three_mode_metrics()
        )
    )

    assert (
        comparison.lowest_latency_mode
        == EvaluationMode.ML_ONLY
    )


def test_build_comparison_preserves_metrics():
    metrics = (
        build_three_mode_metrics()
    )

    comparison = (
        build_evaluation_comparison(
            metrics
        )
    )

    assert (
        comparison.metrics_by_mode
        == metrics
    )


def test_build_comparison_rejects_empty_metrics():
    with pytest.raises(
        ValueError,
        match=(
            "metrics_by_mode must "
            "not be empty"
        ),
    ):
        build_evaluation_comparison(
            {}
        )


def test_comparison_rejects_mode_key_mismatch():
    metrics = {
        EvaluationMode.ML_ONLY: (
            build_metrics(
                mode=EvaluationMode.HYBRID
            )
        )
    }

    with pytest.raises(
        ValueError,
        match=(
            "metrics_by_mode key must "
            "match EvaluationMetrics.mode"
        ),
    ):
        build_evaluation_comparison(
            metrics
        )


def test_compare_modes_builds_absolute_delta():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        f1=0.80,
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        f1=0.90,
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    assert (
        comparison.f1.absolute_delta
        == pytest.approx(
            0.10
        )
    )


def test_compare_modes_builds_relative_delta():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        recall=0.50,
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        recall=0.75,
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    assert (
        comparison.recall.relative_delta
        == pytest.approx(
            0.50
        )
    )


def test_relative_delta_none_when_baseline_zero():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        agent_invocation_rate=0.0,
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        agent_invocation_rate=0.25,
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    assert (
        comparison
        .agent_invocation_rate
        .relative_delta
        is None
    )

    assert (
        comparison
        .agent_invocation_rate
        .absolute_delta
        == 0.25
    )


def test_false_negative_improvement_is_negative_delta():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        false_negative_rate=0.20,
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        false_negative_rate=0.05,
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    assert (
        comparison
        .false_negative_rate
        .absolute_delta
        == pytest.approx(
            -0.15
        )
    )


def test_latency_increase_is_positive_delta():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        average_latency_ms=5.0,
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        average_latency_ms=100.0,
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    assert (
        comparison
        .average_latency_ms
        .absolute_delta
        == 95.0
    )


def test_phishing_recall_delta():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        phishing_recall=0.70,
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        phishing_recall=0.95,
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    assert (
        comparison.phishing_recall
        is not None
    )

    assert (
        comparison
        .phishing_recall
        .absolute_delta
        == pytest.approx(
            0.25
        )
    )


@pytest.mark.parametrize(
    (
        "baseline_phishing",
        "candidate_phishing",
    ),
    [
        (
            None,
            0.90,
        ),
        (
            0.90,
            None,
        ),
        (
            None,
            None,
        ),
    ],
)
def test_phishing_delta_none_when_metric_missing(
    baseline_phishing,
    candidate_phishing,
):
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        phishing_recall=(
            baseline_phishing
        ),
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        phishing_recall=(
            candidate_phishing
        ),
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    assert (
        comparison.phishing_recall
        is None
    )


def test_compare_modes_rejects_same_mode():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY
    )

    candidate = build_metrics(
        mode=EvaluationMode.ML_ONLY
    )

    with pytest.raises(
        ValueError,
        match=(
            "baseline and candidate modes "
            "must be different"
        ),
    ):
        compare_modes(
            baseline=baseline,
            candidate=candidate,
        )


def test_compare_ml_to_hybrid():
    comparison = (
        compare_ml_to_hybrid(
            build_three_mode_metrics()
        )
    )

    assert (
        comparison.baseline_mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        comparison.candidate_mode
        == EvaluationMode.HYBRID
    )

    assert (
        comparison.f1.absolute_delta
        > 0
    )


def test_compare_ml_to_gemini():
    comparison = (
        compare_ml_to_gemini(
            build_three_mode_metrics()
        )
    )

    assert (
        comparison.baseline_mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        comparison.candidate_mode
        == EvaluationMode.GEMINI_ONLY
    )


def test_compare_gemini_to_hybrid():
    comparison = (
        compare_gemini_to_hybrid(
            build_three_mode_metrics()
        )
    )

    assert (
        comparison.baseline_mode
        == EvaluationMode.GEMINI_ONLY
    )

    assert (
        comparison.candidate_mode
        == EvaluationMode.HYBRID
    )


def test_compare_ml_to_hybrid_requires_ml():
    metrics = {
        EvaluationMode.HYBRID: (
            build_metrics(
                mode=EvaluationMode.HYBRID
            )
        )
    }

    with pytest.raises(
        ValueError,
        match=(
            "Missing metrics for ML_ONLY"
        ),
    ):
        compare_ml_to_hybrid(
            metrics
        )


def test_compare_ml_to_hybrid_requires_hybrid():
    metrics = {
        EvaluationMode.ML_ONLY: (
            build_metrics(
                mode=EvaluationMode.ML_ONLY
            )
        )
    }

    with pytest.raises(
        ValueError,
        match=(
            "Missing metrics for HYBRID"
        ),
    ):
        compare_ml_to_hybrid(
            metrics
        )


def test_metric_delta_contains_mode_identity():
    baseline = build_metrics(
        mode=EvaluationMode.ML_ONLY,
        accuracy=0.80,
    )

    candidate = build_metrics(
        mode=EvaluationMode.HYBRID,
        accuracy=0.90,
    )

    comparison = compare_modes(
        baseline=baseline,
        candidate=candidate,
    )

    delta = comparison.accuracy

    assert isinstance(
        delta,
        MetricDelta,
    )

    assert (
        delta.metric_name
        == "accuracy"
    )

    assert (
        delta.baseline_mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        delta.candidate_mode
        == EvaluationMode.HYBRID
    )


def test_tie_breaking_is_deterministic():
    metrics = {
        EvaluationMode.HYBRID: (
            build_metrics(
                mode=EvaluationMode.HYBRID,
                f1=0.90,
                recall=0.90,
                false_negative_rate=0.10,
                average_latency_ms=10.0,
            )
        ),

        EvaluationMode.ML_ONLY: (
            build_metrics(
                mode=EvaluationMode.ML_ONLY,
                f1=0.90,
                recall=0.90,
                false_negative_rate=0.10,
                average_latency_ms=10.0,
            )
        ),
    }

    comparison = (
        build_evaluation_comparison(
            metrics
        )
    )

    assert (
        comparison.best_f1_mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        comparison.best_recall_mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        comparison
        .lowest_false_negative_mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        comparison.lowest_latency_mode
        == EvaluationMode.ML_ONLY
    )