import pytest

from threat_triage.evaluation.metrics import (
    _compute_f1,
    _safe_divide,
    compute_evaluation_metrics,
    compute_metrics_by_mode,
)
from threat_triage.evaluation.models import (
    EvaluationDisposition,
    EvaluationLabel,
    EvaluationMode,
    EvaluationPrediction,
    EvaluationResult,
)


def make_result(
    *,
    sample_id: str,
    mode: EvaluationMode,
    actual: EvaluationLabel,
    predicted: EvaluationLabel | None,
    latency_ms: float = 10.0,
    agent_invoked: bool = False,
    error: str | None = None,
    threat_category: str | None = None,
) -> EvaluationResult:
    prediction = None

    if predicted is not None:
        prediction = EvaluationPrediction(
            predicted_label=predicted,
            confidence=0.90,
            disposition=(
                EvaluationDisposition
                .NOT_APPLICABLE
            ),
            threat_probability=(
                0.90
                if predicted
                == EvaluationLabel.THREAT
                else 0.10
            ),
        )

    metadata = {}

    if threat_category is not None:
        metadata[
            "threat_category"
        ] = threat_category

    return EvaluationResult(
        sample_id=sample_id,
        mode=mode,
        true_label=actual,
        prediction=prediction,
        latency_ms=latency_ms,
        agent_invoked=agent_invoked,
        error=error,
        metadata=metadata,
    )


def build_balanced_results():
    return [
        make_result(
            sample_id="tp-1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
        ),

        make_result(
            sample_id="tp-2",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
        ),

        make_result(
            sample_id="tn-1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
        ),

        make_result(
            sample_id="tn-2",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
        ),

        make_result(
            sample_id="fp-1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.THREAT,
        ),

        make_result(
            sample_id="fn-1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.BENIGN,
        ),
    ]


def test_safe_divide():
    assert (
        _safe_divide(
            4,
            2,
        )
        == 2.0
    )


def test_safe_divide_returns_zero_for_zero_denominator():
    assert (
        _safe_divide(
            10,
            0,
        )
        == 0.0
    )


def test_compute_f1():
    result = _compute_f1(
        precision=0.8,
        recall=0.5,
    )

    assert (
        result
        == pytest.approx(
            0.6153846154
        )
    )


def test_compute_f1_returns_zero_when_precision_and_recall_zero():
    assert (
        _compute_f1(
            precision=0.0,
            recall=0.0,
        )
        == 0.0
    )


def test_confusion_matrix_counts():
    metrics = (
        compute_evaluation_metrics(
            build_balanced_results(),
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.true_positive
        == 2
    )

    assert (
        metrics.true_negative
        == 2
    )

    assert (
        metrics.false_positive
        == 1
    )

    assert (
        metrics.false_negative
        == 1
    )


def test_accuracy():
    metrics = (
        compute_evaluation_metrics(
            build_balanced_results(),
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.accuracy
        == pytest.approx(
            4 / 6
        )
    )


def test_precision():
    metrics = (
        compute_evaluation_metrics(
            build_balanced_results(),
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.precision
        == pytest.approx(
            2 / 3
        )
    )


def test_recall():
    metrics = (
        compute_evaluation_metrics(
            build_balanced_results(),
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.recall
        == pytest.approx(
            2 / 3
        )
    )


def test_f1():
    metrics = (
        compute_evaluation_metrics(
            build_balanced_results(),
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.f1
        == pytest.approx(
            2 / 3
        )
    )


def test_false_positive_rate():
    metrics = (
        compute_evaluation_metrics(
            build_balanced_results(),
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.false_positive_rate
        == pytest.approx(
            1 / 3
        )
    )


def test_false_negative_rate():
    metrics = (
        compute_evaluation_metrics(
            build_balanced_results(),
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.false_negative_rate
        == pytest.approx(
            1 / 3
        )
    )


def test_total_successful_and_failed_samples():
    results = [
        make_result(
            sample_id="success",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
        ),

        make_result(
            sample_id="failure",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=None,
            error="RUNTIME_ERROR",
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        metrics.total_samples
        == 2
    )

    assert (
        metrics.successful_samples
        == 1
    )

    assert (
        metrics.failed_samples
        == 1
    )


def test_failed_sample_does_not_affect_confusion_matrix():
    results = [
        make_result(
            sample_id="tp",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
        ),

        make_result(
            sample_id="failed",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.BENIGN,
            predicted=None,
            error="MODEL_RESPONSE_ERROR",
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        metrics.true_positive
        == 1
    )

    assert (
        metrics.true_negative
        == 0
    )

    assert (
        metrics.false_positive
        == 0
    )

    assert (
        metrics.false_negative
        == 0
    )

    assert (
        metrics.accuracy
        == 1.0
    )


def test_agent_invocation_rate():
    results = [
        make_result(
            sample_id="1",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            agent_invoked=True,
        ),

        make_result(
            sample_id="2",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
            agent_invoked=False,
        ),

        make_result(
            sample_id="3",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            agent_invoked=True,
        ),

        make_result(
            sample_id="4",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
            agent_invoked=False,
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        metrics.agent_invocation_rate
        == 0.5
    )


def test_agent_invocation_rate_includes_failed_samples():
    results = [
        make_result(
            sample_id="success",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            agent_invoked=True,
        ),

        make_result(
            sample_id="failure",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=None,
            agent_invoked=True,
            error="RUNTIME_ERROR",
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        metrics.agent_invocation_rate
        == 1.0
    )


def test_average_latency():
    results = [
        make_result(
            sample_id="1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
            latency_ms=10.0,
        ),

        make_result(
            sample_id="2",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            latency_ms=30.0,
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.average_latency_ms
        == 20.0
    )


def test_average_latency_includes_failed_samples():
    results = [
        make_result(
            sample_id="success",
            mode=EvaluationMode.GEMINI_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            latency_ms=100.0,
        ),

        make_result(
            sample_id="failure",
            mode=EvaluationMode.GEMINI_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=None,
            latency_ms=300.0,
            error="RATE_LIMIT_ERROR",
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.GEMINI_ONLY,
        )
    )

    assert (
        metrics.average_latency_ms
        == 200.0
    )


def test_phishing_recall():
    results = [
        make_result(
            sample_id="phish-1",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            threat_category="PHISHING",
        ),

        make_result(
            sample_id="phish-2",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.BENIGN,
            threat_category="PHISHING",
        ),

        make_result(
            sample_id="malware",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            threat_category="MALWARE",
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        metrics.phishing_recall
        == 0.5
    )


@pytest.mark.parametrize(
    "category",
    [
        "PHISHING",
        "phishing",
        "Credential_Phishing",
        "CREDENTIAL_THEFT",
    ],
)
def test_phishing_categories_are_normalized(
    category,
):
    results = [
        make_result(
            sample_id="phish",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            threat_category=category,
        )
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        metrics.phishing_recall
        == 1.0
    )


def test_phishing_recall_none_without_phishing_samples():
    results = [
        make_result(
            sample_id="malware",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            threat_category="MALWARE",
        )
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        metrics.phishing_recall
        is None
    )


def test_no_results_for_requested_mode_rejected():
    results = [
        make_result(
            sample_id="1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
        )
    ]

    with pytest.raises(
        ValueError,
        match=(
            "No evaluation results found "
            "for requested mode"
        ),
    ):
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )


def test_compute_metrics_by_mode():
    results = [
        make_result(
            sample_id="ml-1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
        ),

        make_result(
            sample_id="hybrid-1",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
            agent_invoked=True,
        ),
    ]

    metrics = compute_metrics_by_mode(
        results
    )

    assert set(
        metrics.keys()
    ) == {
        EvaluationMode.ML_ONLY,
        EvaluationMode.HYBRID,
    }

    assert (
        metrics[
            EvaluationMode.ML_ONLY
        ].accuracy
        == 1.0
    )

    assert (
        metrics[
            EvaluationMode.HYBRID
        ].recall
        == 1.0
    )


def test_compute_metrics_by_mode_rejects_empty_results():
    with pytest.raises(
        ValueError,
        match="results must not be empty",
    ):
        compute_metrics_by_mode(
            []
        )


def test_metrics_are_isolated_by_mode():
    results = [
        make_result(
            sample_id="ml",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.BENIGN,
        ),

        make_result(
            sample_id="hybrid",
            mode=EvaluationMode.HYBRID,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.THREAT,
        ),
    ]

    ml_metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.ML_ONLY,
        )
    )

    hybrid_metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.HYBRID,
        )
    )

    assert (
        ml_metrics.false_negative
        == 1
    )

    assert (
        hybrid_metrics.true_positive
        == 1
    )


def test_no_positive_predictions_precision_is_zero():
    results = [
        make_result(
            sample_id="1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
        ),

        make_result(
            sample_id="2",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.THREAT,
            predicted=EvaluationLabel.BENIGN,
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.precision
        == 0.0
    )


def test_no_actual_positive_samples_recall_is_zero():
    results = [
        make_result(
            sample_id="1",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.BENIGN,
        ),

        make_result(
            sample_id="2",
            mode=EvaluationMode.ML_ONLY,
            actual=EvaluationLabel.BENIGN,
            predicted=EvaluationLabel.THREAT,
        ),
    ]

    metrics = (
        compute_evaluation_metrics(
            results,
            mode=EvaluationMode.ML_ONLY,
        )
    )

    assert (
        metrics.recall
        == 0.0
    )

    assert (
        metrics.false_negative_rate
        == 0.0
    )