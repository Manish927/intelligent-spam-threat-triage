import pytest

from threat_triage.evaluation.models import (
    EvaluationComparison,
    EvaluationDisposition,
    EvaluationLabel,
    EvaluationMetrics,
    EvaluationMode,
    EvaluationPrediction,
    EvaluationResult,
    EvaluationSample,
)


def test_evaluation_modes_are_stable():
    assert (
        EvaluationMode.ML_ONLY.value
        == "ML_ONLY"
    )

    assert (
        EvaluationMode.GEMINI_ONLY.value
        == "GEMINI_ONLY"
    )

    assert (
        EvaluationMode.HYBRID.value
        == "HYBRID"
    )


def test_evaluation_labels_are_stable():
    assert (
        EvaluationLabel.BENIGN.value
        == "BENIGN"
    )

    assert (
        EvaluationLabel.THREAT.value
        == "THREAT"
    )


def test_dispositions_are_stable():
    assert (
        EvaluationDisposition.NOT_APPLICABLE.value
        == "NOT_APPLICABLE"
    )

    assert (
        EvaluationDisposition.ALLOW.value
        == "ALLOW"
    )

    assert (
        EvaluationDisposition.MONITOR.value
        == "MONITOR"
    )

    assert (
        EvaluationDisposition.QUARANTINE.value
        == "QUARANTINE"
    )

    assert (
        EvaluationDisposition.HUMAN_REVIEW.value
        == "HUMAN_REVIEW"
    )


def test_evaluation_sample_creation():
    sample = EvaluationSample(
        sample_id="sample-001",
        subject="Account update",
        body="Please review your account.",
        sender="support@example.com",
        true_label=EvaluationLabel.BENIGN,
        urls=(
            "https://example.com",
        ),
        source="test",
    )

    assert (
        sample.sample_id
        == "sample-001"
    )

    assert (
        sample.true_label
        == EvaluationLabel.BENIGN
    )

    assert (
        sample.urls
        == (
            "https://example.com",
        )
    )


def test_evaluation_sample_defaults():
    sample = EvaluationSample(
        sample_id="sample-001",
        subject=None,
        body=None,
        sender=None,
        true_label=EvaluationLabel.THREAT,
    )

    assert sample.urls == ()
    assert sample.threat_category is None
    assert sample.source is None


def test_evaluation_sample_rejects_empty_id():
    with pytest.raises(
        ValueError,
        match="sample_id must not be empty",
    ):
        EvaluationSample(
            sample_id="",
            subject=None,
            body=None,
            sender=None,
            true_label=EvaluationLabel.BENIGN,
        )


def test_prediction_creation():
    prediction = EvaluationPrediction(
        predicted_label=EvaluationLabel.THREAT,
        confidence=0.95,
        disposition=(
            EvaluationDisposition.QUARANTINE
        ),
        threat_probability=0.93,
        explanation="Strong phishing evidence.",
    )

    assert (
        prediction.predicted_label
        == EvaluationLabel.THREAT
    )

    assert (
        prediction.confidence
        == 0.95
    )

    assert (
        prediction.threat_probability
        == 0.93
    )


def test_prediction_defaults_to_not_applicable_disposition():
    prediction = EvaluationPrediction(
        predicted_label=EvaluationLabel.BENIGN,
        confidence=0.80,
    )

    assert (
        prediction.disposition
        == (
            EvaluationDisposition
            .NOT_APPLICABLE
        )
    )


@pytest.mark.parametrize(
    "confidence",
    [
        -0.01,
        1.01,
    ],
)
def test_prediction_rejects_invalid_confidence(
    confidence,
):
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        EvaluationPrediction(
            predicted_label=EvaluationLabel.THREAT,
            confidence=confidence,
        )


@pytest.mark.parametrize(
    "probability",
    [
        -0.01,
        1.01,
    ],
)
def test_prediction_rejects_invalid_threat_probability(
    probability,
):
    with pytest.raises(
        ValueError,
        match=(
            "threat_probability must be "
            "between 0 and 1"
        ),
    ):
        EvaluationPrediction(
            predicted_label=EvaluationLabel.THREAT,
            confidence=0.90,
            threat_probability=probability,
        )


def test_result_creation_with_prediction():
    prediction = EvaluationPrediction(
        predicted_label=EvaluationLabel.THREAT,
        confidence=0.90,
    )

    result = EvaluationResult(
        sample_id="sample-001",
        mode=EvaluationMode.HYBRID,
        true_label=EvaluationLabel.THREAT,
        prediction=prediction,
        latency_ms=125.5,
        agent_invoked=True,
    )

    assert (
        result.mode
        == EvaluationMode.HYBRID
    )

    assert (
        result.prediction
        is prediction
    )

    assert result.error is None


def test_result_creation_with_error():
    result = EvaluationResult(
        sample_id="sample-001",
        mode=EvaluationMode.GEMINI_ONLY,
        true_label=EvaluationLabel.THREAT,
        prediction=None,
        latency_ms=100.0,
        agent_invoked=True,
        error="MODEL_RESPONSE_ERROR",
    )

    assert result.prediction is None

    assert (
        result.error
        == "MODEL_RESPONSE_ERROR"
    )


def test_result_rejects_empty_sample_id():
    with pytest.raises(
        ValueError,
        match="sample_id must not be empty",
    ):
        EvaluationResult(
            sample_id="",
            mode=EvaluationMode.ML_ONLY,
            true_label=EvaluationLabel.BENIGN,
            prediction=EvaluationPrediction(
                predicted_label=(
                    EvaluationLabel.BENIGN
                ),
                confidence=0.90,
            ),
            latency_ms=1.0,
            agent_invoked=False,
        )


def test_result_rejects_negative_latency():
    with pytest.raises(
        ValueError,
        match="latency_ms must not be negative",
    ):
        EvaluationResult(
            sample_id="sample-001",
            mode=EvaluationMode.ML_ONLY,
            true_label=EvaluationLabel.BENIGN,
            prediction=EvaluationPrediction(
                predicted_label=(
                    EvaluationLabel.BENIGN
                ),
                confidence=0.90,
            ),
            latency_ms=-1.0,
            agent_invoked=False,
        )


def test_result_requires_prediction_or_error():
    with pytest.raises(
        ValueError,
        match="prediction or error must be provided",
    ):
        EvaluationResult(
            sample_id="sample-001",
            mode=EvaluationMode.ML_ONLY,
            true_label=EvaluationLabel.BENIGN,
            prediction=None,
            latency_ms=1.0,
            agent_invoked=False,
            error=None,
        )


def test_result_rejects_prediction_and_error_together():
    with pytest.raises(
        ValueError,
        match=(
            "prediction and error cannot "
            "both be provided"
        ),
    ):
        EvaluationResult(
            sample_id="sample-001",
            mode=EvaluationMode.ML_ONLY,
            true_label=EvaluationLabel.BENIGN,
            prediction=EvaluationPrediction(
                predicted_label=(
                    EvaluationLabel.BENIGN
                ),
                confidence=0.90,
            ),
            latency_ms=1.0,
            agent_invoked=False,
            error="unexpected",
        )


def build_metrics(
    *,
    mode=EvaluationMode.HYBRID,
):
    return EvaluationMetrics(
        mode=mode,

        total_samples=100,
        successful_samples=98,
        failed_samples=2,

        true_positive=40,
        true_negative=50,
        false_positive=5,
        false_negative=3,

        accuracy=0.918,
        precision=0.889,
        recall=0.930,
        f1=0.909,

        false_positive_rate=0.091,
        false_negative_rate=0.070,

        phishing_recall=0.95,

        agent_invocation_rate=0.25,

        average_latency_ms=120.0,
    )


def test_metrics_creation():
    metrics = build_metrics()

    assert (
        metrics.mode
        == EvaluationMode.HYBRID
    )

    assert (
        metrics.total_samples
        == 100
    )

    assert (
        metrics.f1
        == 0.909
    )


def test_metrics_allow_none_phishing_recall():
    metrics = EvaluationMetrics(
        mode=EvaluationMode.ML_ONLY,

        total_samples=10,
        successful_samples=10,
        failed_samples=0,

        true_positive=4,
        true_negative=5,
        false_positive=1,
        false_negative=0,

        accuracy=0.9,
        precision=0.8,
        recall=1.0,
        f1=0.889,

        false_positive_rate=(
            1.0 / 6.0
        ),

        false_negative_rate=0.0,

        phishing_recall=None,

        agent_invocation_rate=0.0,

        average_latency_ms=2.0,
    )

    assert (
        metrics.phishing_recall
        is None
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "total_samples",
        "successful_samples",
        "failed_samples",
        "true_positive",
        "true_negative",
        "false_positive",
        "false_negative",
    ],
)
def test_metrics_reject_negative_integer_fields(
    field_name,
):
    values = {
        "mode": EvaluationMode.HYBRID,

        "total_samples": 10,
        "successful_samples": 10,
        "failed_samples": 0,

        "true_positive": 4,
        "true_negative": 5,
        "false_positive": 1,
        "false_negative": 0,

        "accuracy": 0.9,
        "precision": 0.8,
        "recall": 1.0,
        "f1": 0.889,

        "false_positive_rate": 0.1,
        "false_negative_rate": 0.0,

        "agent_invocation_rate": 0.2,

        "average_latency_ms": 10.0,
    }

    values[field_name] = -1

    with pytest.raises(
        ValueError,
        match=f"{field_name} must not be negative",
    ):
        EvaluationMetrics(
            **values
        )


def test_metrics_require_success_and_failure_to_equal_total():
    with pytest.raises(
        ValueError,
        match=(
            "successful_samples \\+ "
            "failed_samples must equal "
            "total_samples"
        ),
    ):
        EvaluationMetrics(
            mode=EvaluationMode.HYBRID,

            total_samples=10,
            successful_samples=8,
            failed_samples=1,

            true_positive=3,
            true_negative=4,
            false_positive=1,
            false_negative=0,

            accuracy=0.875,
            precision=0.75,
            recall=1.0,
            f1=0.857,

            false_positive_rate=0.2,
            false_negative_rate=0.0,

            agent_invocation_rate=0.2,

            average_latency_ms=10.0,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "agent_invocation_rate",
        "phishing_recall",
    ],
)
def test_metrics_reject_out_of_range_metrics(
    field_name,
):
    values = {
        "mode": EvaluationMode.HYBRID,

        "total_samples": 10,
        "successful_samples": 10,
        "failed_samples": 0,

        "true_positive": 4,
        "true_negative": 5,
        "false_positive": 1,
        "false_negative": 0,

        "accuracy": 0.9,
        "precision": 0.8,
        "recall": 1.0,
        "f1": 0.889,

        "false_positive_rate": 0.1,
        "false_negative_rate": 0.0,

        "phishing_recall": 0.9,

        "agent_invocation_rate": 0.2,

        "average_latency_ms": 10.0,
    }

    values[field_name] = 1.1

    with pytest.raises(
        ValueError,
        match=(
            f"{field_name} must be "
            "between 0 and 1"
        ),
    ):
        EvaluationMetrics(
            **values
        )


def test_metrics_reject_negative_average_latency():
    values = build_metrics()

    with pytest.raises(
        ValueError,
        match=(
            "average_latency_ms "
            "must not be negative"
        ),
    ):
        EvaluationMetrics(
            mode=values.mode,

            total_samples=values.total_samples,
            successful_samples=(
                values.successful_samples
            ),
            failed_samples=values.failed_samples,

            true_positive=values.true_positive,
            true_negative=values.true_negative,
            false_positive=values.false_positive,
            false_negative=values.false_negative,

            accuracy=values.accuracy,
            precision=values.precision,
            recall=values.recall,
            f1=values.f1,

            false_positive_rate=(
                values.false_positive_rate
            ),

            false_negative_rate=(
                values.false_negative_rate
            ),

            phishing_recall=(
                values.phishing_recall
            ),

            agent_invocation_rate=(
                values.agent_invocation_rate
            ),

            average_latency_ms=-1.0,
        )


def test_comparison_creation():
    ml_metrics = build_metrics(
        mode=EvaluationMode.ML_ONLY
    )

    hybrid_metrics = build_metrics(
        mode=EvaluationMode.HYBRID
    )

    comparison = EvaluationComparison(
        metrics_by_mode={
            EvaluationMode.ML_ONLY: (
                ml_metrics
            ),
            EvaluationMode.HYBRID: (
                hybrid_metrics
            ),
        },

        best_f1_mode=(
            EvaluationMode.HYBRID
        ),

        best_recall_mode=(
            EvaluationMode.HYBRID
        ),

        lowest_false_negative_mode=(
            EvaluationMode.HYBRID
        ),

        lowest_latency_mode=(
            EvaluationMode.ML_ONLY
        ),
    )

    assert (
        len(comparison.metrics_by_mode)
        == 2
    )

    assert (
        comparison.best_f1_mode
        == EvaluationMode.HYBRID
    )


def test_comparison_rejects_empty_metrics():
    with pytest.raises(
        ValueError,
        match="metrics_by_mode must not be empty",
    ):
        EvaluationComparison(
            metrics_by_mode={}
        )