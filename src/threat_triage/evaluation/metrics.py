from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

from threat_triage.evaluation.models import (
    EvaluationLabel,
    EvaluationMetrics,
    EvaluationMode,
    EvaluationResult,
)


def compute_evaluation_metrics(
    results: Sequence[EvaluationResult]
    | Iterable[EvaluationResult],
    *,
    mode: EvaluationMode,
) -> EvaluationMetrics:
    """
    Compute aggregate evaluation metrics for one execution mode.

    THREAT is treated as the positive class.

    Failed samples:
        - count toward total_samples,
        - count toward failed_samples,
        - do not contribute to confusion-matrix counts,
        - do not contribute to classification metrics,
        - still contribute to agent invocation rate,
        - still contribute to average latency.

    This separation lets us distinguish:

        model quality
        vs.
        runtime reliability
    """

    normalized_results = list(
        results
    )

    selected = [
        result
        for result in normalized_results
        if result.mode == mode
    ]

    if not selected:
        raise ValueError(
            "No evaluation results found "
            "for requested mode"
        )

    total_samples = len(
        selected
    )

    successful_results = [
        result
        for result in selected
        if (
            result.prediction is not None
            and result.error is None
        )
    ]

    failed_results = [
        result
        for result in selected
        if result.error is not None
    ]

    successful_samples = len(
        successful_results
    )

    failed_samples = len(
        failed_results
    )

    if (
        successful_samples
        + failed_samples
        != total_samples
    ):
        raise ValueError(
            "Every evaluation result must be "
            "either successful or failed"
        )

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for result in successful_results:
        predicted = (
            result
            .prediction
            .predicted_label
        )

        actual = (
            result.true_label
        )

        if (
            actual == EvaluationLabel.THREAT
            and predicted == EvaluationLabel.THREAT
        ):
            true_positive += 1

        elif (
            actual == EvaluationLabel.BENIGN
            and predicted == EvaluationLabel.BENIGN
        ):
            true_negative += 1

        elif (
            actual == EvaluationLabel.BENIGN
            and predicted == EvaluationLabel.THREAT
        ):
            false_positive += 1

        elif (
            actual == EvaluationLabel.THREAT
            and predicted == EvaluationLabel.BENIGN
        ):
            false_negative += 1

    accuracy = _safe_divide(
        true_positive + true_negative,
        successful_samples,
    )

    precision = _safe_divide(
        true_positive,
        true_positive + false_positive,
    )

    recall = _safe_divide(
        true_positive,
        true_positive + false_negative,
    )

    f1 = _compute_f1(
        precision=precision,
        recall=recall,
    )

    false_positive_rate = _safe_divide(
        false_positive,
        false_positive + true_negative,
    )

    false_negative_rate = _safe_divide(
        false_negative,
        false_negative + true_positive,
    )

    agent_invocation_rate = _safe_divide(
        sum(
            1
            for result in selected
            if result.agent_invoked
        ),
        total_samples,
    )

    average_latency_ms = _safe_divide(
        sum(
            result.latency_ms
            for result in selected
        ),
        total_samples,
    )

    phishing_recall = (
        _compute_phishing_recall(
            successful_results
        )
    )

    return EvaluationMetrics(
        mode=mode,

        total_samples=total_samples,
        successful_samples=successful_samples,
        failed_samples=failed_samples,

        true_positive=true_positive,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,

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


def compute_metrics_by_mode(
    results: Sequence[EvaluationResult]
    | Iterable[EvaluationResult],
) -> dict[
    EvaluationMode,
    EvaluationMetrics,
]:
    """
    Compute EvaluationMetrics for every mode represented
    in the result set.
    """

    normalized_results = list(
        results
    )

    if not normalized_results:
        raise ValueError(
            "results must not be empty"
        )

    grouped: dict[
        EvaluationMode,
        list[EvaluationResult],
    ] = defaultdict(
        list
    )

    for result in normalized_results:
        grouped[
            result.mode
        ].append(
            result
        )

    return {
        mode: compute_evaluation_metrics(
            mode_results,
            mode=mode,
        )
        for mode, mode_results
        in grouped.items()
    }


def _compute_phishing_recall(
    successful_results: Sequence[
        EvaluationResult
    ],
) -> float | None:
    """
    Compute phishing-specific recall when threat-category metadata
    is available.

    The evaluation runner will later preserve sample metadata using:

        metadata["threat_category"]

    A sample is considered phishing when the normalized category is:

        PHISHING
        CREDENTIAL_PHISHING
        CREDENTIAL_THEFT

    If no phishing samples exist in the result set, None is returned.
    """

    phishing_total = 0
    phishing_detected = 0

    accepted_categories = {
        "PHISHING",
        "CREDENTIAL_PHISHING",
        "CREDENTIAL_THEFT",
    }

    for result in successful_results:
        raw_category = (
            result.metadata.get(
                "threat_category"
            )
        )

        if raw_category is None:
            continue

        normalized_category = str(
            raw_category
        ).strip().upper()

        if (
            normalized_category
            not in accepted_categories
        ):
            continue

        phishing_total += 1

        if (
            result.prediction
            is not None
            and (
                result
                .prediction
                .predicted_label
                == EvaluationLabel.THREAT
            )
        ):
            phishing_detected += 1

    if phishing_total == 0:
        return None

    return _safe_divide(
        phishing_detected,
        phishing_total,
    )


def _safe_divide(
    numerator: float,
    denominator: float,
) -> float:
    """
    Divide safely for evaluation metrics.

    Metrics whose denominator is zero are reported as 0.0.
    """

    if denominator == 0:
        return 0.0

    return float(
        numerator
        / denominator
    )


def _compute_f1(
    *,
    precision: float,
    recall: float,
) -> float:
    """
    Compute the harmonic mean of precision and recall.
    """

    denominator = (
        precision
        + recall
    )

    if denominator == 0:
        return 0.0

    return (
        2.0
        * precision
        * recall
        / denominator
    )