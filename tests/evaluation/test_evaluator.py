import asyncio

import pytest

from threat_triage.evaluation.evaluator import (
    evaluate_batch,
    evaluate_gemini_sample,
    evaluate_hybrid_sample,
    evaluate_ml_sample,
    evaluate_sample,
)
from threat_triage.evaluation.models import (
    EvaluationDisposition,
    EvaluationLabel,
    EvaluationMode,
    EvaluationPrediction,
    EvaluationSample,
)


def build_sample(
    *,
    sample_id: str = "sample-001",
    true_label: EvaluationLabel = (
        EvaluationLabel.THREAT
    ),
    threat_category: str | None = (
        "PHISHING"
    ),
    source: str | None = "unit-test",
) -> EvaluationSample:
    return EvaluationSample(
        sample_id=sample_id,
        subject=(
            "Account verification required"
        ),
        body=(
            "Verify your account."
        ),
        sender=(
            "security@example.test"
        ),
        true_label=true_label,
        urls=(
            "https://example.test/login",
        ),
        threat_category=(
            threat_category
        ),
        source=source,
    )


def build_prediction(
    *,
    label: EvaluationLabel = (
        EvaluationLabel.THREAT
    ),
) -> EvaluationPrediction:
    return EvaluationPrediction(
        predicted_label=label,
        confidence=0.90,
        disposition=(
            EvaluationDisposition.QUARANTINE
            if label == EvaluationLabel.THREAT
            else EvaluationDisposition.ALLOW
        ),
        threat_probability=(
            0.90
            if label == EvaluationLabel.THREAT
            else 0.10
        ),
        explanation=(
            "Evaluation prediction."
        ),
    )


@pytest.mark.anyio
async def test_evaluate_sample_with_sync_executor():
    sample = build_sample()

    def executor(
        value: EvaluationSample,
    ) -> EvaluationPrediction:
        assert value is sample

        return build_prediction()

    result = await evaluate_sample(
        sample,
        mode=EvaluationMode.ML_ONLY,
        executor=executor,
        agent_invoked=False,
    )

    assert (
        result.sample_id
        == sample.sample_id
    )

    assert (
        result.mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        result.true_label
        == EvaluationLabel.THREAT
    )

    assert (
        result.prediction
        is not None
    )

    assert (
        result.prediction.predicted_label
        == EvaluationLabel.THREAT
    )

    assert result.error is None


@pytest.mark.anyio
async def test_evaluate_sample_with_async_executor():
    sample = build_sample()

    async def executor(
        value: EvaluationSample,
    ) -> EvaluationPrediction:
        await asyncio.sleep(
            0
        )

        assert value is sample

        return build_prediction()

    result = await evaluate_sample(
        sample,
        mode=EvaluationMode.GEMINI_ONLY,
        executor=executor,
    )

    assert (
        result.prediction
        is not None
    )

    assert (
        result.mode
        == EvaluationMode.GEMINI_ONLY
    )

    assert result.error is None


@pytest.mark.anyio
async def test_ml_sample_never_marks_agent_invoked():
    result = await evaluate_ml_sample(
        build_sample(),
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert (
        result.mode
        == EvaluationMode.ML_ONLY
    )

    assert (
        result.agent_invoked
        is False
    )


@pytest.mark.anyio
async def test_gemini_sample_marks_agent_invoked():
    async def executor(
        _: EvaluationSample,
    ) -> EvaluationPrediction:
        return build_prediction()

    result = await evaluate_gemini_sample(
        build_sample(),
        executor=executor,
    )

    assert (
        result.mode
        == EvaluationMode.GEMINI_ONLY
    )

    assert (
        result.agent_invoked
        is True
    )


@pytest.mark.anyio
async def test_hybrid_sample_can_invoke_agent():
    result = await evaluate_hybrid_sample(
        build_sample(),
        executor=lambda _: (
            build_prediction()
        ),
        agent_invoked=True,
    )

    assert (
        result.mode
        == EvaluationMode.HYBRID
    )

    assert (
        result.agent_invoked
        is True
    )


@pytest.mark.anyio
async def test_hybrid_sample_can_skip_agent():
    result = await evaluate_hybrid_sample(
        build_sample(),
        executor=lambda _: (
            build_prediction()
        ),
        agent_invoked=False,
    )

    assert (
        result.mode
        == EvaluationMode.HYBRID
    )

    assert (
        result.agent_invoked
        is False
    )


@pytest.mark.anyio
async def test_sample_metadata_is_preserved():
    sample = build_sample(
        threat_category=(
            "CREDENTIAL_PHISHING"
        ),
        source="evaluation-dataset",
    )

    result = await evaluate_ml_sample(
        sample,
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert result.metadata == {
        "threat_category": (
            "CREDENTIAL_PHISHING"
        ),
        "source": (
            "evaluation-dataset"
        ),
    }


@pytest.mark.anyio
async def test_none_metadata_is_not_added():
    sample = build_sample(
        threat_category=None,
        source=None,
    )

    result = await evaluate_ml_sample(
        sample,
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert (
        result.metadata
        == {}
    )


@pytest.mark.anyio
async def test_latency_is_recorded():
    async def executor(
        _: EvaluationSample,
    ) -> EvaluationPrediction:
        await asyncio.sleep(
            0.001
        )

        return build_prediction()

    result = await evaluate_gemini_sample(
        build_sample(),
        executor=executor,
    )

    assert (
        result.latency_ms
        >= 0.0
    )


@pytest.mark.anyio
async def test_executor_exception_becomes_failed_result():
    def executor(
        _: EvaluationSample,
    ) -> EvaluationPrediction:
        raise RuntimeError(
            "provider unavailable"
        )

    result = await evaluate_sample(
        build_sample(),
        mode=EvaluationMode.GEMINI_ONLY,
        executor=executor,
    )

    assert (
        result.prediction
        is None
    )

    assert (
        result.error
        == (
            "RuntimeError: "
            "provider unavailable"
        )
    )

    assert (
        result.agent_invoked
        is True
    )


@pytest.mark.anyio
async def test_empty_exception_message_is_supported():
    def executor(
        _: EvaluationSample,
    ) -> EvaluationPrediction:
        raise RuntimeError()

    result = await evaluate_gemini_sample(
        build_sample(),
        executor=executor,
    )

    assert (
        result.error
        == "RuntimeError"
    )


@pytest.mark.anyio
async def test_invalid_executor_return_type_becomes_failure():
    def executor(
        _: EvaluationSample,
    ):
        return {
            "predicted_label": (
                "THREAT"
            )
        }

    result = await evaluate_ml_sample(
        build_sample(),
        executor=executor,
    )

    assert (
        result.prediction
        is None
    )

    assert result.error == (
        "TypeError: "
        "Evaluation executor must return "
        "EvaluationPrediction"
    )


@pytest.mark.anyio
async def test_batch_evaluates_every_sample():
    samples = [
        build_sample(
            sample_id="sample-001"
        ),
        build_sample(
            sample_id="sample-002"
        ),
        build_sample(
            sample_id="sample-003"
        ),
    ]

    results = await evaluate_batch(
        samples,
        mode=EvaluationMode.ML_ONLY,
        executor=lambda _: (
            build_prediction()
        ),
        agent_invoked=False,
    )

    assert (
        len(results)
        == 3
    )

    assert [
        result.sample_id
        for result in results
    ] == [
        "sample-001",
        "sample-002",
        "sample-003",
    ]


@pytest.mark.anyio
async def test_batch_preserves_order():
    samples = [
        build_sample(
            sample_id="a"
        ),
        build_sample(
            sample_id="b"
        ),
        build_sample(
            sample_id="c"
        ),
    ]

    results = await evaluate_batch(
        samples,
        mode=EvaluationMode.ML_ONLY,
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert [
        result.sample_id
        for result in results
    ] == [
        "a",
        "b",
        "c",
    ]


@pytest.mark.anyio
async def test_batch_continues_after_executor_failure():
    samples = [
        build_sample(
            sample_id="success-1"
        ),
        build_sample(
            sample_id="failure"
        ),
        build_sample(
            sample_id="success-2"
        ),
    ]

    def executor(
        sample: EvaluationSample,
    ) -> EvaluationPrediction:
        if (
            sample.sample_id
            == "failure"
        ):
            raise RuntimeError(
                "temporary failure"
            )

        return build_prediction()

    results = await evaluate_batch(
        samples,
        mode=EvaluationMode.HYBRID,
        executor=executor,
        agent_invoked=True,
    )

    assert (
        len(results)
        == 3
    )

    assert (
        results[0].error
        is None
    )

    assert (
        results[1].error
        == (
            "RuntimeError: "
            "temporary failure"
        )
    )

    assert (
        results[2].error
        is None
    )


@pytest.mark.anyio
async def test_batch_accepts_generator():
    samples = (
        build_sample(
            sample_id=f"sample-{index}"
        )
        for index in range(
            3
        )
    )

    results = await evaluate_batch(
        samples,
        mode=EvaluationMode.ML_ONLY,
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert (
        len(results)
        == 3
    )


@pytest.mark.anyio
async def test_batch_empty_input_returns_empty_list():
    results = await evaluate_batch(
        [],
        mode=EvaluationMode.ML_ONLY,
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert (
        results
        == []
    )


@pytest.mark.anyio
async def test_generic_hybrid_defaults_agent_invoked_true():
    result = await evaluate_sample(
        build_sample(),
        mode=EvaluationMode.HYBRID,
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert (
        result.agent_invoked
        is True
    )


@pytest.mark.anyio
async def test_generic_ml_defaults_agent_invoked_false():
    result = await evaluate_sample(
        build_sample(),
        mode=EvaluationMode.ML_ONLY,
        executor=lambda _: (
            build_prediction()
        ),
    )

    assert (
        result.agent_invoked
        is False
    )


@pytest.mark.anyio
async def test_explicit_agent_invoked_overrides_default():
    result = await evaluate_sample(
        build_sample(),
        mode=EvaluationMode.HYBRID,
        executor=lambda _: (
            build_prediction()
        ),
        agent_invoked=False,
    )

    assert (
        result.agent_invoked
        is False
    )