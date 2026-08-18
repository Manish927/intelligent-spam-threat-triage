import pytest

from threat_triage.agents.models import (
    AgentDisposition,
    AgentModelMetadata,
    AgentRecommendation,
    AgentReviewResult,
)
from threat_triage.evaluation.adapters import (
    HybridEvaluationAdapter,
    MLArtifactAdapter,
    _evaluation_disposition_from_agent,
    _label_from_agent_disposition,
)
from threat_triage.evaluation.models import (
    EvaluationDisposition,
    EvaluationLabel,
    EvaluationSample,
)


class FakeProbabilityModel:
    def __init__(
        self,
        probability: float,
    ):
        self.probability = probability

        self.last_input = None

    def predict_proba(
        self,
        values,
    ):
        self.last_input = values

        return [
            [
                1.0 - self.probability,
                self.probability,
            ]
        ]


def build_sample(
    *,
    sample_id: str = "sample-001",
    subject: str | None = (
        "Account verification"
    ),
    body: str | None = (
        "Please verify your account."
    ),
    sender: str | None = (
        "support@example.com"
    ),
) -> EvaluationSample:
    return EvaluationSample(
        sample_id=sample_id,
        subject=subject,
        body=body,
        sender=sender,
        true_label=(
            EvaluationLabel.THREAT
        ),
    )


def test_ml_adapter_builds_combined_text():
    model = FakeProbabilityModel(
        0.90
    )

    adapter = MLArtifactAdapter(
        model=model
    )

    sample = build_sample(
        subject="Subject",
        body="Body",
    )

    text = adapter.build_model_text(
        sample
    )

    assert text == (
        "Subject\nBody"
    )


def test_ml_adapter_handles_missing_subject():
    adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.1
        )
    )

    sample = build_sample(
        subject=None,
        body="Body",
    )

    assert (
        adapter.build_model_text(
            sample
        )
        == "Body"
    )


def test_ml_adapter_handles_missing_body():
    adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.1
        )
    )

    sample = build_sample(
        subject="Subject",
        body=None,
    )

    assert (
        adapter.build_model_text(
            sample
        )
        == "Subject"
    )


def test_ml_adapter_predicts_threat():
    adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.90
        ),
        decision_threshold=0.70,
    )

    prediction = adapter.evaluate(
        build_sample()
    )

    assert (
        prediction.predicted_label
        == EvaluationLabel.THREAT
    )

    assert (
        prediction.threat_probability
        == 0.90
    )

    assert (
        prediction.confidence
        == 0.90
    )


def test_ml_adapter_predicts_benign():
    adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.10
        ),
        decision_threshold=0.70,
    )

    prediction = adapter.evaluate(
        build_sample()
    )

    assert (
        prediction.predicted_label
        == EvaluationLabel.BENIGN
    )

    assert (
        prediction.confidence
        == pytest.approx(
            0.90
        )
    )


def test_ml_adapter_uses_not_applicable_disposition():
    adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.90
        )
    )

    prediction = adapter.evaluate(
        build_sample()
    )

    assert (
        prediction.disposition
        == (
            EvaluationDisposition
            .NOT_APPLICABLE
        )
    )


def test_ml_adapter_builds_ml_evidence():
    adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.91
        ),
        decision_threshold=0.70,
        model_name="test-model",
        model_version="9.0",
    )

    evidence = (
        adapter.build_ml_evidence(
            build_sample()
        )
    )

    assert (
        evidence.predicted_label
        == "THREAT"
    )

    assert (
        evidence.threat_probability
        == 0.91
    )

    assert (
        evidence.decision_threshold
        == 0.70
    )

    assert (
        evidence.model_name
        == "test-model"
    )

    assert (
        evidence.model_version
        == "9.0"
    )


@pytest.mark.parametrize(
    "threshold",
    [
        -0.01,
        1.01,
    ],
)
def test_ml_adapter_rejects_invalid_threshold(
    threshold,
):
    with pytest.raises(
        ValueError,
        match=(
            "decision_threshold must be "
            "between 0 and 1"
        ),
    ):
        MLArtifactAdapter(
            model=FakeProbabilityModel(
                0.5
            ),
            decision_threshold=threshold,
        )


def test_ml_adapter_requires_predict_proba():
    with pytest.raises(
        TypeError,
        match=(
            "model must provide "
            "predict_proba"
        ),
    ):
        MLArtifactAdapter(
            model=object()
        )


def test_ml_adapter_rejects_bad_probability_shape():
    class BadModel:
        def predict_proba(
            self,
            values,
        ):
            return [
                [
                    1.0
                ]
            ]

    adapter = MLArtifactAdapter(
        model=BadModel()
    )

    with pytest.raises(
        ValueError,
        match=(
            "predict_proba returned "
            "an unsupported result"
        ),
    ):
        adapter.evaluate(
            build_sample()
        )


def test_ml_adapter_rejects_out_of_range_probability():
    class BadModel:
        def predict_proba(
            self,
            values,
        ):
            return [
                [
                    -0.2,
                    1.2,
                ]
            ]

    adapter = MLArtifactAdapter(
        model=BadModel()
    )

    with pytest.raises(
        ValueError,
        match=(
            "model threat probability must "
            "be between 0 and 1"
        ),
    ):
        adapter.evaluate(
            build_sample()
        )


def test_agent_allow_maps_to_benign():
    assert (
        _label_from_agent_disposition(
            AgentDisposition.ALLOW
        )
        == EvaluationLabel.BENIGN
    )


@pytest.mark.parametrize(
    "disposition",
    [
        AgentDisposition.MONITOR,
        AgentDisposition.QUARANTINE,
        AgentDisposition.HUMAN_REVIEW,
    ],
)
def test_non_allow_agent_dispositions_map_to_threat(
    disposition,
):
    assert (
        _label_from_agent_disposition(
            disposition
        )
        == EvaluationLabel.THREAT
    )


@pytest.mark.parametrize(
    (
        "agent_disposition",
        "evaluation_disposition",
    ),
    [
        (
            AgentDisposition.ALLOW,
            EvaluationDisposition.ALLOW,
        ),
        (
            AgentDisposition.MONITOR,
            EvaluationDisposition.MONITOR,
        ),
        (
            AgentDisposition.QUARANTINE,
            EvaluationDisposition.QUARANTINE,
        ),
        (
            AgentDisposition.HUMAN_REVIEW,
            EvaluationDisposition.HUMAN_REVIEW,
        ),
    ],
)
def test_agent_disposition_mapping(
    agent_disposition,
    evaluation_disposition,
):
    assert (
        _evaluation_disposition_from_agent(
            agent_disposition
        )
        == evaluation_disposition
    )


@pytest.mark.asyncio
async def test_hybrid_low_risk_message_can_skip_agent():
    ml_adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.01
        ),
        decision_threshold=0.70,
    )

    adapter = (
        HybridEvaluationAdapter(
            ml_adapter=ml_adapter,
            agent_executor=None,
        )
    )

    sample = EvaluationSample(
        sample_id="benign-001",
        subject="Meeting reminder",
        body=(
            "Our regular project meeting "
            "is tomorrow."
        ),
        sender="colleague@example.com",
        true_label=(
            EvaluationLabel.BENIGN
        ),
    )

    prediction = await adapter.evaluate(
        sample
    )

    assert (
        prediction.predicted_label
        == EvaluationLabel.BENIGN
    )

    assert (
        prediction.disposition
        == EvaluationDisposition.ALLOW
    )


@pytest.mark.asyncio
async def test_hybrid_agent_review_calls_agent():
    ml_adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.10
        ),
        decision_threshold=0.70,
    )

    calls = []

    async def fake_agent_executor(
        *,
        review_input,
        model,
    ):
        calls.append(
            (
                review_input,
                model,
            )
        )

        return AgentReviewResult(
            message_id=(
                review_input.message_id
            ),
            findings=[],
            recommendation=(
                AgentRecommendation(
                    disposition=(
                        AgentDisposition
                        .QUARANTINE
                    ),
                    confidence=0.95,
                    reasons=[
                        "Strong phishing evidence"
                    ],
                    requires_human_review=False,
                )
            ),
            explanation=(
                "Credential phishing detected."
            ),
            model_metadata=(
                AgentModelMetadata(
                    provider="google",
                    model_name=model,
                    agent_version="0.1.0",
                    request_id="test",
                )
            ),
        )

    adapter = HybridEvaluationAdapter(
        ml_adapter=ml_adapter,
        agent_executor=(
            fake_agent_executor
        ),
        gemini_model=(
            "gemini-test-model"
        ),
    )

    sample = EvaluationSample(
        sample_id="phishing-001",
        subject=(
            "URGENT: Account verification"
        ),
        body=(
            "Your account will be suspended. "
            "Verify immediately at "
            "https://paypa1-security.xyz/login"
        ),
        sender=(
            "PayPal Security "
            "<support@paypa1-security.example>"
        ),
        true_label=(
            EvaluationLabel.THREAT
        ),
        threat_category="PHISHING",
    )

    prediction = await adapter.evaluate(
        sample
    )

    assert len(
        calls
    ) == 1

    assert (
        calls[0][1]
        == "gemini-test-model"
    )

    assert (
        prediction.predicted_label
        == EvaluationLabel.THREAT
    )

    assert (
        prediction.disposition
        == (
            EvaluationDisposition
            .QUARANTINE
        )
    )

    assert (
        prediction.confidence
        == 0.95
    )


@pytest.mark.asyncio
async def test_hybrid_agent_review_requires_executor():
    ml_adapter = MLArtifactAdapter(
        model=FakeProbabilityModel(
            0.10
        )
    )

    adapter = (
        HybridEvaluationAdapter(
            ml_adapter=ml_adapter,
            agent_executor=None,
        )
    )

    sample = EvaluationSample(
        sample_id="phishing-001",
        subject=(
            "URGENT verify account"
        ),
        body=(
            "Account suspended. "
            "Login at "
            "https://bad-login.xyz/login"
        ),
        sender=(
            "Security "
            "<support@bad-domain.example>"
        ),
        true_label=(
            EvaluationLabel.THREAT
        ),
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "Hybrid evaluation requires "
            "agent_executor"
        ),
    ):
        await adapter.evaluate(
            sample
        )