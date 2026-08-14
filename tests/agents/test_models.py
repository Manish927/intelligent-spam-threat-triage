import pytest

from threat_triage.agents.models import (
    AgentDisposition,
    AgentFinding,
    AgentFindingCategory,
    AgentFindingSeverity,
    AgentModelMetadata,
    AgentRecommendation,
    AgentReviewInput,
    AgentReviewResult,
)
from threat_triage.risk.models import (
    EvidenceSummary,
    MLEvidence,
    RiskAssessment,
    RiskSeverity,
    RoutingDecision,
    RoutingResult,
)


def build_ml_evidence() -> MLEvidence:
    return MLEvidence(
        predicted_label="THREAT",
        threat_probability=0.91,
        decision_threshold=0.7364,
        model_name="tfidf-logistic-regression",
        model_version="0.1.0",
    )


def build_evidence_summary() -> EvidenceSummary:
    return EvidenceSummary(
        total_signal_count=3,
        url_signal_count=1,
        sender_signal_count=1,
        language_signal_count=1,
        evidence_categories=[
            "URL",
            "SENDER",
            "LANGUAGE",
        ],
        strong_signals=[
            "url_credential_path",
            "sender_display_mismatch",
        ],
    )


def build_risk_assessment(
    message_id: str = "msg-001",
) -> RiskAssessment:
    return RiskAssessment(
        message_id=message_id,
        risk_score=78.0,
        severity=RiskSeverity.CRITICAL,
        confidence=0.82,
        reasons=[
            "High ML threat probability",
            "Strong deterministic evidence",
        ],
        requires_deep_analysis=True,
    )


def build_routing_result(
    message_id: str = "msg-001",
) -> RoutingResult:
    return RoutingResult(
        message_id=message_id,
        decision=RoutingDecision.AGENT_REVIEW,
        reason="Message requires Agentic AI review",
        requires_human_review=False,
    )


def build_review_input(
    message_id: str = "msg-001",
) -> AgentReviewInput:
    return AgentReviewInput(
        message_id=message_id,
        subject="URGENT account verification",
        body_preview=(
            "Verify your account immediately "
            "using the supplied link."
        ),
        sender=(
            "Security Team "
            "<security@paypa1-example.com>"
        ),
        ml_evidence=build_ml_evidence(),
        evidence_summary=build_evidence_summary(),
        risk_assessment=build_risk_assessment(
            message_id
        ),
        routing_result=build_routing_result(
            message_id
        ),
    )


def build_finding() -> AgentFinding:
    return AgentFinding(
        category=AgentFindingCategory.URL,
        finding=(
            "URL contains credential-related "
            "path indicators."
        ),
        severity=AgentFindingSeverity.HIGH,
        confidence=0.92,
        evidence_refs=[
            "security.url.credential_path_keyword"
        ],
    )


def build_recommendation() -> AgentRecommendation:
    return AgentRecommendation(
        disposition=AgentDisposition.QUARANTINE,
        confidence=0.93,
        reasons=[
            "Credential collection indicators detected",
            "Sender identity appears inconsistent",
        ],
        requires_human_review=False,
    )


def build_metadata() -> AgentModelMetadata:
    return AgentModelMetadata(
        provider="google",
        model_name="gemini",
        agent_version="0.1.0",
        request_id="request-123",
    )


def test_agent_review_input_creation():
    review_input = build_review_input()

    assert review_input.message_id == "msg-001"

    assert (
        review_input.ml_evidence.predicted_label
        == "THREAT"
    )

    assert (
        review_input.evidence_summary.total_signal_count
        == 3
    )

    assert (
        review_input.risk_assessment.severity
        == RiskSeverity.CRITICAL
    )

    assert (
        review_input.routing_result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_agent_review_input_allows_optional_message_fields():
    review_input = AgentReviewInput(
        message_id="msg-optional",
        subject=None,
        body_preview=None,
        sender=None,
        ml_evidence=build_ml_evidence(),
        evidence_summary=build_evidence_summary(),
        risk_assessment=build_risk_assessment(
            "msg-optional"
        ),
        routing_result=build_routing_result(
            "msg-optional"
        ),
    )

    assert review_input.subject is None
    assert review_input.body_preview is None
    assert review_input.sender is None


def test_agent_review_input_rejects_empty_message_id():
    with pytest.raises(
        ValueError,
        match="message_id must not be empty",
    ):
        AgentReviewInput(
            message_id="",
            subject=None,
            body_preview=None,
            sender=None,
            ml_evidence=build_ml_evidence(),
            evidence_summary=build_evidence_summary(),
            risk_assessment=build_risk_assessment(
                ""
            ),
            routing_result=build_routing_result(
                ""
            ),
        )


def test_agent_review_input_rejects_risk_assessment_id_mismatch():
    with pytest.raises(
        ValueError,
        match=(
            "AgentReviewInput message_id must match "
            "RiskAssessment message_id"
        ),
    ):
        AgentReviewInput(
            message_id="msg-input",
            subject="Subject",
            body_preview="Body",
            sender="user@example.com",
            ml_evidence=build_ml_evidence(),
            evidence_summary=build_evidence_summary(),
            risk_assessment=build_risk_assessment(
                "msg-risk"
            ),
            routing_result=build_routing_result(
                "msg-input"
            ),
        )


def test_agent_review_input_rejects_routing_result_id_mismatch():
    with pytest.raises(
        ValueError,
        match=(
            "AgentReviewInput message_id must match "
            "RoutingResult message_id"
        ),
    ):
        AgentReviewInput(
            message_id="msg-input",
            subject="Subject",
            body_preview="Body",
            sender="user@example.com",
            ml_evidence=build_ml_evidence(),
            evidence_summary=build_evidence_summary(),
            risk_assessment=build_risk_assessment(
                "msg-input"
            ),
            routing_result=build_routing_result(
                "msg-routing"
            ),
        )


@pytest.mark.parametrize(
    "category",
    [
        AgentFindingCategory.URL,
        AgentFindingCategory.SENDER,
        AgentFindingCategory.LANGUAGE,
        AgentFindingCategory.THREAT_INTELLIGENCE,
        AgentFindingCategory.MESSAGE_CONTEXT,
        AgentFindingCategory.MODEL_CONFLICT,
        AgentFindingCategory.POLICY,
    ],
)
def test_agent_finding_category_values(
    category,
):
    assert category.value in {
        "URL",
        "SENDER",
        "LANGUAGE",
        "THREAT_INTELLIGENCE",
        "MESSAGE_CONTEXT",
        "MODEL_CONFLICT",
        "POLICY",
    }


@pytest.mark.parametrize(
    "severity",
    [
        AgentFindingSeverity.INFO,
        AgentFindingSeverity.LOW,
        AgentFindingSeverity.MEDIUM,
        AgentFindingSeverity.HIGH,
        AgentFindingSeverity.CRITICAL,
    ],
)
def test_agent_finding_severity_values(
    severity,
):
    assert severity.value in {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


@pytest.mark.parametrize(
    "disposition",
    [
        AgentDisposition.ALLOW,
        AgentDisposition.MONITOR,
        AgentDisposition.QUARANTINE,
        AgentDisposition.HUMAN_REVIEW,
    ],
)
def test_agent_disposition_values(
    disposition,
):
    assert disposition.value in {
        "ALLOW",
        "MONITOR",
        "QUARANTINE",
        "HUMAN_REVIEW",
    }


def test_agent_finding_creation():
    finding = build_finding()

    assert (
        finding.category
        == AgentFindingCategory.URL
    )

    assert (
        finding.severity
        == AgentFindingSeverity.HIGH
    )

    assert finding.confidence == 0.92

    assert finding.evidence_refs == [
        "security.url.credential_path_keyword"
    ]


def test_agent_finding_rejects_empty_finding():
    with pytest.raises(
        ValueError,
        match="finding must not be empty",
    ):
        AgentFinding(
            category=AgentFindingCategory.URL,
            finding="",
            severity=AgentFindingSeverity.HIGH,
            confidence=0.90,
        )


@pytest.mark.parametrize(
    "confidence",
    [
        -0.01,
        1.01,
    ],
)
def test_agent_finding_rejects_invalid_confidence(
    confidence,
):
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        AgentFinding(
            category=AgentFindingCategory.URL,
            finding="Suspicious URL",
            severity=AgentFindingSeverity.HIGH,
            confidence=confidence,
        )


def test_agent_recommendation_creation():
    recommendation = build_recommendation()

    assert (
        recommendation.disposition
        == AgentDisposition.QUARANTINE
    )

    assert recommendation.confidence == 0.93

    assert (
        recommendation.requires_human_review
        is False
    )

    assert len(recommendation.reasons) == 2


@pytest.mark.parametrize(
    "confidence",
    [
        -0.01,
        1.01,
    ],
)
def test_agent_recommendation_rejects_invalid_confidence(
    confidence,
):
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        AgentRecommendation(
            disposition=AgentDisposition.MONITOR,
            confidence=confidence,
            reasons=[
                "Some evidence requires observation"
            ],
        )


def test_agent_recommendation_requires_reasons():
    with pytest.raises(
        ValueError,
        match="reasons must not be empty",
    ):
        AgentRecommendation(
            disposition=AgentDisposition.MONITOR,
            confidence=0.70,
            reasons=[],
        )


def test_human_review_disposition_requires_human_review_flag():
    with pytest.raises(
        ValueError,
        match=(
            "HUMAN_REVIEW disposition requires "
            "requires_human_review=True"
        ),
    ):
        AgentRecommendation(
            disposition=AgentDisposition.HUMAN_REVIEW,
            confidence=0.95,
            reasons=[
                "High-impact ambiguous threat"
            ],
            requires_human_review=False,
        )


def test_human_review_recommendation_creation():
    recommendation = AgentRecommendation(
        disposition=AgentDisposition.HUMAN_REVIEW,
        confidence=0.95,
        reasons=[
            "High-impact ambiguous threat"
        ],
        requires_human_review=True,
    )

    assert (
        recommendation.disposition
        == AgentDisposition.HUMAN_REVIEW
    )

    assert (
        recommendation.requires_human_review
        is True
    )


def test_model_metadata_creation():
    metadata = build_metadata()

    assert metadata.provider == "google"
    assert metadata.model_name == "gemini"
    assert metadata.agent_version == "0.1.0"
    assert metadata.request_id == "request-123"


@pytest.mark.parametrize(
    "field_name",
    [
        "provider",
        "model_name",
        "agent_version",
    ],
)
def test_model_metadata_rejects_empty_required_fields(
    field_name,
):
    values = {
        "provider": "google",
        "model_name": "gemini",
        "agent_version": "0.1.0",
    }

    values[field_name] = ""

    with pytest.raises(
        ValueError,
    ):
        AgentModelMetadata(
            provider=values["provider"],
            model_name=values["model_name"],
            agent_version=values[
                "agent_version"
            ],
        )


def test_agent_review_result_creation():
    result = AgentReviewResult(
        message_id="msg-001",
        findings=[
            build_finding()
        ],
        recommendation=(
            build_recommendation()
        ),
        explanation=(
            "The message contains credential-related "
            "URL evidence and sender inconsistency."
        ),
        model_metadata=build_metadata(),
    )

    assert result.message_id == "msg-001"
    assert len(result.findings) == 1

    assert (
        result.recommendation.disposition
        == AgentDisposition.QUARANTINE
    )

    assert result.explanation


def test_agent_review_result_allows_no_findings():
    """
    An agent can legitimately conclude that no suspicious
    findings were identified.
    """

    result = AgentReviewResult(
        message_id="msg-clear",
        findings=[],
        recommendation=AgentRecommendation(
            disposition=AgentDisposition.ALLOW,
            confidence=0.88,
            reasons=[
                "No material suspicious evidence identified"
            ],
            requires_human_review=False,
        ),
        explanation=(
            "No significant threat indicators were found."
        ),
        model_metadata=build_metadata(),
    )

    assert result.findings == []

    assert (
        result.recommendation.disposition
        == AgentDisposition.ALLOW
    )


def test_agent_review_result_rejects_empty_message_id():
    with pytest.raises(
        ValueError,
        match="message_id must not be empty",
    ):
        AgentReviewResult(
            message_id="",
            findings=[
                build_finding()
            ],
            recommendation=(
                build_recommendation()
            ),
            explanation="Explanation",
            model_metadata=build_metadata(),
        )


def test_agent_review_result_rejects_empty_explanation():
    with pytest.raises(
        ValueError,
        match="explanation must not be empty",
    ):
        AgentReviewResult(
            message_id="msg-001",
            findings=[
                build_finding()
            ],
            recommendation=(
                build_recommendation()
            ),
            explanation="",
            model_metadata=build_metadata(),
        )


def test_complete_agent_contract_preserves_structured_evidence():
    """
    Verify the complete Agentic AI contract can represent an
    explainable threat-review result without relying on
    unstructured output.
    """

    review_input = build_review_input(
        message_id="msg-contract"
    )

    finding = AgentFinding(
        category=AgentFindingCategory.MODEL_CONFLICT,
        finding=(
            "Deterministic evidence conflicts with "
            "the original ML interpretation."
        ),
        severity=AgentFindingSeverity.HIGH,
        confidence=0.89,
        evidence_refs=[
            "ml.threat_probability",
            "security.url.credential_path_keyword",
        ],
    )

    recommendation = AgentRecommendation(
        disposition=AgentDisposition.HUMAN_REVIEW,
        confidence=0.91,
        reasons=[
            "Conflicting evidence requires analyst validation"
        ],
        requires_human_review=True,
    )

    result = AgentReviewResult(
        message_id="msg-contract",
        findings=[
            finding
        ],
        recommendation=recommendation,
        explanation=(
            "The classical ML result and deterministic "
            "security evidence disagree, so human "
            "validation is recommended."
        ),
        model_metadata=build_metadata(),
    )

    assert (
        review_input.message_id
        == result.message_id
    )

    assert (
        result.findings[0].category
        == AgentFindingCategory.MODEL_CONFLICT
    )

    assert (
        result.recommendation.disposition
        == AgentDisposition.HUMAN_REVIEW
    )

    assert (
        result.recommendation.requires_human_review
        is True
    )