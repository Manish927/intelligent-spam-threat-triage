from datetime import datetime, timezone

import pytest

from threat_triage.risk.models import (
    EvidenceProvenance,
    EvidenceSummary,
    MLEvidence,
    RiskAssessment,
    RiskEvidence,
    RiskSeverity,
    RoutingDecision,
    RoutingResult,
)

from threat_triage.security.models import (
    LanguageFeatures,
    SecurityFeatures,
    SenderFeatures,
    URLFeatures,
)


def build_security_features(
    message_id: str = "msg-001",
) -> SecurityFeatures:
    return SecurityFeatures(
        message_id=message_id,

        url=URLFeatures(
            has_url=True,
            url_count=1,
            uses_ip_address_url=False,
            uses_url_shortener=False,
            suspicious_tld=False,
            punycode_domain=False,
            excessive_subdomains=False,
            domain_contains_digits=True,
            domain_contains_hyphen=True,
            credential_path_keyword=True,
            extracted_urls=[
                "https://paypa1-security.example/login"
            ],
            matched_credential_terms=[
                "login"
            ],
        ),

        sender=SenderFeatures(
            sender_present=True,
            sender_address=(
                "support@paypa1-security.example"
            ),
            sender_domain=(
                "paypa1-security.example"
            ),
            sender_domain_has_digits=True,
            sender_domain_has_hyphen=True,
            free_email_provider=False,
            possible_display_name_mismatch=True,
        ),

        language=LanguageFeatures(
            urgency_language=True,
            credential_request=True,
            financial_request=False,
            verification_request=True,
            account_suspension_language=True,
            password_reset_language=False,
            matched_urgency_terms=[
                "urgent"
            ],
            matched_credential_terms=[
                "password"
            ],
            matched_financial_terms=[],
            matched_verification_terms=[
                "verify account"
            ],
            matched_suspension_terms=[
                "account suspended"
            ],
            matched_password_terms=[],
        ),
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
        total_signal_count=7,
        url_signal_count=3,
        sender_signal_count=2,
        language_signal_count=2,
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


def build_provenance() -> EvidenceProvenance:
    return EvidenceProvenance(
        model_version="0.1.0",
        feature_version="0.1.0",
    )


def test_ml_evidence_creation():
    evidence = build_ml_evidence()

    assert evidence.predicted_label == "THREAT"
    assert evidence.threat_probability == 0.91
    assert evidence.decision_threshold == 0.7364
    assert evidence.model_name == (
        "tfidf-logistic-regression"
    )
    assert evidence.model_version == "0.1.0"


@pytest.mark.parametrize(
    "probability",
    [
        -0.01,
        1.01,
    ],
)
def test_ml_evidence_rejects_invalid_probability(
    probability,
):
    with pytest.raises(
        ValueError,
        match=(
            "threat_probability must be "
            "between 0 and 1"
        ),
    ):
        MLEvidence(
            predicted_label="THREAT",
            threat_probability=probability,
            decision_threshold=0.50,
            model_name="model",
            model_version="1",
        )


@pytest.mark.parametrize(
    "threshold",
    [
        -0.01,
        1.01,
    ],
)
def test_ml_evidence_rejects_invalid_threshold(
    threshold,
):
    with pytest.raises(
        ValueError,
        match=(
            "decision_threshold must be "
            "between 0 and 1"
        ),
    ):
        MLEvidence(
            predicted_label="BENIGN",
            threat_probability=0.10,
            decision_threshold=threshold,
            model_name="model",
            model_version="1",
        )


def test_ml_evidence_rejects_empty_label():
    with pytest.raises(
        ValueError,
        match="predicted_label must not be empty",
    ):
        MLEvidence(
            predicted_label="",
            threat_probability=0.10,
            decision_threshold=0.50,
            model_name="model",
            model_version="1",
        )


def test_evidence_summary_creation():
    summary = build_evidence_summary()

    assert summary.total_signal_count == 7
    assert summary.url_signal_count == 3
    assert summary.sender_signal_count == 2
    assert summary.language_signal_count == 2


def test_evidence_summary_rejects_negative_count():
    with pytest.raises(
        ValueError,
        match=(
            "Evidence signal counts "
            "must not be negative"
        ),
    ):
        EvidenceSummary(
            total_signal_count=-1,
            url_signal_count=0,
            sender_signal_count=0,
            language_signal_count=0,
        )


def test_evidence_summary_rejects_inconsistent_total():
    with pytest.raises(
        ValueError,
        match=(
            "total_signal_count must equal "
            "the sum"
        ),
    ):
        EvidenceSummary(
            total_signal_count=5,
            url_signal_count=2,
            sender_signal_count=2,
            language_signal_count=2,
        )


def test_provenance_is_timezone_aware():
    provenance = build_provenance()

    assert provenance.generated_at.tzinfo is not None


def test_provenance_rejects_naive_datetime():
    with pytest.raises(
        ValueError,
        match=(
            "generated_at must be "
            "timezone-aware"
        ),
    ):
        EvidenceProvenance(
            model_version="0.1.0",
            feature_version="0.1.0",
            generated_at=datetime.now(),
        )


def test_risk_evidence_creation():
    security = build_security_features(
        message_id="msg-001"
    )

    evidence = RiskEvidence(
        message_id="msg-001",
        ml=build_ml_evidence(),
        security=security,
        summary=build_evidence_summary(),
        provenance=build_provenance(),
    )

    assert evidence.message_id == "msg-001"
    assert evidence.ml.threat_probability == 0.91

    assert (
        evidence.security.message_id
        == evidence.message_id
    )


def test_risk_evidence_rejects_message_id_mismatch():
    security = build_security_features(
        message_id="msg-security"
    )

    with pytest.raises(
        ValueError,
        match=(
            "RiskEvidence message_id must match "
            "SecurityFeatures message_id"
        ),
    ):
        RiskEvidence(
            message_id="msg-risk",
            ml=build_ml_evidence(),
            security=security,
            summary=build_evidence_summary(),
            provenance=build_provenance(),
        )


def test_risk_assessment_creation():
    assessment = RiskAssessment(
        message_id="msg-001",
        risk_score=82.5,
        severity=RiskSeverity.HIGH,
        confidence=0.88,
        reasons=[
            "High ML threat probability",
            "Credential-related URL evidence",
        ],
        requires_deep_analysis=True,
    )

    assert assessment.risk_score == 82.5
    assert assessment.severity == RiskSeverity.HIGH
    assert assessment.confidence == 0.88
    assert assessment.requires_deep_analysis is True


@pytest.mark.parametrize(
    "risk_score",
    [
        -0.1,
        100.1,
    ],
)
def test_risk_assessment_rejects_invalid_score(
    risk_score,
):
    with pytest.raises(
        ValueError,
        match="risk_score must be between 0 and 100",
    ):
        RiskAssessment(
            message_id="msg-001",
            risk_score=risk_score,
            severity=RiskSeverity.HIGH,
            confidence=0.90,
        )


@pytest.mark.parametrize(
    "confidence",
    [
        -0.01,
        1.01,
    ],
)
def test_risk_assessment_rejects_invalid_confidence(
    confidence,
):
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        RiskAssessment(
            message_id="msg-001",
            risk_score=75.0,
            severity=RiskSeverity.HIGH,
            confidence=confidence,
        )


@pytest.mark.parametrize(
    "severity",
    [
        RiskSeverity.LOW,
        RiskSeverity.MEDIUM,
        RiskSeverity.HIGH,
        RiskSeverity.CRITICAL,
    ],
)
def test_risk_severity_values(severity):
    assert severity.value in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


@pytest.mark.parametrize(
    "decision",
    [
        RoutingDecision.ALLOW,
        RoutingDecision.MONITOR,
        RoutingDecision.AGENT_REVIEW,
        RoutingDecision.HUMAN_REVIEW,
    ],
)
def test_routing_decision_values(decision):
    assert decision.value in {
        "ALLOW",
        "MONITOR",
        "AGENT_REVIEW",
        "HUMAN_REVIEW",
    }


def test_routing_result_creation():
    result = RoutingResult(
        message_id="msg-001",
        decision=RoutingDecision.AGENT_REVIEW,
        reason=(
            "Conflicting ML and deterministic evidence"
        ),
        requires_human_review=False,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )

    assert result.requires_human_review is False


def test_routing_result_rejects_empty_reason():
    with pytest.raises(
        ValueError,
        match="reason must not be empty",
    ):
        RoutingResult(
            message_id="msg-001",
            decision=RoutingDecision.ALLOW,
            reason="",
        )