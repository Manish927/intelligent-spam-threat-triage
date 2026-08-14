import pytest

from threat_triage.risk.evidence_builder import (
    build_risk_evidence,
)
from threat_triage.risk.models import (
    MLEvidence,
    RiskAssessment,
    RiskSeverity,
    RoutingDecision,
)
from threat_triage.risk.routing_policy import (
    RoutingPolicy,
    route_message,
)
from threat_triage.security.models import (
    LanguageFeatures,
    SecurityFeatures,
    SenderFeatures,
    URLFeatures,
)


def build_ml_evidence(
    probability: float = 0.50,
) -> MLEvidence:
    label = (
        "THREAT"
        if probability >= 0.7364
        else "BENIGN"
    )

    return MLEvidence(
        predicted_label=label,
        threat_probability=probability,
        decision_threshold=0.7364,
        model_name="tfidf-logistic-regression",
        model_version="0.1.0",
    )


def build_security_features(
    *,
    message_id: str = "msg-001",
    strong_signal_count: int = 0,
) -> SecurityFeatures:
    """
    Build a small SecurityFeatures object.

    Strong-signal mapping for tests:
        1 -> suspicious TLD
        2 -> suspicious TLD + display-name mismatch
        3 -> above + urgency
    """

    suspicious_tld = (
        strong_signal_count >= 1
    )

    display_mismatch = (
        strong_signal_count >= 2
    )

    urgency = (
        strong_signal_count >= 3
    )

    return SecurityFeatures(
        message_id=message_id,

        url=URLFeatures(
            has_url=suspicious_tld,
            url_count=(
                1
                if suspicious_tld
                else 0
            ),
            uses_ip_address_url=False,
            uses_url_shortener=False,
            suspicious_tld=suspicious_tld,
            punycode_domain=False,
            excessive_subdomains=False,
            domain_contains_digits=False,
            domain_contains_hyphen=False,
            credential_path_keyword=False,
            extracted_urls=[],
            matched_credential_terms=[],
        ),

        sender=SenderFeatures(
            sender_present=True,
            sender_address="user@example.com",
            sender_domain="example.com",
            sender_domain_has_digits=False,
            sender_domain_has_hyphen=False,
            free_email_provider=False,
            possible_display_name_mismatch=(
                display_mismatch
            ),
        ),

        language=LanguageFeatures(
            urgency_language=urgency,
            credential_request=False,
            financial_request=False,
            verification_request=False,
            account_suspension_language=False,
            password_reset_language=False,
            matched_urgency_terms=[],
            matched_credential_terms=[],
            matched_financial_terms=[],
            matched_verification_terms=[],
            matched_suspension_terms=[],
            matched_password_terms=[],
        ),
    )


def build_evidence(
    *,
    message_id: str = "msg-001",
    probability: float = 0.50,
    strong_signal_count: int = 0,
):
    security = build_security_features(
        message_id=message_id,
        strong_signal_count=strong_signal_count,
    )

    return build_risk_evidence(
        message_id=message_id,
        ml_evidence=build_ml_evidence(
            probability
        ),
        security_features=security,
    )


def build_assessment(
    *,
    message_id: str = "msg-001",
    score: float = 10.0,
    severity: RiskSeverity = RiskSeverity.LOW,
    requires_deep_analysis: bool = False,
) -> RiskAssessment:
    return RiskAssessment(
        message_id=message_id,
        risk_score=score,
        severity=severity,
        confidence=0.80,
        reasons=[],
        requires_deep_analysis=(
            requires_deep_analysis
        ),
    )


def test_allow_low_risk_message():
    evidence = build_evidence(
        probability=0.05
    )

    assessment = build_assessment(
        score=10.0,
        severity=RiskSeverity.LOW,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.ALLOW
    )

    assert (
        result.requires_human_review
        is False
    )


def test_monitor_medium_low_score():
    evidence = build_evidence()

    assessment = build_assessment(
        score=30.0,
        severity=RiskSeverity.MEDIUM,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.MONITOR
    )


def test_agent_review_for_higher_score():
    evidence = build_evidence()

    assessment = build_assessment(
        score=60.0,
        severity=RiskSeverity.HIGH,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_human_review_for_score_above_agent_threshold():
    evidence = build_evidence()

    assessment = build_assessment(
        score=80.0,
        severity=RiskSeverity.HIGH,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.HUMAN_REVIEW
    )

    assert (
        result.requires_human_review
        is True
    )


def test_critical_severity_forces_human_review():
    evidence = build_evidence(
        probability=0.20
    )

    assessment = build_assessment(
        score=40.0,
        severity=RiskSeverity.CRITICAL,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.HUMAN_REVIEW
    )


def test_high_risk_with_multiple_strong_signals_forces_human_review():
    evidence = build_evidence(
        strong_signal_count=2
    )

    assessment = build_assessment(
        score=60.0,
        severity=RiskSeverity.HIGH,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        len(
            evidence.summary.strong_signals
        )
        == 2
    )

    assert (
        result.decision
        == RoutingDecision.HUMAN_REVIEW
    )


def test_single_strong_signal_does_not_force_human_review():
    evidence = build_evidence(
        strong_signal_count=1
    )

    assessment = build_assessment(
        score=60.0,
        severity=RiskSeverity.HIGH,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_deep_analysis_overrides_allow_score():
    evidence = build_evidence(
        probability=0.10
    )

    assessment = build_assessment(
        score=10.0,
        severity=RiskSeverity.LOW,
        requires_deep_analysis=True,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_deep_analysis_overrides_monitor_score():
    evidence = build_evidence()

    assessment = build_assessment(
        score=30.0,
        severity=RiskSeverity.MEDIUM,
        requires_deep_analysis=True,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_critical_human_review_has_priority_over_deep_analysis():
    evidence = build_evidence()

    assessment = build_assessment(
        score=50.0,
        severity=RiskSeverity.CRITICAL,
        requires_deep_analysis=True,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.decision
        == RoutingDecision.HUMAN_REVIEW
    )


@pytest.mark.parametrize(
    "score, expected",
    [
        (
            0.0,
            RoutingDecision.ALLOW,
        ),
        (
            20.0,
            RoutingDecision.ALLOW,
        ),
        (
            20.01,
            RoutingDecision.MONITOR,
        ),
        (
            40.0,
            RoutingDecision.MONITOR,
        ),
        (
            40.01,
            RoutingDecision.AGENT_REVIEW,
        ),
        (
            75.0,
            RoutingDecision.AGENT_REVIEW,
        ),
        (
            75.01,
            RoutingDecision.HUMAN_REVIEW,
        ),
        (
            100.0,
            RoutingDecision.HUMAN_REVIEW,
        ),
    ],
)
def test_default_score_boundaries(
    score,
    expected,
):
    evidence = build_evidence()

    # Keep severity deliberately LOW so this test
    # isolates numeric routing boundaries.
    assessment = build_assessment(
        score=score,
        severity=RiskSeverity.LOW,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert result.decision == expected


def test_custom_routing_policy():
    policy = RoutingPolicy(
        allow_max_score=10.0,
        monitor_max_score=25.0,
        agent_review_max_score=60.0,
    )

    evidence = build_evidence()

    assessment = build_assessment(
        score=20.0,
        severity=RiskSeverity.LOW,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
        policy=policy,
    )

    assert (
        result.decision
        == RoutingDecision.MONITOR
    )


def test_can_disable_critical_human_review_override():
    policy = RoutingPolicy(
        human_review_for_critical=False,
    )

    evidence = build_evidence()

    assessment = build_assessment(
        score=50.0,
        severity=RiskSeverity.CRITICAL,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
        policy=policy,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_can_disable_high_strong_signal_override():
    policy = RoutingPolicy(
        human_review_for_high_with_strong_signals=False,
    )

    evidence = build_evidence(
        strong_signal_count=2
    )

    assessment = build_assessment(
        score=60.0,
        severity=RiskSeverity.HIGH,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
        policy=policy,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_can_disable_deep_analysis_agent_override():
    policy = RoutingPolicy(
        agent_review_when_deep_analysis_required=False,
    )

    evidence = build_evidence()

    assessment = build_assessment(
        score=10.0,
        severity=RiskSeverity.LOW,
        requires_deep_analysis=True,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
        policy=policy,
    )

    assert (
        result.decision
        == RoutingDecision.ALLOW
    )


def test_custom_strong_signal_threshold():
    policy = RoutingPolicy(
        human_review_min_strong_signals=3
    )

    evidence = build_evidence(
        strong_signal_count=2
    )

    assessment = build_assessment(
        score=60.0,
        severity=RiskSeverity.HIGH,
        requires_deep_analysis=False,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
        policy=policy,
    )

    assert (
        result.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_message_id_mismatch_rejected():
    evidence = build_evidence(
        message_id="evidence-id"
    )

    assessment = build_assessment(
        message_id="assessment-id"
    )

    with pytest.raises(
        ValueError,
        match=(
            "RiskEvidence message_id must match "
            "RiskAssessment message_id"
        ),
    ):
        route_message(
            evidence=evidence,
            assessment=assessment,
        )


@pytest.mark.parametrize(
    "allow, monitor, agent",
    [
        (-1.0, 40.0, 75.0),
        (20.0, 101.0, 75.0),
        (20.0, 40.0, 101.0),
    ],
)
def test_invalid_threshold_range(
    allow,
    monitor,
    agent,
):
    policy = RoutingPolicy(
        allow_max_score=allow,
        monitor_max_score=monitor,
        agent_review_max_score=agent,
    )

    evidence = build_evidence()
    assessment = build_assessment()

    with pytest.raises(ValueError):
        route_message(
            evidence=evidence,
            assessment=assessment,
            policy=policy,
        )


def test_invalid_threshold_order_rejected():
    policy = RoutingPolicy(
        allow_max_score=40.0,
        monitor_max_score=20.0,
        agent_review_max_score=75.0,
    )

    evidence = build_evidence()
    assessment = build_assessment()

    with pytest.raises(
        ValueError,
        match=(
            "Routing thresholds must satisfy "
            "allow <= monitor <= agent_review"
        ),
    ):
        route_message(
            evidence=evidence,
            assessment=assessment,
            policy=policy,
        )


def test_negative_strong_signal_threshold_rejected():
    policy = RoutingPolicy(
        human_review_min_strong_signals=-1
    )

    evidence = build_evidence()
    assessment = build_assessment()

    with pytest.raises(
        ValueError,
        match=(
            "human_review_min_strong_signals "
            "must not be negative"
        ),
    ):
        route_message(
            evidence=evidence,
            assessment=assessment,
            policy=policy,
        )


def test_allow_reason_contains_threshold_explanation():
    evidence = build_evidence()

    assessment = build_assessment(
        score=10.0,
        severity=RiskSeverity.LOW,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        "Risk remains below allow threshold"
        in result.reason
    )


def test_agent_reason_mentions_agentic_ai():
    evidence = build_evidence()

    assessment = build_assessment(
        score=60.0,
        severity=RiskSeverity.HIGH,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        "Message requires Agentic AI review"
        in result.reason
    )


def test_human_reason_mentions_security_review():
    evidence = build_evidence()

    assessment = build_assessment(
        score=90.0,
        severity=RiskSeverity.CRITICAL,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        "Message requires human security review"
        in result.reason
    )


def test_reason_includes_security_signal_count():
    evidence = build_evidence(
        strong_signal_count=2
    )

    assessment = build_assessment(
        score=60.0,
        severity=RiskSeverity.HIGH,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        "deterministic security signals detected"
        in result.reason
    )

    assert (
        "strong security signals detected"
        in result.reason
    )


def test_routing_result_preserves_message_id():
    evidence = build_evidence(
        message_id="msg-routing-123"
    )

    assessment = build_assessment(
        message_id="msg-routing-123",
        score=10.0,
    )

    result = route_message(
        evidence=evidence,
        assessment=assessment,
    )

    assert (
        result.message_id
        == "msg-routing-123"
    )