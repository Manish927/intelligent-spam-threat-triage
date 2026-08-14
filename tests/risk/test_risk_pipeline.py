from threat_triage.risk import (
    MLEvidence,
    RiskSeverity,
    RoutingDecision,
    build_risk_evidence,
    route_message,
    score_risk,
)
from threat_triage.security.models import (
    LanguageFeatures,
    SecurityFeatures,
    SenderFeatures,
    URLFeatures,
)


def build_security_features(
    *,
    message_id: str,
    suspicious_tld: bool = False,
    credential_path: bool = False,
    display_mismatch: bool = False,
    urgency: bool = False,
    financial: bool = False,
    suspension: bool = False,
    weak_url_digit_signal: bool = False,
) -> SecurityFeatures:
    """
    Build deterministic SecurityFeatures for end-to-end
    risk-pipeline integration tests.
    """

    return SecurityFeatures(
        message_id=message_id,

        url=URLFeatures(
            has_url=(
                suspicious_tld
                or credential_path
                or weak_url_digit_signal
            ),
            url_count=(
                1
                if (
                    suspicious_tld
                    or credential_path
                    or weak_url_digit_signal
                )
                else 0
            ),
            uses_ip_address_url=False,
            uses_url_shortener=False,
            suspicious_tld=suspicious_tld,
            punycode_domain=False,
            excessive_subdomains=False,
            domain_contains_digits=weak_url_digit_signal,
            domain_contains_hyphen=False,
            credential_path_keyword=credential_path,
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
            possible_display_name_mismatch=display_mismatch,
        ),

        language=LanguageFeatures(
            urgency_language=urgency,
            credential_request=False,
            financial_request=financial,
            verification_request=False,
            account_suspension_language=suspension,
            password_reset_language=False,
            matched_urgency_terms=[],
            matched_credential_terms=[],
            matched_financial_terms=[],
            matched_verification_terms=[],
            matched_suspension_terms=[],
            matched_password_terms=[],
        ),
    )


def build_ml_evidence(
    *,
    probability: float,
) -> MLEvidence:
    """
    Build ML evidence using the threshold selected in Notebook 02.
    """

    predicted_label = (
        "THREAT"
        if probability >= 0.7364
        else "BENIGN"
    )

    return MLEvidence(
        predicted_label=predicted_label,
        threat_probability=probability,
        decision_threshold=0.7364,
        model_name="tfidf-logistic-regression",
        model_version="0.1.0",
    )


def run_pipeline(
    *,
    message_id: str,
    probability: float,
    security_features: SecurityFeatures,
):
    """
    Run the complete Phase 4 production pipeline:

        MLEvidence
            +
        SecurityFeatures
            ↓
        RiskEvidence
            ↓
        RiskAssessment
            ↓
        RoutingResult
    """

    ml_evidence = build_ml_evidence(
        probability=probability
    )

    risk_evidence = build_risk_evidence(
        message_id=message_id,
        ml_evidence=ml_evidence,
        security_features=security_features,
    )

    assessment = score_risk(
        risk_evidence
    )

    routing = route_message(
        evidence=risk_evidence,
        assessment=assessment,
    )

    return (
        risk_evidence,
        assessment,
        routing,
    )


def test_clearly_benign_message_routes_to_allow():
    """
    Low ML probability and no security evidence should
    follow the low-risk ALLOW path.
    """

    message_id = "msg-benign"

    security = build_security_features(
        message_id=message_id,
    )

    (
        risk_evidence,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.05,
        security_features=security,
    )

    assert (
        risk_evidence.summary.total_signal_count
        == 0
    )

    # ML score:
    # 0.05 * 60 = 3
    assert assessment.risk_score == 3.0

    assert (
        assessment.severity
        == RiskSeverity.LOW
    )

    assert (
        assessment.requires_deep_analysis
        is False
    )

    assert (
        routing.decision
        == RoutingDecision.ALLOW
    )

    assert (
        routing.requires_human_review
        is False
    )


def test_low_ml_probability_with_strong_evidence_routes_to_agent_review():
    """
    Reproduce one of the important Notebook 03 findings:

    A message can have a very low ML threat probability but still
    expose meaningful deterministic evidence.

    Strong deterministic evidence should therefore trigger
    deeper analysis.
    """

    message_id = "msg-conflicting-evidence"

    security = build_security_features(
        message_id=message_id,
        suspicious_tld=True,
    )

    (
        risk_evidence,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.05,
        security_features=security,
    )

    assert (
        "url_suspicious_tld"
        in risk_evidence.summary.strong_signals
    )

    assert (
        risk_evidence.summary.total_signal_count
        == 1
    )

    # ML = 3
    # Strong signal = 8
    # Total = 11
    assert assessment.risk_score == 11.0

    assert (
        assessment.severity
        == RiskSeverity.LOW
    )

    # Strong evidence overrides the low ML certainty.
    assert (
        assessment.requires_deep_analysis
        is True
    )

    assert (
        routing.decision
        == RoutingDecision.AGENT_REVIEW
    )

    assert (
        routing.requires_human_review
        is False
    )


def test_uncertain_ml_probability_routes_to_agent_review():
    """
    An ambiguous ML probability should trigger deeper analysis
    even when deterministic evidence is absent.
    """

    message_id = "msg-uncertain"

    security = build_security_features(
        message_id=message_id,
    )

    (
        risk_evidence,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.50,
        security_features=security,
    )

    assert (
        risk_evidence.summary.total_signal_count
        == 0
    )

    # ML = 0.50 * 60 = 30
    assert assessment.risk_score == 30.0

    assert (
        assessment.severity
        == RiskSeverity.MEDIUM
    )

    assert (
        assessment.requires_deep_analysis
        is True
    )

    assert (
        routing.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_multiple_weak_signals_route_to_agent_review():
    """
    Multiple weak signals should not automatically imply THREAT,
    but they should justify deeper analysis.
    """

    message_id = "msg-weak-signals"

    security = SecurityFeatures(
        message_id=message_id,

        url=URLFeatures(
            has_url=True,
            url_count=1,
            uses_ip_address_url=False,
            uses_url_shortener=False,
            suspicious_tld=False,
            punycode_domain=False,
            excessive_subdomains=True,
            domain_contains_digits=True,
            domain_contains_hyphen=True,
            credential_path_keyword=False,
            extracted_urls=[],
            matched_credential_terms=[],
        ),

        sender=SenderFeatures(
            sender_present=True,
            sender_address="user@gmail.com",
            sender_domain="gmail.com",
            sender_domain_has_digits=False,
            sender_domain_has_hyphen=False,
            free_email_provider=True,
            possible_display_name_mismatch=False,
        ),

        language=LanguageFeatures(
            urgency_language=False,
            credential_request=True,
            financial_request=False,
            verification_request=True,
            account_suspension_language=False,
            password_reset_language=True,
            matched_urgency_terms=[],
            matched_credential_terms=[],
            matched_financial_terms=[],
            matched_verification_terms=[],
            matched_suspension_terms=[],
            matched_password_terms=[],
        ),
    )

    (
        risk_evidence,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.20,
        security_features=security,
    )

    # URL:
    # excessive_subdomains
    # digits
    # hyphen
    #
    # Sender:
    # free provider
    #
    # Language:
    # credentials
    # verification
    # password reset
    #
    # Total = 7 weak signals.
    assert (
        risk_evidence.summary.total_signal_count
        == 7
    )

    assert (
        risk_evidence.summary.strong_signals
        == []
    )

    # ML:
    # 0.20 * 60 = 12
    #
    # 7 weak signals:
    # 7 * 2 = 14
    #
    # Risk = 26
    assert assessment.risk_score == 26.0

    assert (
        assessment.severity
        == RiskSeverity.MEDIUM
    )

    # Multiple deterministic signals trigger
    # deep analysis.
    assert (
        assessment.requires_deep_analysis
        is True
    )

    assert (
        routing.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_high_confidence_threat_without_extra_evidence_routes_to_agent_review():
    """
    A high ML threat probability produces high risk, but with the
    default routing policy a HIGH-severity case without multiple
    strong deterministic signals remains eligible for Agentic review.
    """

    message_id = "msg-high-ml"

    security = build_security_features(
        message_id=message_id,
    )

    (
        _,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.90,
        security_features=security,
    )

    # ML:
    # 0.90 * 60 = 54
    assert assessment.risk_score == 54.0

    assert (
        assessment.severity
        == RiskSeverity.HIGH
    )

    assert (
        assessment.requires_deep_analysis
        is False
    )

    assert (
        routing.decision
        == RoutingDecision.AGENT_REVIEW
    )


def test_high_confidence_threat_with_multiple_strong_signals_routes_to_human_review():
    """
    HIGH risk combined with multiple strong deterministic signals
    should invoke the human-review override.
    """

    message_id = "msg-human-review"

    security = build_security_features(
        message_id=message_id,
        suspicious_tld=True,
        display_mismatch=True,
    )

    (
        risk_evidence,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.90,
        security_features=security,
    )

    assert (
        len(
            risk_evidence.summary.strong_signals
        )
        == 2
    )

    # ML = 54
    # Strong signals = 16
    # Total = 70
    assert assessment.risk_score == 70.0

    assert (
        assessment.severity
        == RiskSeverity.HIGH
    )

    assert (
        routing.decision
        == RoutingDecision.HUMAN_REVIEW
    )

    assert (
        routing.requires_human_review
        is True
    )


def test_critical_message_routes_to_human_review():
    """
    CRITICAL severity should always invoke human review
    under the default routing policy.
    """

    message_id = "msg-critical"

    security = build_security_features(
        message_id=message_id,
        suspicious_tld=True,
        credential_path=True,
        display_mismatch=True,
        urgency=True,
        financial=True,
        suspension=True,
    )

    (
        risk_evidence,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.95,
        security_features=security,
    )

    assert (
        len(
            risk_evidence.summary.strong_signals
        )
        >= 2
    )

    assert assessment.risk_score >= 75.0

    assert (
        assessment.severity
        == RiskSeverity.CRITICAL
    )

    assert (
        routing.decision
        == RoutingDecision.HUMAN_REVIEW
    )

    assert (
        routing.requires_human_review
        is True
    )


def test_pipeline_preserves_message_identity():
    """
    The same message identifier must flow through every layer.
    """

    message_id = "msg-identity"

    security = build_security_features(
        message_id=message_id,
    )

    (
        risk_evidence,
        assessment,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.10,
        security_features=security,
    )

    assert (
        risk_evidence.message_id
        == message_id
    )

    assert (
        assessment.message_id
        == message_id
    )

    assert (
        routing.message_id
        == message_id
    )


def test_pipeline_preserves_ml_provenance():
    """
    Model provenance must survive evidence construction so
    downstream agents and audit systems know which model produced
    the original prediction.
    """

    message_id = "msg-provenance"

    security = build_security_features(
        message_id=message_id,
    )

    (
        risk_evidence,
        _,
        _,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.20,
        security_features=security,
    )

    assert (
        risk_evidence.provenance.model_version
        == "0.1.0"
    )

    assert (
        risk_evidence.provenance.feature_version
        == "0.1.0"
    )

    assert (
        risk_evidence.ml.model_name
        == "tfidf-logistic-regression"
    )


def test_pipeline_generates_explainable_assessment():
    """
    RiskAssessment should explain the numerical score and
    strong evidence used by the scorer.
    """

    message_id = "msg-assessment-explainability"

    security = build_security_features(
        message_id=message_id,
        credential_path=True,
        urgency=True,
    )

    (
        _,
        assessment,
        _,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.55,
        security_features=security,
    )

    assert len(
        assessment.reasons
    ) > 0

    assert any(
        "ML threat probability"
        in reason
        for reason in assessment.reasons
    )

    assert any(
        "Deterministic security evidence"
        in reason
        for reason in assessment.reasons
    )

    assert (
        "URL contains credential-related path terms"
        in assessment.reasons
    )

    assert (
        "Urgency language detected"
        in assessment.reasons
    )


def test_pipeline_generates_explainable_routing_result():
    """
    RoutingResult should preserve an operator-readable explanation
    for why the message entered Agentic AI review.
    """

    message_id = "msg-routing-explainability"

    security = build_security_features(
        message_id=message_id,
        suspicious_tld=True,
    )

    (
        _,
        _,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.05,
        security_features=security,
    )

    assert routing.reason

    assert (
        "Risk score"
        in routing.reason
    )

    assert (
        "ML threat probability"
        in routing.reason
    )

    assert (
        "strong security signals detected"
        in routing.reason
    )

    assert (
        "Risk assessment requires deeper analysis"
        in routing.reason
    )

    assert (
        "Message requires Agentic AI review"
        in routing.reason
    )


def test_low_confidence_ml_prediction_does_not_lose_original_label():
    """
    Risk processing must not rewrite the original ML prediction.

    The downstream layers interpret the evidence but preserve
    its original provenance.
    """

    message_id = "msg-original-label"

    security = build_security_features(
        message_id=message_id,
        suspicious_tld=True,
    )

    (
        risk_evidence,
        _,
        routing,
    ) = run_pipeline(
        message_id=message_id,
        probability=0.05,
        security_features=security,
    )

    assert (
        risk_evidence.ml.predicted_label
        == "BENIGN"
    )

    # Although ML said BENIGN, security evidence
    # causes escalation.
    assert (
        routing.decision
        == RoutingDecision.AGENT_REVIEW
    )