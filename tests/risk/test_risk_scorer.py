import pytest

from threat_triage.risk.evidence_builder import (
    build_risk_evidence,
)
from threat_triage.risk.models import (
    MLEvidence,
    RiskSeverity,
)
from threat_triage.risk.risk_scorer import (
    RiskScoringPolicy,
    score_risk,
)
from threat_triage.security.models import (
    LanguageFeatures,
    SecurityFeatures,
    SenderFeatures,
    URLFeatures,
)


def build_ml_evidence(
    probability: float = 0.80,
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
    ip_url: bool = False,
    suspicious_tld: bool = False,
    punycode: bool = False,
    credential_path: bool = False,
    url_digits: bool = False,
    url_hyphen: bool = False,
    sender_digits: bool = False,
    sender_hyphen: bool = False,
    free_provider: bool = False,
    display_mismatch: bool = False,
    urgency: bool = False,
    credentials: bool = False,
    financial: bool = False,
    verification: bool = False,
    suspension: bool = False,
    password_reset: bool = False,
) -> SecurityFeatures:
    return SecurityFeatures(
        message_id=message_id,

        url=URLFeatures(
            has_url=(
                ip_url
                or suspicious_tld
                or punycode
                or credential_path
                or url_digits
                or url_hyphen
            ),
            url_count=1,
            uses_ip_address_url=ip_url,
            uses_url_shortener=False,
            suspicious_tld=suspicious_tld,
            punycode_domain=punycode,
            excessive_subdomains=False,
            domain_contains_digits=url_digits,
            domain_contains_hyphen=url_hyphen,
            credential_path_keyword=credential_path,
            extracted_urls=[],
            matched_credential_terms=[],
        ),

        sender=SenderFeatures(
            sender_present=True,
            sender_address="user@example.com",
            sender_domain="example.com",
            sender_domain_has_digits=sender_digits,
            sender_domain_has_hyphen=sender_hyphen,
            free_email_provider=free_provider,
            possible_display_name_mismatch=display_mismatch,
        ),

        language=LanguageFeatures(
            urgency_language=urgency,
            credential_request=credentials,
            financial_request=financial,
            verification_request=verification,
            account_suspension_language=suspension,
            password_reset_language=password_reset,
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
    probability: float = 0.80,
    security_features: SecurityFeatures | None = None,
):
    if security_features is None:
        security_features = build_security_features()

    return build_risk_evidence(
        message_id=security_features.message_id,
        ml_evidence=build_ml_evidence(
            probability
        ),
        security_features=security_features,
    )


def test_ml_only_score():
    evidence = build_evidence(
        probability=0.80
    )

    assessment = score_risk(
        evidence
    )

    # 0.80 * 60
    assert assessment.risk_score == 48.0

    assert (
        assessment.severity
        == RiskSeverity.MEDIUM
    )


def test_strong_signal_weighting():
    security = build_security_features(
        ip_url=True,
    )

    evidence = build_evidence(
        probability=0.50,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    # ML: 0.50 * 60 = 30
    # Strong signal: 1 * 8 = 8
    # Total = 38
    assert assessment.risk_score == 38.0


def test_weak_signal_weighting():
    security = build_security_features(
        url_digits=True,
    )

    evidence = build_evidence(
        probability=0.50,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    # ML = 30
    # Weak signal = 2
    assert assessment.risk_score == 32.0


def test_multiple_strong_signals():
    security = build_security_features(
        ip_url=True,
        suspicious_tld=True,
        display_mismatch=True,
        urgency=True,
    )

    evidence = build_evidence(
        probability=0.50,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    # ML = 30
    # 4 strong * 8 = 32
    # total = 62
    assert assessment.risk_score == 62.0

    assert (
        assessment.severity
        == RiskSeverity.HIGH
    )


def test_mixed_strong_and_weak_signals():
    security = build_security_features(
        ip_url=True,          # strong
        credential_path=True, # strong
        url_digits=True,      # weak
        sender_digits=True,   # weak
        credentials=True,     # weak
    )

    evidence = build_evidence(
        probability=0.40,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    # ML: 0.40 * 60 = 24
    # Strong: 2 * 8 = 16
    # Weak: 3 * 2 = 6
    # Total = 46
    assert assessment.risk_score == 46.0


def test_security_evidence_score_is_capped():
    security = build_security_features(
        ip_url=True,
        suspicious_tld=True,
        punycode=True,
        credential_path=True,
        url_digits=True,
        url_hyphen=True,
        sender_digits=True,
        sender_hyphen=True,
        free_provider=True,
        display_mismatch=True,
        urgency=True,
        credentials=True,
        financial=True,
        verification=True,
        suspension=True,
        password_reset=True,
    )

    evidence = build_evidence(
        probability=0.50,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    # ML = 30
    # Security contribution may exceed 40,
    # but policy caps it at 40.
    assert assessment.risk_score == 70.0


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, RiskSeverity.LOW),
        (24.99, RiskSeverity.LOW),
        (25.0, RiskSeverity.MEDIUM),
        (49.99, RiskSeverity.MEDIUM),
        (50.0, RiskSeverity.HIGH),
        (74.99, RiskSeverity.HIGH),
        (75.0, RiskSeverity.CRITICAL),
        (100.0, RiskSeverity.CRITICAL),
    ],
)
def test_severity_boundaries(
    score,
    expected,
):
    policy = RiskScoringPolicy(
        ml_probability_weight=100.0,
        strong_signal_weight=0.0,
        weak_signal_weight=0.0,
        max_security_evidence_score=0.0,
    )

    probability = score / 100.0

    evidence = build_evidence(
        probability=probability
    )

    assessment = score_risk(
        evidence,
        policy=policy,
    )

    assert assessment.severity == expected


def test_uncertain_probability_requires_deep_analysis():
    evidence = build_evidence(
        probability=0.50
    )

    assessment = score_risk(
        evidence
    )

    assert (
        assessment.requires_deep_analysis
        is True
    )


def test_low_probability_without_signals_does_not_require_deep_analysis():
    evidence = build_evidence(
        probability=0.10
    )

    assessment = score_risk(
        evidence
    )

    assert (
        assessment.requires_deep_analysis
        is False
    )


def test_high_probability_without_signals_does_not_require_deep_analysis():
    evidence = build_evidence(
        probability=0.95
    )

    assessment = score_risk(
        evidence
    )

    assert (
        assessment.requires_deep_analysis
        is False
    )


def test_strong_signal_requires_deep_analysis_even_with_low_probability():
    security = build_security_features(
        suspicious_tld=True,
    )

    evidence = build_evidence(
        probability=0.05,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    assert (
        assessment.requires_deep_analysis
        is True
    )


def test_multiple_weak_signals_require_deep_analysis():
    security = build_security_features(
        url_digits=True,
        sender_digits=True,
    )

    evidence = build_evidence(
        probability=0.05,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    assert (
        assessment.requires_deep_analysis
        is True
    )


@pytest.mark.parametrize(
    "probability, expected_confidence",
    [
        (0.50, 0.0),
        (0.40, 0.2),
        (0.60, 0.2),
        (0.25, 0.5),
        (0.75, 0.5),
        (0.00, 1.0),
        (1.00, 1.0),
    ],
)
def test_confidence_calculation(
    probability,
    expected_confidence,
):
    evidence = build_evidence(
        probability=probability
    )

    assessment = score_risk(
        evidence
    )

    assert (
        assessment.confidence
        == pytest.approx(
            expected_confidence,
            abs=1e-4,
        )
    )


def test_reasons_include_ml_contribution():
    evidence = build_evidence(
        probability=0.80
    )

    assessment = score_risk(
        evidence
    )

    assert any(
        "ML threat probability"
        in reason
        for reason in assessment.reasons
    )


def test_reasons_include_security_contribution():
    security = build_security_features(
        suspicious_tld=True,
    )

    evidence = build_evidence(
        probability=0.50,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    assert any(
        "Deterministic security evidence"
        in reason
        for reason in assessment.reasons
    )


def test_reasons_include_strong_signal_explanation():
    security = build_security_features(
        credential_path=True,
    )

    evidence = build_evidence(
        probability=0.50,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    assert (
        "URL contains credential-related path terms"
        in assessment.reasons
    )


def test_reasons_include_deep_analysis():
    evidence = build_evidence(
        probability=0.50
    )

    assessment = score_risk(
        evidence
    )

    assert (
        "Evidence requires deeper analysis"
        in assessment.reasons
    )


def test_custom_policy_changes_score():
    policy = RiskScoringPolicy(
        ml_probability_weight=50.0,
        strong_signal_weight=10.0,
        weak_signal_weight=1.0,
        max_security_evidence_score=50.0,
    )

    security = build_security_features(
        suspicious_tld=True,
    )

    evidence = build_evidence(
        probability=0.50,
        security_features=security,
    )

    assessment = score_risk(
        evidence,
        policy=policy,
    )

    # ML = 25
    # Strong = 10
    assert assessment.risk_score == 35.0


def test_invalid_negative_ml_weight():
    policy = RiskScoringPolicy(
        ml_probability_weight=-1.0
    )

    evidence = build_evidence()

    with pytest.raises(
        ValueError,
        match=(
            "ml_probability_weight "
            "must not be negative"
        ),
    ):
        score_risk(
            evidence,
            policy=policy,
        )


def test_invalid_probability_range_order():
    policy = RiskScoringPolicy(
        deep_analysis_probability_low=0.80,
        deep_analysis_probability_high=0.20,
    )

    evidence = build_evidence()

    with pytest.raises(
        ValueError,
        match=(
            "deep-analysis probability "
            "lower bound must not exceed "
            "upper bound"
        ),
    ):
        score_risk(
            evidence,
            policy=policy,
        )


@pytest.mark.parametrize(
    "low, high",
    [
        (-0.1, 0.8),
        (0.2, 1.1),
    ],
)
def test_invalid_deep_analysis_probability_bounds(
    low,
    high,
):
    policy = RiskScoringPolicy(
        deep_analysis_probability_low=low,
        deep_analysis_probability_high=high,
    )

    evidence = build_evidence()

    with pytest.raises(ValueError):
        score_risk(
            evidence,
            policy=policy,
        )


def test_assessment_preserves_message_id():
    security = build_security_features(
        message_id="msg-risk-123",
    )

    evidence = build_evidence(
        probability=0.75,
        security_features=security,
    )

    assessment = score_risk(
        evidence
    )

    assert (
        assessment.message_id
        == "msg-risk-123"
    )