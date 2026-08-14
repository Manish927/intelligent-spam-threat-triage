import pytest

from threat_triage.risk.evidence_builder import (
    build_evidence_summary,
    build_risk_evidence,
)
from threat_triage.risk.models import (
    MLEvidence,
)
from threat_triage.security.models import (
    LanguageFeatures,
    SecurityFeatures,
    SenderFeatures,
    URLFeatures,
)


def build_ml_evidence(
    *,
    label: str = "THREAT",
    probability: float = 0.91,
    threshold: float = 0.7364,
    version: str = "0.1.0",
) -> MLEvidence:
    return MLEvidence(
        predicted_label=label,
        threat_probability=probability,
        decision_threshold=threshold,
        model_name="tfidf-logistic-regression",
        model_version=version,
    )


def build_empty_security_features(
    message_id: str = "msg-001",
) -> SecurityFeatures:
    return SecurityFeatures(
        message_id=message_id,

        url=URLFeatures(
            has_url=False,
            url_count=0,
            uses_ip_address_url=False,
            uses_url_shortener=False,
            suspicious_tld=False,
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
            sender_address="alice@example.com",
            sender_domain="example.com",
            sender_domain_has_digits=False,
            sender_domain_has_hyphen=False,
            free_email_provider=False,
            possible_display_name_mismatch=False,
        ),

        language=LanguageFeatures(
            urgency_language=False,
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


def build_security_features_with_signals(
    message_id: str = "msg-002",
) -> SecurityFeatures:
    return SecurityFeatures(
        message_id=message_id,

        url=URLFeatures(
            has_url=True,
            url_count=1,
            uses_ip_address_url=True,
            uses_url_shortener=False,
            suspicious_tld=True,
            punycode_domain=False,
            excessive_subdomains=False,
            domain_contains_digits=True,
            domain_contains_hyphen=True,
            credential_path_keyword=True,
            extracted_urls=[
                "https://192.0.2.10/login"
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
            financial_request=True,
            verification_request=True,
            account_suspension_language=True,
            password_reset_language=False,
            matched_urgency_terms=[
                "urgent"
            ],
            matched_credential_terms=[
                "password"
            ],
            matched_financial_terms=[
                "payment"
            ],
            matched_verification_terms=[
                "verify account"
            ],
            matched_suspension_terms=[
                "account suspended"
            ],
            matched_password_terms=[],
        ),
    )


def test_build_evidence_summary_no_signals():
    security = build_empty_security_features()

    summary = build_evidence_summary(
        security
    )

    assert summary.total_signal_count == 0
    assert summary.url_signal_count == 0
    assert summary.sender_signal_count == 0
    assert summary.language_signal_count == 0

    assert summary.evidence_categories == []
    assert summary.strong_signals == []


def test_build_evidence_summary_counts_signals():
    security = build_security_features_with_signals()

    summary = build_evidence_summary(
        security
    )

    # URL:
    # ip, suspicious_tld, digits, hyphen, credential_path = 5
    assert summary.url_signal_count == 5

    # Sender:
    # digits, hyphen, display mismatch = 3
    assert summary.sender_signal_count == 3

    # Language:
    # urgency, credentials, financial,
    # verification, suspension = 5
    assert summary.language_signal_count == 5

    assert summary.total_signal_count == 13


def test_build_evidence_summary_assigns_categories():
    security = build_security_features_with_signals()

    summary = build_evidence_summary(
        security
    )

    assert summary.evidence_categories == [
        "URL",
        "SENDER",
        "LANGUAGE",
    ]


def test_build_evidence_summary_extracts_strong_signals():
    security = build_security_features_with_signals()

    summary = build_evidence_summary(
        security
    )

    expected = {
        "url_ip_address",
        "url_suspicious_tld",
        "url_credential_path",
        "sender_display_mismatch",
        "lang_urgency",
        "lang_financial",
        "lang_suspension",
    }

    assert set(
        summary.strong_signals
    ) == expected


def test_weak_signals_are_not_marked_strong():
    security = SecurityFeatures(
        message_id="msg-weak",

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
            credential_path_keyword=False,
            extracted_urls=[
                "https://example-123.com"
            ],
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
            password_reset_language=False,
            matched_urgency_terms=[],
            matched_credential_terms=[
                "password"
            ],
            matched_financial_terms=[],
            matched_verification_terms=[
                "verify"
            ],
            matched_suspension_terms=[],
            matched_password_terms=[],
        ),
    )

    summary = build_evidence_summary(
        security
    )

    assert summary.total_signal_count == 5

    assert summary.strong_signals == []


def test_build_risk_evidence():
    security = build_security_features_with_signals(
        message_id="msg-003"
    )

    ml = build_ml_evidence()

    evidence = build_risk_evidence(
        message_id="msg-003",
        ml_evidence=ml,
        security_features=security,
        feature_version="0.2.0",
    )

    assert evidence.message_id == "msg-003"

    assert evidence.ml is ml
    assert evidence.security is security

    assert evidence.summary.total_signal_count == 13

    assert (
        evidence.provenance.model_version
        == ml.model_version
    )

    assert (
        evidence.provenance.feature_version
        == "0.2.0"
    )


def test_build_risk_evidence_uses_default_feature_version():
    security = build_empty_security_features(
        message_id="msg-004"
    )

    evidence = build_risk_evidence(
        message_id="msg-004",
        ml_evidence=build_ml_evidence(),
        security_features=security,
    )

    assert (
        evidence.provenance.feature_version
        == "0.1.0"
    )


def test_build_risk_evidence_rejects_empty_message_id():
    security = build_empty_security_features(
        message_id="msg-005"
    )

    with pytest.raises(
        ValueError,
        match="message_id must not be empty",
    ):
        build_risk_evidence(
            message_id="",
            ml_evidence=build_ml_evidence(),
            security_features=security,
        )


def test_build_risk_evidence_rejects_message_id_mismatch():
    security = build_empty_security_features(
        message_id="security-id"
    )

    with pytest.raises(
        ValueError,
        match=(
            "message_id must match "
            "SecurityFeatures message_id"
        ),
    ):
        build_risk_evidence(
            message_id="risk-id",
            ml_evidence=build_ml_evidence(),
            security_features=security,
        )


def test_provenance_generated_at_is_timezone_aware():
    security = build_empty_security_features(
        message_id="msg-006"
    )

    evidence = build_risk_evidence(
        message_id="msg-006",
        ml_evidence=build_ml_evidence(),
        security_features=security,
    )

    assert (
        evidence.provenance.generated_at.tzinfo
        is not None
    )


def test_summary_is_deterministic():
    security = build_security_features_with_signals()

    first = build_evidence_summary(
        security
    )

    second = build_evidence_summary(
        security
    )

    assert first == second


def test_strong_signals_are_sorted():
    security = build_security_features_with_signals()

    summary = build_evidence_summary(
        security
    )

    assert (
        summary.strong_signals
        == sorted(
            summary.strong_signals
        )
    )