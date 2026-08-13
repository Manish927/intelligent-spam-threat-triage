import pytest

from threat_triage.security.feature_extractor import (
    extract_security_features,
    extract_security_features_from_record,
)


def test_extract_security_features_benign_message():
    result = extract_security_features(
        message_id="msg-001",
        subject="Project Status Meeting",
        body=(
            "Hi team, the project status meeting is "
            "scheduled for tomorrow at 10 AM."
        ),
        sender="Alice Smith <alice@example.com>",
    )

    assert result.message_id == "msg-001"

    # URL evidence
    assert result.url.has_url is False
    assert result.url.url_count == 0

    # Sender evidence
    assert result.sender.sender_present is True
    assert (
        result.sender.sender_address
        == "alice@example.com"
    )
    assert result.sender.sender_domain == "example.com"
    assert result.sender.free_email_provider is False
    assert (
        result.sender.possible_display_name_mismatch
        is False
    )

    # Language evidence
    assert result.language.urgency_language is False
    assert result.language.credential_request is False
    assert result.language.financial_request is False
    assert result.language.verification_request is False
    assert (
        result.language.account_suspension_language
        is False
    )
    assert (
        result.language.password_reset_language
        is False
    )


def test_extract_security_features_phishing_style_message():
    result = extract_security_features(
        message_id="msg-002",
        subject="URGENT: Account Suspension Notice",
        body=(
            "Your account will be suspended. "
            "Verify your identity immediately and "
            "reset your password at "
            "https://paypa1-security.xyz/login/verify"
        ),
        sender=(
            "PayPal Security "
            "<support@paypa1-security.example>"
        ),
    )

    assert result.message_id == "msg-002"

    # URL evidence
    assert result.url.has_url is True
    assert result.url.url_count == 1
    assert result.url.suspicious_tld is True
    assert result.url.domain_contains_digits is True
    assert result.url.domain_contains_hyphen is True
    assert result.url.credential_path_keyword is True

    assert "login" in (
        result.url.matched_credential_terms
    )

    assert "verify" in (
        result.url.matched_credential_terms
    )

    # Sender evidence
    assert result.sender.sender_present is True
    assert (
        result.sender.sender_domain
        == "paypa1-security.example"
    )
    assert (
        result.sender.sender_domain_has_digits
        is True
    )
    assert (
        result.sender.sender_domain_has_hyphen
        is True
    )
    assert (
        result.sender.possible_display_name_mismatch
        is True
    )

    # Language evidence
    assert result.language.urgency_language is True
    assert result.language.credential_request is True
    assert result.language.verification_request is True
    assert (
        result.language.account_suspension_language
        is True
    )
    assert (
        result.language.password_reset_language
        is True
    )

    assert "urgent" in (
        result.language.matched_urgency_terms
    )

    assert "immediately" in (
        result.language.matched_urgency_terms
    )

    assert "verify your identity" in (
        result.language.matched_verification_terms
    )

    assert "account suspended" in (
        result.language.matched_suspension_terms
    )

    assert "reset your password" in (
        result.language.matched_password_terms
    )


def test_extract_security_features_with_missing_optional_fields():
    result = extract_security_features(
        message_id="msg-003",
        subject=None,
        body=None,
        sender=None,
    )

    assert result.message_id == "msg-003"

    assert result.url.has_url is False
    assert result.url.url_count == 0

    assert result.sender.sender_present is False
    assert result.sender.sender_address is None
    assert result.sender.sender_domain is None

    assert result.language.urgency_language is False
    assert result.language.credential_request is False


def test_extract_security_features_rejects_empty_message_id():
    with pytest.raises(
        ValueError,
        match="message_id must not be empty",
    ):
        extract_security_features(
            message_id="",
            subject="Test",
            body="Body",
            sender="alice@example.com",
        )


def test_extract_security_features_rejects_whitespace_message_id():
    with pytest.raises(
        ValueError,
        match="message_id must not be empty",
    ):
        extract_security_features(
            message_id="   ",
            subject="Test",
            body="Body",
            sender="alice@example.com",
        )


def test_extract_security_features_rejects_none_message_id():
    with pytest.raises(
        ValueError,
        match="message_id must not be None",
    ):
        extract_security_features(
            message_id=None,  # type: ignore[arg-type]
            subject="Test",
            body="Body",
            sender="alice@example.com",
        )


def test_extract_security_features_from_canonical_record():
    record = {
        "message_id": "msg-004",
        "subject": "Security Alert",
        "body": (
            "Verify your account at "
            "https://example.com/login"
        ),
        "sender": "Security <security@example.com>",
        "receiver": "user@example.com",
        "timestamp": None,
        "has_url": True,
        "source_dataset": "unit-test",
        "original_label": 1,
        "canonical_label": "THREAT",
        "label_id": 1,
        "combined_text": (
            "Security Alert\n\n"
            "Verify your account at "
            "https://example.com/login"
        ),
    }

    result = extract_security_features_from_record(
        record
    )

    assert result.message_id == "msg-004"

    assert result.url.has_url is True
    assert result.url.url_count == 1

    assert result.sender.sender_present is True
    assert (
        result.sender.sender_domain
        == "example.com"
    )

    assert result.language.verification_request is True
    assert result.language.credential_request is True


def test_extract_security_features_from_record_missing_required_field():
    record = {
        "message_id": "msg-005",
        "subject": "Test",
        "body": "Body",
        # sender is intentionally missing
    }

    with pytest.raises(
        ValueError,
        match="Canonical record is missing required fields",
    ):
        extract_security_features_from_record(
            record
        )


@pytest.mark.parametrize(
    "missing_field",
    [
        "message_id",
        "subject",
        "body",
        "sender",
    ],
)
def test_extract_security_features_from_record_validates_all_required_fields(
    missing_field,
):
    record = {
        "message_id": "msg-006",
        "subject": "Test",
        "body": "Body",
        "sender": "alice@example.com",
    }

    record.pop(missing_field)

    with pytest.raises(ValueError):
        extract_security_features_from_record(
            record
        )


def test_extract_security_features_from_record_empty_strings_become_none():
    record = {
        "message_id": "msg-007",
        "subject": "",
        "body": "   ",
        "sender": "",
    }

    result = extract_security_features_from_record(
        record
    )

    assert result.message_id == "msg-007"

    assert result.url.has_url is False

    assert result.sender.sender_present is False
    assert result.sender.sender_address is None
    assert result.sender.sender_domain is None

    assert result.language.urgency_language is False


def test_feature_extractor_preserves_evidence_separation():
    """
    Ensure the feature extractor returns evidence only.

    It should not expose risk scores or triage decisions.
    """

    result = extract_security_features(
        message_id="msg-008",
        subject="URGENT",
        body=(
            "Verify your password at "
            "https://example.xyz/login"
        ),
        sender="Security <security@example.com>",
    )

    assert not hasattr(
        result,
        "risk_score",
    )

    assert not hasattr(
        result,
        "triage",
    )

    assert not hasattr(
        result,
        "classification",
    )