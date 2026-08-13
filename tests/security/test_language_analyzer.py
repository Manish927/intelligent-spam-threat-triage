import pytest

from threat_triage.security.language_analyzer import (
    analyze_language,
)


def test_analyze_empty_message():
    result = analyze_language(
        subject=None,
        body=None,
    )

    assert result.urgency_language is False
    assert result.credential_request is False
    assert result.financial_request is False
    assert result.verification_request is False
    assert result.account_suspension_language is False
    assert result.password_reset_language is False

    assert result.matched_urgency_terms == []
    assert result.matched_credential_terms == []
    assert result.matched_financial_terms == []
    assert result.matched_verification_terms == []
    assert result.matched_suspension_terms == []
    assert result.matched_password_terms == []


def test_normal_business_message_has_no_security_language():
    result = analyze_language(
        subject="Project status meeting",
        body=(
            "Hi team, the project meeting is scheduled "
            "for tomorrow at 10 AM."
        ),
    )

    assert result.urgency_language is False
    assert result.credential_request is False
    assert result.financial_request is False
    assert result.verification_request is False
    assert result.account_suspension_language is False
    assert result.password_reset_language is False


@pytest.mark.parametrize(
    "text, expected_term",
    [
        (
            "URGENT: Please review this message.",
            "urgent",
        ),
        (
            "Respond immediately.",
            "immediately",
        ),
        (
            "Act now to avoid interruption.",
            "act now",
        ),
        (
            "Please respond as soon as possible.",
            "as soon as possible",
        ),
        (
            "Complete this within 24 hours.",
            "within 24 hours",
        ),
        (
            "This is a limited time opportunity.",
            "limited time",
        ),
        (
            "Final notice regarding your account.",
            "final notice",
        ),
    ],
)
def test_urgency_language_detected(
    text,
    expected_term,
):
    result = analyze_language(
        subject=text,
        body=None,
    )

    assert result.urgency_language is True
    assert (
        expected_term
        in result.matched_urgency_terms
    )


@pytest.mark.parametrize(
    "text, expected_term",
    [
        (
            "Enter your password to continue.",
            "password",
        ),
        (
            "Please provide your username.",
            "username",
        ),
        (
            "Confirm your credentials.",
            "credentials",
        ),
        (
            "Login to your account.",
            "login",
        ),
        (
            "Please log in to continue.",
            "login",
        ),
        (
            "Sign in to verify your account.",
            "sign in",
        ),
        (
            "Verify your password immediately.",
            "verify your password",
        ),
        (
            "Confirm your password to continue.",
            "confirm your password",
        ),
    ],
)
def test_credential_language_detected(
    text,
    expected_term,
):
    result = analyze_language(
        subject=None,
        body=text,
    )

    assert result.credential_request is True
    assert (
        expected_term
        in result.matched_credential_terms
    )


@pytest.mark.parametrize(
    "text, expected_term",
    [
        (
            "Please update your bank account.",
            "bank account",
        ),
        (
            "Enter your credit card details.",
            "credit card",
        ),
        (
            "Your debit card requires verification.",
            "debit card",
        ),
        (
            "Your payment has failed.",
            "payment",
        ),
        (
            "Complete the wire transfer today.",
            "wire transfer",
        ),
        (
            "Please review the attached invoice.",
            "invoice",
        ),
        (
            "Your refund is ready.",
            "refund",
        ),
        (
            "Update your billing information.",
            "billing",
        ),
    ],
)
def test_financial_language_detected(
    text,
    expected_term,
):
    result = analyze_language(
        subject=None,
        body=text,
    )

    assert result.financial_request is True
    assert (
        expected_term
        in result.matched_financial_terms
    )


@pytest.mark.parametrize(
    "text, expected_term",
    [
        (
            "Verify your information.",
            "verify",
        ),
        (
            "Account verification is required.",
            "verification",
        ),
        (
            "Confirm your identity now.",
            "confirm your identity",
        ),
        (
            "Verify your identity immediately.",
            "verify your identity",
        ),
        (
            "Confirm your account.",
            "confirm account",
        ),
        (
            "Verify your account.",
            "verify account",
        ),
    ],
)
def test_verification_language_detected(
    text,
    expected_term,
):
    result = analyze_language(
        subject=None,
        body=text,
    )

    assert result.verification_request is True
    assert (
        expected_term
        in result.matched_verification_terms
    )


@pytest.mark.parametrize(
    "text, expected_term",
    [
        (
            "Your account has been suspended.",
            "account suspended",
        ),
        (
            "Your account will be suspended.",
            "account suspended",
        ),
        (
            "Your account is locked.",
            "account locked",
        ),
        (
            "Your account will be disabled.",
            "account disabled",
        ),
        (
            "Your access has been restricted.",
            "access restricted",
        ),
        (
            "Your account will be terminated.",
            "account terminated",
        ),
    ],
)
def test_suspension_language_detected(
    text,
    expected_term,
):
    result = analyze_language(
        subject=None,
        body=text,
    )

    assert (
        result.account_suspension_language
        is True
    )

    assert (
        expected_term
        in result.matched_suspension_terms
    )


@pytest.mark.parametrize(
    "text, expected_term",
    [
        (
            "Reset your password now.",
            "reset your password",
        ),
        (
            "A password reset is required.",
            "password reset",
        ),
        (
            "Change your password today.",
            "change your password",
        ),
        (
            "Update your password immediately.",
            "update your password",
        ),
    ],
)
def test_password_reset_language_detected(
    text,
    expected_term,
):
    result = analyze_language(
        subject=None,
        body=text,
    )

    assert (
        result.password_reset_language
        is True
    )

    assert (
        expected_term
        in result.matched_password_terms
    )


def test_case_insensitive_matching():
    result = analyze_language(
        subject="URGENT ACCOUNT NOTICE",
        body=(
            "VERIFY YOUR ACCOUNT IMMEDIATELY."
        ),
    )

    assert result.urgency_language is True
    assert result.verification_request is True

    assert "urgent" in (
        result.matched_urgency_terms
    )

    assert "immediately" in (
        result.matched_urgency_terms
    )

    assert "verify account" in (
        result.matched_verification_terms
    )


def test_subject_and_body_are_both_analyzed():
    result = analyze_language(
        subject="URGENT account notice",
        body=(
            "Verify your identity and "
            "reset your password."
        ),
    )

    assert result.urgency_language is True
    assert result.credential_request is True
    assert result.verification_request is True
    assert result.password_reset_language is True


def test_combined_phishing_style_message():
    result = analyze_language(
        subject=(
            "URGENT: Account Suspension Notice"
        ),
        body=(
            "Your account will be suspended. "
            "Verify your identity immediately "
            "and reset your password."
        ),
    )

    assert result.urgency_language is True

    assert (
        result.credential_request
        is True
    )

    assert (
        result.verification_request
        is True
    )

    assert (
        result.account_suspension_language
        is True
    )

    assert (
        result.password_reset_language
        is True
    )

    assert "urgent" in (
        result.matched_urgency_terms
    )

    assert "immediately" in (
        result.matched_urgency_terms
    )

    assert "verify your identity" in (
        result.matched_verification_terms
    )

    assert "account suspended" in (
        result.matched_suspension_terms
    )

    assert "reset your password" in (
        result.matched_password_terms
    )


def test_financial_and_credential_signals_together():
    result = analyze_language(
        subject="Payment verification required",
        body=(
            "Please sign in and confirm your "
            "credit card information."
        ),
    )

    assert result.financial_request is True
    assert result.credential_request is True
    assert result.verification_request is True

    assert "credit card" in (
        result.matched_financial_terms
    )

    assert "sign in" in (
        result.matched_credential_terms
    )

    assert "verification" in (
        result.matched_verification_terms
    )


def test_duplicate_matches_are_deduplicated():
    result = analyze_language(
        subject="URGENT URGENT",
        body=(
            "This is urgent. "
            "Please act now. "
            "Act now immediately."
        ),
    )

    assert result.urgency_language is True

    assert (
        result.matched_urgency_terms.count(
            "urgent"
        )
        == 1
    )

    assert (
        result.matched_urgency_terms.count(
            "act now"
        )
        == 1
    )


def test_matched_terms_are_sorted():
    result = analyze_language(
        subject="Urgent final notice",
        body=(
            "Please act now immediately."
        ),
    )

    assert (
        result.matched_urgency_terms
        == sorted(
            result.matched_urgency_terms
        )
    )


def test_password_term_can_trigger_credentials_and_password_reset():
    result = analyze_language(
        subject="Password Reset",
        body=(
            "Reset your password immediately."
        ),
    )

    assert result.credential_request is True

    assert (
        result.password_reset_language
        is True
    )

    assert "password" in (
        result.matched_credential_terms
    )

    assert "reset your password" in (
        result.matched_password_terms
    )


def test_invoice_alone_does_not_trigger_credentials():
    result = analyze_language(
        subject="Invoice available",
        body=(
            "Please review the invoice "
            "for last month's services."
        ),
    )

    assert result.financial_request is True
    assert result.credential_request is False
    assert result.urgency_language is False
    assert result.account_suspension_language is False


def test_ordinary_use_of_account_does_not_trigger_suspension():
    result = analyze_language(
        subject="Account summary",
        body=(
            "Your monthly account summary "
            "is now available."
        ),
    )

    assert (
        result.account_suspension_language
        is False
    )


def test_ordinary_password_discussion_triggers_credential_signal_only():
    result = analyze_language(
        subject="Security Training",
        body=(
            "Employees should never share "
            "their password with another person."
        ),
    )

    # The deterministic analyzer detects vocabulary,
    # not malicious intent.
    assert result.credential_request is True

    assert (
        result.password_reset_language
        is False
    )