import pytest

from threat_triage.security.sender_analyzer import (
    analyze_sender,
    detect_display_name_mismatch,
    domain_has_digits,
    domain_has_hyphen,
    extract_display_name,
    extract_sender_address,
    extract_sender_domain,
    is_free_email_provider,
)


@pytest.mark.parametrize(
    "sender, expected",
    [
        (
            "Alice <alice@example.com>",
            "alice@example.com",
        ),
        (
            "alice@example.com",
            "alice@example.com",
        ),
        (
            "ALICE@EXAMPLE.COM",
            "alice@example.com",
        ),
        (
            "  Alice <Alice@Example.com>  ",
            "alice@example.com",
        ),
    ],
)
def test_extract_sender_address_valid(sender, expected):
    assert extract_sender_address(sender) == expected


@pytest.mark.parametrize(
    "sender",
    [
        None,
        "",
        "not-an-email",
        "Alice <not-an-email>",
        "@example.com",
        "alice@",
    ],
)
def test_extract_sender_address_invalid(sender):
    assert extract_sender_address(sender) is None


@pytest.mark.parametrize(
    "address, expected",
    [
        (
            "alice@example.com",
            "example.com",
        ),
        (
            "support@security.example.com",
            "security.example.com",
        ),
        (
            "user@EXAMPLE.COM",
            "example.com",
        ),
    ],
)
def test_extract_sender_domain(address, expected):
    assert extract_sender_domain(address) == expected


@pytest.mark.parametrize(
    "address",
    [
        None,
        "",
        "not-an-email",
    ],
)
def test_extract_sender_domain_invalid(address):
    assert extract_sender_domain(address) is None


def test_domain_has_digits_true():
    assert domain_has_digits(
        "paypa1-security.example"
    ) is True


def test_domain_has_digits_false():
    assert domain_has_digits(
        "paypal-security.example"
    ) is False


def test_domain_has_digits_none():
    assert domain_has_digits(None) is False


def test_domain_has_hyphen_true():
    assert domain_has_hyphen(
        "paypal-security.example"
    ) is True


def test_domain_has_hyphen_false():
    assert domain_has_hyphen(
        "paypal.example"
    ) is False


def test_domain_has_hyphen_none():
    assert domain_has_hyphen(None) is False


@pytest.mark.parametrize(
    "domain",
    [
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
    ],
)
def test_free_email_provider_detected(domain):
    assert is_free_email_provider(domain) is True


def test_business_domain_is_not_free_provider():
    assert is_free_email_provider(
        "example.com"
    ) is False


def test_free_email_provider_none():
    assert is_free_email_provider(None) is False


@pytest.mark.parametrize(
    "sender, expected",
    [
        (
            "PayPal Security <support@example.com>",
            "PayPal Security",
        ),
        (
            "Alice Smith <alice@example.com>",
            "Alice Smith",
        ),
        (
            "alice@example.com",
            None,
        ),
        (
            None,
            None,
        ),
    ],
)
def test_extract_display_name(sender, expected):
    assert extract_display_name(sender) == expected


def test_display_name_mismatch_detected():
    sender = (
        "PayPal Security "
        "<support@random-security.example>"
    )

    assert (
        detect_display_name_mismatch(sender)
        is True
    )


def test_display_name_matches_domain():
    sender = (
        "PayPal Security "
        "<support@paypal.com>"
    )

    assert (
        detect_display_name_mismatch(sender)
        is False
    )


def test_display_name_without_known_brand_not_flagged():
    sender = (
        "Accounts Team "
        "<accounts@random-security.example>"
    )

    assert (
        detect_display_name_mismatch(sender)
        is False
    )


def test_display_name_gmail_mismatch_detected():
    sender = (
        "Gmail Security "
        "<alert@random-domain.example>"
    )

    assert (
        detect_display_name_mismatch(sender)
        is True
    )


def test_display_name_gmail_matches_domain():
    sender = (
        "Gmail Security "
        "<alert@gmail.com>"
    )

    assert (
        detect_display_name_mismatch(sender)
        is False
    )


def test_analyze_sender_missing():
    result = analyze_sender(None)

    assert result.sender_present is False
    assert result.sender_address is None
    assert result.sender_domain is None
    assert result.sender_domain_has_digits is False
    assert result.sender_domain_has_hyphen is False
    assert result.free_email_provider is False
    assert (
        result.possible_display_name_mismatch
        is False
    )


def test_analyze_normal_business_sender():
    result = analyze_sender(
        "Alice Smith <alice@example.com>"
    )

    assert result.sender_present is True
    assert (
        result.sender_address
        == "alice@example.com"
    )
    assert result.sender_domain == "example.com"
    assert result.sender_domain_has_digits is False
    assert result.sender_domain_has_hyphen is False
    assert result.free_email_provider is False
    assert (
        result.possible_display_name_mismatch
        is False
    )


def test_analyze_free_email_sender():
    result = analyze_sender(
        "Alice <alice@gmail.com>"
    )

    assert result.sender_present is True
    assert result.sender_domain == "gmail.com"
    assert result.free_email_provider is True


def test_analyze_suspicious_sender_domain():
    result = analyze_sender(
        "Support "
        "<help@paypa1-security.example>"
    )

    assert result.sender_present is True
    assert (
        result.sender_domain
        == "paypa1-security.example"
    )
    assert (
        result.sender_domain_has_digits
        is True
    )
    assert (
        result.sender_domain_has_hyphen
        is True
    )


def test_analyze_brand_mismatch_sender():
    result = analyze_sender(
        "PayPal Security "
        "<support@paypa1-security.example>"
    )

    assert result.sender_present is True

    assert (
        result.possible_display_name_mismatch
        is True
    )