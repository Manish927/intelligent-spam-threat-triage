import json

import pytest

from threat_triage.agents.tools.sender_tool import (
    SenderToolResult,
    inspect_sender_evidence,
    inspect_sender_evidence_dict,
)


def test_normal_sender_returns_structured_result():
    result = inspect_sender_evidence(
        "Alice Smith <alice@example.com>"
    )

    assert isinstance(
        result,
        SenderToolResult,
    )

    assert (
        result.sender_input
        == "Alice Smith <alice@example.com>"
    )

    assert result.sender_present is True

    assert (
        result.display_name
        == "Alice Smith"
    )

    assert (
        result.sender_address
        == "alice@example.com"
    )

    assert (
        result.sender_domain
        == "example.com"
    )

    assert (
        result.sender_domain_has_digits
        is False
    )

    assert (
        result.sender_domain_has_hyphen
        is False
    )

    assert (
        result.free_email_provider
        is False
    )

    assert (
        result.possible_display_name_mismatch
        is False
    )

    assert result.signal_count == 0
    assert result.evidence == []


def test_plain_email_address_is_supported():
    result = inspect_sender_evidence(
        "alice@example.com"
    )

    assert result.sender_present is True
    assert result.display_name is None
    assert (
        result.sender_address
        == "alice@example.com"
    )
    assert (
        result.sender_domain
        == "example.com"
    )


def test_sender_domain_digits_detected():
    result = inspect_sender_evidence(
        "Support <support@paypa1.example>"
    )

    assert (
        result.sender_domain_has_digits
        is True
    )

    assert (
        "Sender domain contains digits"
        in result.evidence
    )


def test_sender_domain_hyphen_detected():
    result = inspect_sender_evidence(
        "Support <support@paypal-security.example>"
    )

    assert (
        result.sender_domain_has_hyphen
        is True
    )

    assert (
        "Sender domain contains hyphens"
        in result.evidence
    )


def test_free_email_provider_detected():
    result = inspect_sender_evidence(
        "Alice <alice@gmail.com>"
    )

    assert (
        result.free_email_provider
        is True
    )

    assert (
        "Sender uses a configured free-email provider"
        in result.evidence
    )


def test_display_name_mismatch_detected():
    result = inspect_sender_evidence(
        "PayPal Security "
        "<support@random-security.example>"
    )

    assert (
        result.possible_display_name_mismatch
        is True
    )

    assert (
        "Sender display name may conflict with sender domain"
        in result.evidence
    )


def test_matching_display_name_not_flagged():
    result = inspect_sender_evidence(
        "PayPal Security "
        "<support@paypal.com>"
    )

    assert (
        result.possible_display_name_mismatch
        is False
    )


def test_multiple_sender_signals_are_counted():
    result = inspect_sender_evidence(
        "PayPal Security "
        "<support@paypa1-security.example>"
    )

    expected_evidence = {
        "Sender domain contains digits",
        "Sender domain contains hyphens",
        (
            "Sender display name may conflict "
            "with sender domain"
        ),
    }

    assert (
        set(result.evidence)
        == expected_evidence
    )

    assert (
        result.signal_count
        == len(expected_evidence)
    )


def test_malformed_sender_returns_parse_evidence():
    result = inspect_sender_evidence(
        "not-an-email"
    )

    assert (
        result.sender_present
        is False
    )

    assert result.sender_address is None
    assert result.sender_domain is None

    assert (
        "Sender address could not be parsed"
        in result.evidence
    )


def test_leading_and_trailing_whitespace_removed():
    result = inspect_sender_evidence(
        "   Alice <alice@example.com>   "
    )

    assert (
        result.sender_input
        == "Alice <alice@example.com>"
    )


def test_crlf_is_normalized():
    result = inspect_sender_evidence(
        "Alice\r\n<alice@example.com>"
    )

    assert (
        "\r"
        not in result.sender_input
    )

    assert (
        "\n"
        not in result.sender_input
    )


def test_nul_character_removed():
    result = inspect_sender_evidence(
        "Ali\x00ce <alice@example.com>"
    )

    assert (
        "\x00"
        not in result.sender_input
    )


def test_dictionary_wrapper_returns_plain_dict():
    result = inspect_sender_evidence_dict(
        "Alice <alice@gmail.com>"
    )

    assert isinstance(
        result,
        dict,
    )

    assert result["sender_present"] is True

    assert (
        result["sender_address"]
        == "alice@gmail.com"
    )

    assert (
        result["sender_domain"]
        == "gmail.com"
    )

    assert (
        result["free_email_provider"]
        is True
    )

    assert isinstance(
        result["evidence"],
        list,
    )


def test_dictionary_wrapper_is_json_serializable():
    result = inspect_sender_evidence_dict(
        "Alice <alice@gmail.com>"
    )

    serialized = json.dumps(
        result
    )

    assert isinstance(
        serialized,
        str,
    )


def test_none_sender_rejected():
    with pytest.raises(
        ValueError,
        match="sender must not be None",
    ):
        inspect_sender_evidence(
            None  # type: ignore[arg-type]
        )


def test_empty_sender_rejected():
    with pytest.raises(
        ValueError,
        match="sender must not be empty",
    ):
        inspect_sender_evidence(
            ""
        )


def test_whitespace_only_sender_rejected():
    with pytest.raises(
        ValueError,
        match="sender must not be empty",
    ):
        inspect_sender_evidence(
            "   "
        )


def test_sender_that_becomes_empty_after_normalization_rejected():
    with pytest.raises(
        ValueError,
        match="sender must not be empty",
    ):
        inspect_sender_evidence(
            "\x00"
        )


def test_oversized_sender_rejected():
    sender = (
        "A" * 2050
    )

    with pytest.raises(
        ValueError,
        match=(
            "sender exceeds maximum supported length"
        ),
    ):
        inspect_sender_evidence(
            sender
        )


def test_tool_does_not_return_malicious_verdict():
    result = inspect_sender_evidence_dict(
        "PayPal Security "
        "<support@paypa1-security.example>"
    )

    assert "malicious" not in result
    assert "benign" not in result
    assert "classification" not in result
    assert "verdict" not in result
    assert "risk_score" not in result


def test_tool_returns_evidence_not_decision():
    result = inspect_sender_evidence(
        "PayPal Security "
        "<support@paypa1-security.example>"
    )

    assert result.signal_count > 0
    assert len(result.evidence) > 0

    assert not hasattr(
        result,
        "decision",
    )

    assert not hasattr(
        result,
        "disposition",
    )


def test_signal_count_matches_evidence_length():
    result = inspect_sender_evidence(
        "PayPal Security "
        "<support@paypa1-security.example>"
    )

    assert (
        result.signal_count
        == len(result.evidence)
    )


def test_result_preserves_normalized_email_case():
    result = inspect_sender_evidence(
        "Alice <ALICE@EXAMPLE.COM>"
    )

    assert (
        result.sender_address
        == "alice@example.com"
    )

    assert (
        result.sender_domain
        == "example.com"
    )


def test_unknown_display_name_is_not_flagged():
    result = inspect_sender_evidence(
        "Accounts Team "
        "<accounts@random-security.example>"
    )

    assert (
        result.possible_display_name_mismatch
        is False
    )


def test_free_provider_is_evidence_only():
    result = inspect_sender_evidence(
        "Alice <alice@gmail.com>"
    )

    assert result.free_email_provider is True

    assert (
        result.signal_count
        == 1
    )

    assert not hasattr(
        result,
        "risk_score",
    )


def test_sender_tool_result_rejects_negative_signal_count():
    with pytest.raises(
        ValueError,
        match=(
            "signal_count must not be negative"
        ),
    ):
        SenderToolResult(
            sender_input="alice@example.com",
            sender_present=True,
            display_name=None,
            sender_address="alice@example.com",
            sender_domain="example.com",
            sender_domain_has_digits=False,
            sender_domain_has_hyphen=False,
            free_email_provider=False,
            possible_display_name_mismatch=False,
            signal_count=-1,
        )


def test_sender_tool_result_rejects_empty_sender_input():
    with pytest.raises(
        ValueError,
        match=(
            "sender_input must not be empty"
        ),
    ):
        SenderToolResult(
            sender_input="",
            sender_present=False,
            display_name=None,
            sender_address=None,
            sender_domain=None,
            sender_domain_has_digits=False,
            sender_domain_has_hyphen=False,
            free_email_provider=False,
            possible_display_name_mismatch=False,
            signal_count=0,
        )