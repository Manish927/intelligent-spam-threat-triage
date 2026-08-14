import pytest

from threat_triage.agents.tools.url_tool import (
    URLToolResult,
    inspect_url_evidence,
    inspect_url_evidence_dict,
)


def test_normal_url_returns_structured_result():
    result = inspect_url_evidence(
        "https://example.com/docs"
    )

    assert isinstance(
        result,
        URLToolResult,
    )

    assert (
        result.url
        == "https://example.com/docs"
    )

    assert (
        result.domain
        == "example.com"
    )

    assert result.signal_count == 0

    assert result.has_ip_address is False
    assert result.uses_url_shortener is False
    assert result.suspicious_tld is False
    assert result.punycode_domain is False
    assert result.excessive_subdomains is False
    assert result.domain_contains_digits is False
    assert result.domain_contains_hyphen is False
    assert result.credential_path_keyword is False

    assert result.matched_credential_terms == []
    assert result.evidence == []


def test_ip_address_url_detected():
    result = inspect_url_evidence(
        "https://192.0.2.10/login"
    )

    assert result.has_ip_address is True

    assert (
        "URL uses a literal IP address"
        in result.evidence
    )


def test_suspicious_tld_detected():
    result = inspect_url_evidence(
        "https://account-security.xyz/login"
    )

    assert (
        result.suspicious_tld
        is True
    )

    assert (
        "URL uses a configured suspicious TLD"
        in result.evidence
    )


def test_punycode_domain_detected():
    result = inspect_url_evidence(
        "https://xn--paypl-7ve.example/login"
    )

    assert (
        result.punycode_domain
        is True
    )

    assert (
        "URL contains an IDNA/punycode domain"
        in result.evidence
    )


def test_url_shortener_detected():
    result = inspect_url_evidence(
        "https://bit.ly/example123"
    )

    assert (
        result.uses_url_shortener
        is True
    )

    assert (
        "URL uses a known shortening service"
        in result.evidence
    )


def test_excessive_subdomains_detected():
    result = inspect_url_evidence(
        "https://login.secure.account.example.com"
    )

    assert (
        result.excessive_subdomains
        is True
    )

    assert (
        "URL contains an unusually deep "
        "subdomain structure"
        in result.evidence
    )


def test_domain_digits_detected():
    result = inspect_url_evidence(
        "https://paypa1.example/login"
    )

    assert (
        result.domain_contains_digits
        is True
    )

    assert (
        "URL domain contains digits"
        in result.evidence
    )


def test_domain_hyphen_detected():
    result = inspect_url_evidence(
        "https://paypal-security.example/login"
    )

    assert (
        result.domain_contains_hyphen
        is True
    )

    assert (
        "URL domain contains hyphens"
        in result.evidence
    )


def test_credential_path_detected():
    result = inspect_url_evidence(
        "https://example.com/login/verify"
    )

    assert (
        result.credential_path_keyword
        is True
    )

    assert (
        "login"
        in result.matched_credential_terms
    )

    assert (
        "verify"
        in result.matched_credential_terms
    )

    assert (
        "URL contains credential-related path terms"
        in result.evidence
    )


def test_multiple_signals_are_counted():
    result = inspect_url_evidence(
        "https://paypa1-security.xyz/login"
    )

    expected_evidence = {
        "URL uses a configured suspicious TLD",
        "URL domain contains digits",
        "URL domain contains hyphens",
        "URL contains credential-related path terms",
    }

    assert (
        set(result.evidence)
        == expected_evidence
    )

    assert (
        result.signal_count
        == len(expected_evidence)
    )


def test_ip_address_plus_credential_path():
    result = inspect_url_evidence(
        "https://192.0.2.10/account/login"
    )

    assert result.has_ip_address is True

    assert (
        result.credential_path_keyword
        is True
    )

    assert (
        result.signal_count
        >= 2
    )


def test_www_url_is_normalized():
    result = inspect_url_evidence(
        "www.example.com/login"
    )

    assert (
        result.url
        == "http://www.example.com/login"
    )

    assert (
        result.domain
        == "www.example.com"
    )

    assert (
        result.credential_path_keyword
        is True
    )


def test_leading_and_trailing_whitespace_is_removed():
    result = inspect_url_evidence(
        "   https://example.com/login   "
    )

    assert (
        result.url
        == "https://example.com/login"
    )


def test_dictionary_wrapper_returns_plain_dict():
    result = inspect_url_evidence_dict(
        "https://example.xyz/login"
    )

    assert isinstance(
        result,
        dict,
    )

    assert result["url"] == (
        "https://example.xyz/login"
    )

    assert result["domain"] == (
        "example.xyz"
    )

    assert (
        result["suspicious_tld"]
        is True
    )

    assert (
        result["credential_path_keyword"]
        is True
    )

    assert isinstance(
        result["evidence"],
        list,
    )


def test_dictionary_wrapper_is_json_serializable():
    import json

    result = inspect_url_evidence_dict(
        "https://example.xyz/login"
    )

    serialized = json.dumps(
        result
    )

    assert isinstance(
        serialized,
        str,
    )


def test_empty_url_rejected():
    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        inspect_url_evidence(
            ""
        )


def test_whitespace_only_url_rejected():
    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        inspect_url_evidence(
            "   "
        )


def test_none_url_rejected():
    with pytest.raises(
        ValueError,
        match="url must not be None",
    ):
        inspect_url_evidence(
            None  # type: ignore[arg-type]
        )


def test_oversized_url_rejected():
    oversized = (
        "https://example.com/"
        + "a" * 5000
    )

    with pytest.raises(
        ValueError,
        match=(
            "url exceeds maximum supported length"
        ),
    ):
        inspect_url_evidence(
            oversized
        )


@pytest.mark.parametrize(
    "value",
    [
        "not-a-url",
        "ftp://example.com/file",
        "example.com/login",
    ],
)
def test_unsupported_or_unparseable_url_rejected(
    value,
):
    with pytest.raises(
        ValueError,
        match=(
            "No supported URL could be extracted"
        ),
    ):
        inspect_url_evidence(
            value
        )


def test_tool_does_not_return_malicious_verdict():
    """
    The agent-facing tool must return evidence,
    not a final malicious/benign classification.
    """

    result = inspect_url_evidence_dict(
        "https://paypa1-security.xyz/login"
    )

    assert "malicious" not in result
    assert "benign" not in result
    assert "classification" not in result
    assert "verdict" not in result
    assert "risk_score" not in result


def test_tool_returns_evidence_not_decision():
    result = inspect_url_evidence(
        "https://example.xyz/login"
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


def test_credential_terms_are_preserved():
    result = inspect_url_evidence(
        "https://example.com/"
        "login/verify/account"
    )

    assert set(
        result.matched_credential_terms
    ).issuperset(
        {
            "login",
            "verify",
            "account",
        }
    )


def test_evidence_count_matches_evidence_list():
    result = inspect_url_evidence(
        "https://paypa1-security.xyz/login"
    )

    assert (
        result.signal_count
        == len(result.evidence)
    )


def test_result_preserves_normalized_domain():
    result = inspect_url_evidence(
        "https://SECURE.Example.COM/login"
    )

    assert (
        result.domain
        == "secure.example.com"
    )


def test_normal_url_with_query_is_supported():
    result = inspect_url_evidence(
        "https://example.com/"
        "page?id=123"
    )

    assert (
        result.domain
        == "example.com"
    )

    assert (
        result.has_ip_address
        is False
    )


def test_query_credential_term_is_detected():
    result = inspect_url_evidence(
        "https://example.com/page"
        "?action=verify"
    )

    assert (
        result.credential_path_keyword
        is True
    )

    assert (
        "verify"
        in result.matched_credential_terms
    )


def test_url_tool_reuses_deterministic_normalization():
    """
    The agent tool should expose the same normalization
    behavior as the deterministic URL analyzer.
    """

    result = inspect_url_evidence(
        "www.example.com/account"
    )

    assert (
        result.url
        == "http://www.example.com/account"
    )

    assert (
        result.domain
        == "www.example.com"
    )


def test_url_tool_result_rejects_negative_signal_count():
    with pytest.raises(
        ValueError,
        match=(
            "signal_count must not be negative"
        ),
    ):
        URLToolResult(
            url="https://example.com",
            domain="example.com",
            signal_count=-1,
            has_ip_address=False,
            uses_url_shortener=False,
            suspicious_tld=False,
            punycode_domain=False,
            excessive_subdomains=False,
            domain_contains_digits=False,
            domain_contains_hyphen=False,
            credential_path_keyword=False,
        )


def test_url_tool_result_rejects_empty_url():
    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        URLToolResult(
            url="",
            domain=None,
            signal_count=0,
            has_ip_address=False,
            uses_url_shortener=False,
            suspicious_tld=False,
            punycode_domain=False,
            excessive_subdomains=False,
            domain_contains_digits=False,
            domain_contains_hyphen=False,
            credential_path_keyword=False,
        )