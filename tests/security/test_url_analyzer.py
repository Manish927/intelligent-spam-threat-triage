import pytest

from threat_triage.security.url_analyzer import (
    analyze_urls,
    domain_has_digits,
    domain_has_hyphen,
    extract_domain,
    extract_urls,
    has_excessive_subdomains,
    has_punycode,
    has_suspicious_tld,
    is_ip_address_domain,
    is_url_shortener,
)


def test_extract_single_https_url():
    text = "Please visit https://example.com/login"

    urls = extract_urls(text)

    assert urls == [
        "https://example.com/login"
    ]


def test_extract_www_url_adds_scheme():
    text = "Visit www.example.com/account"

    urls = extract_urls(text)

    assert urls == [
        "http://www.example.com/account"
    ]


def test_extract_multiple_urls():
    text = """
    Visit https://example.com/login
    and https://security.example.org/reset
    """

    urls = extract_urls(text)

    assert len(urls) == 2

    assert "https://example.com/login" in urls

    assert (
        "https://security.example.org/reset"
        in urls
    )


def test_extract_url_removes_trailing_punctuation():
    text = (
        "Click https://example.com/login, "
        "to continue."
    )

    urls = extract_urls(text)

    assert urls == [
        "https://example.com/login"
    ]


def test_extract_urls_from_empty_text():
    assert extract_urls(None) == []
    assert extract_urls("") == []


def test_extract_domain():
    domain = extract_domain(
        "https://secure.example.com/login"
    )

    assert domain == "secure.example.com"


def test_extract_domain_normalizes_case():
    domain = extract_domain(
        "https://SECURE.Example.COM/login"
    )

    assert domain == "secure.example.com"


def test_ip_address_domain_ipv4():
    assert is_ip_address_domain(
        "192.0.2.10"
    ) is True


def test_normal_domain_is_not_ip():
    assert is_ip_address_domain(
        "example.com"
    ) is False


@pytest.mark.parametrize(
    "domain",
    [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "rb.gy",
    ],
)
def test_known_url_shorteners(domain):
    assert is_url_shortener(domain) is True


def test_normal_domain_is_not_shortener():
    assert is_url_shortener(
        "example.com"
    ) is False


@pytest.mark.parametrize(
    "domain",
    [
        "example.xyz",
        "example.click",
        "example.top",
        "example.zip",
    ],
)
def test_suspicious_tlds(domain):
    assert has_suspicious_tld(
        domain
    ) is True


def test_normal_tld_is_not_suspicious():
    assert has_suspicious_tld(
        "example.com"
    ) is False


def test_punycode_domain_detected():
    assert has_punycode(
        "xn--paypal-4ve.example"
    ) is True


def test_normal_domain_is_not_punycode():
    assert has_punycode(
        "paypal.example"
    ) is False


def test_excessive_subdomains_detected():
    domain = (
        "login.secure.account.example.com"
    )

    assert has_excessive_subdomains(
        domain
    ) is True


def test_normal_subdomain_depth():
    assert has_excessive_subdomains(
        "secure.example.com"
    ) is False


def test_domain_with_digits():
    assert domain_has_digits(
        "paypa1-security.example"
    ) is True


def test_domain_without_digits():
    assert domain_has_digits(
        "paypal-security.example"
    ) is False


def test_domain_with_hyphen():
    assert domain_has_hyphen(
        "paypal-security.example"
    ) is True


def test_domain_without_hyphen():
    assert domain_has_hyphen(
        "paypal.example"
    ) is False


def test_analyze_email_without_url():
    result = analyze_urls(
        subject="Project Update",
        body="Meeting is scheduled for tomorrow.",
    )

    assert result.has_url is False
    assert result.url_count == 0
    assert result.extracted_urls == []

    assert (
        result.uses_ip_address_url
        is False
    )

    assert (
        result.credential_path_keyword
        is False
    )


def test_analyze_normal_benign_url():
    result = analyze_urls(
        subject="Documentation",
        body=(
            "Please review "
            "https://docs.example.com/project"
        ),
    )

    assert result.has_url is True
    assert result.url_count == 1

    assert (
        result.uses_ip_address_url
        is False
    )

    assert (
        result.uses_url_shortener
        is False
    )

    assert (
        result.suspicious_tld
        is False
    )

    assert (
        result.credential_path_keyword
        is False
    )


def test_analyze_ip_address_login_url():
    result = analyze_urls(
        subject="Account Alert",
        body=(
            "Login immediately at "
            "https://192.0.2.10/login/verify"
        ),
    )

    assert result.has_url is True
    assert result.url_count == 1

    assert (
        result.uses_ip_address_url
        is True
    )

    assert (
        result.credential_path_keyword
        is True
    )

    assert "login" in (
        result.matched_credential_terms
    )

    assert "verify" in (
        result.matched_credential_terms
    )


def test_analyze_url_shortener():
    result = analyze_urls(
        subject="Please review",
        body="Open https://bit.ly/example123",
    )

    assert result.has_url is True

    assert (
        result.uses_url_shortener
        is True
    )


def test_analyze_suspicious_tld():
    result = analyze_urls(
        subject="Security Notice",
        body=(
            "Visit "
            "https://account-security.xyz/login"
        ),
    )

    assert (
        result.suspicious_tld
        is True
    )

    assert (
        result.domain_contains_hyphen
        is True
    )


def test_analyze_domain_with_digits():
    result = analyze_urls(
        subject="Verification",
        body=(
            "Visit "
            "https://paypa1.example/verify"
        ),
    )

    assert (
        result.domain_contains_digits
        is True
    )


def test_analyze_punycode_domain():
    result = analyze_urls(
        subject="Security",
        body=(
            "Visit "
            "https://xn--paypl-7ve.example/login"
        ),
    )

    assert (
        result.punycode_domain
        is True
    )


def test_analyze_excessive_subdomains():
    result = analyze_urls(
        subject="Security",
        body=(
            "Visit "
            "https://login.secure.account.example.com"
        ),
    )

    assert (
        result.excessive_subdomains
        is True
    )


def test_analyze_urls_from_subject_and_body():
    result = analyze_urls(
        subject=(
            "Review https://example.com/login"
        ),
        body=(
            "Backup link "
            "https://example.org/account"
        ),
    )

    assert result.url_count == 2

    assert (
        result.credential_path_keyword
        is True
    )


def test_multiple_credential_terms_are_deduplicated():
    result = analyze_urls(
        subject="Account Security",
        body=(
            "https://example.com/"
            "login/login/verify/verify"
        ),
    )

    assert (
        result.matched_credential_terms
        == ["login", "verify"]
    )