from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Set
from urllib.parse import urlparse

from .models import URLFeatures


URL_PATTERN = re.compile(
    r"""(?ix)
    \b(
        https?://[^\s<>"']+
        |
        www\.[^\s<>"']+
    )
    """
)


KNOWN_URL_SHORTENERS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}


SUSPICIOUS_TLDS: Set[str] = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "work",
    "support",
    "country",
    "stream",
    "download",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
}


CREDENTIAL_PATH_KEYWORDS: Set[str] = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "passwd",
    "credential",
    "credentials",
    "secure",
    "security",
    "auth",
    "authentication",
    "update",
    "confirm",
}


def analyze_urls(
    subject: str | None,
    body: str | None,
) -> URLFeatures:
    """
    Extract and analyze URL-related security evidence from an email.

    This function returns observable URL characteristics only.
    It does not assign a risk score or make a security decision.
    """

    text = _combine_text(
        subject=subject,
        body=body,
    )

    extracted_urls = extract_urls(text)

    domains = [
        domain
        for url in extracted_urls
        if (domain := extract_domain(url))
    ]

    matched_credential_terms = sorted(
        _find_credential_path_terms(
            extracted_urls
        )
    )

    return URLFeatures(
        has_url=bool(extracted_urls),
        url_count=len(extracted_urls),
        uses_ip_address_url=any(
            is_ip_address_domain(domain)
            for domain in domains
        ),
        uses_url_shortener=any(
            is_url_shortener(domain)
            for domain in domains
        ),
        suspicious_tld=any(
            has_suspicious_tld(domain)
            for domain in domains
        ),
        punycode_domain=any(
            has_punycode(domain)
            for domain in domains
        ),
        excessive_subdomains=any(
            has_excessive_subdomains(domain)
            for domain in domains
        ),
        domain_contains_digits=any(
            domain_has_digits(domain)
            for domain in domains
        ),
        domain_contains_hyphen=any(
            domain_has_hyphen(domain)
            for domain in domains
        ),
        credential_path_keyword=bool(
            matched_credential_terms
        ),
        extracted_urls=extracted_urls,
        matched_credential_terms=(
            matched_credential_terms
        ),
    )


def extract_urls(
    text: str | None,
) -> List[str]:
    """
    Extract HTTP/HTTPS and www-style URLs from text.

    Returned URLs are normalized enough for parsing but are not
    dereferenced or visited.
    """

    if not text:
        return []

    matches = URL_PATTERN.findall(text)

    normalized_urls: List[str] = []

    for value in matches:
        cleaned = _strip_trailing_punctuation(
            value.strip()
        )

        if cleaned.startswith("www."):
            cleaned = f"http://{cleaned}"

        normalized_urls.append(cleaned)

    return normalized_urls


def extract_domain(
    url: str,
) -> str | None:
    """
    Extract normalized hostname from a URL.
    """

    if not url:
        return None

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower().rstrip(".")

    except ValueError:
        return None


def is_ip_address_domain(
    domain: str | None,
) -> bool:
    """
    Return True when the hostname is a literal IPv4 or IPv6 address.
    """

    if not domain:
        return False

    try:
        ipaddress.ip_address(domain)
        return True

    except ValueError:
        return False


def is_url_shortener(
    domain: str | None,
) -> bool:
    """
    Return True when the domain matches a known URL shortener.
    """

    if not domain:
        return False

    domain = domain.lower()

    return (
        domain in KNOWN_URL_SHORTENERS
        or any(
            domain.endswith(
                f".{shortener}"
            )
            for shortener in KNOWN_URL_SHORTENERS
        )
    )


def has_suspicious_tld(
    domain: str | None,
) -> bool:
    """
    Return True when the hostname uses a configured suspicious TLD.

    This is a heuristic signal only and does not imply maliciousness.
    """

    if not domain:
        return False

    parts = domain.lower().split(".")

    if len(parts) < 2:
        return False

    tld = parts[-1]

    return tld in SUSPICIOUS_TLDS


def has_punycode(
    domain: str | None,
) -> bool:
    """
    Return True when the hostname contains an IDNA punycode label.
    """

    if not domain:
        return False

    return any(
        label.lower().startswith("xn--")
        for label in domain.split(".")
    )


def has_excessive_subdomains(
    domain: str | None,
    max_labels: int = 4,
) -> bool:
    """
    Detect unusually deep hostname structures.

    Example:

        login.secure.account.example.com

    has five labels and will be flagged when max_labels=4.

    This is a heuristic signal, not proof of maliciousness.
    """

    if not domain:
        return False

    labels = [
        label
        for label in domain.split(".")
        if label
    ]

    return len(labels) > max_labels


def domain_has_digits(
    domain: str | None,
) -> bool:
    """
    Return True when any domain label contains a digit.
    """

    if not domain:
        return False

    return any(
        character.isdigit()
        for character in domain
    )


def domain_has_hyphen(
    domain: str | None,
) -> bool:
    """
    Return True when the hostname contains a hyphen.
    """

    if not domain:
        return False

    return "-" in domain


def _find_credential_path_terms(
    urls: Iterable[str],
) -> Set[str]:
    """
    Search URL path/query components for credential-related terms.
    """

    matched_terms: Set[str] = set()

    for url in urls:
        try:
            parsed = urlparse(url)

            searchable = " ".join(
                [
                    parsed.path or "",
                    parsed.query or "",
                    parsed.fragment or "",
                ]
            ).lower()

        except ValueError:
            continue

        for keyword in CREDENTIAL_PATH_KEYWORDS:
            if keyword in searchable:
                matched_terms.add(keyword)

    return matched_terms


def _combine_text(
    subject: str | None,
    body: str | None,
) -> str:
    """
    Combine nullable subject/body for URL extraction.
    """

    parts = [
        value
        for value in (subject, body)
        if value
    ]

    return "\n".join(parts)


def _strip_trailing_punctuation(
    value: str,
) -> str:
    """
    Remove common punctuation captured after URLs in prose.
    """

    return value.rstrip(
        ".,;:!?)]}>\"'"
    )