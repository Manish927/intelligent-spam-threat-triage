from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List, Optional

from threat_triage.security.url_analyzer import (
    analyze_urls,
    extract_domain,
)


@dataclass(frozen=True)
class URLToolResult:
    """
    Structured result returned by the agent-facing URL inspection tool.

    The result contains deterministic evidence only.

    It does not:
        - visit the URL,
        - resolve DNS,
        - follow redirects,
        - query reputation services,
        - download content,
        - classify the URL as malicious.
    """

    url: str
    domain: Optional[str]

    signal_count: int

    has_ip_address: bool
    uses_url_shortener: bool
    suspicious_tld: bool
    punycode_domain: bool
    excessive_subdomains: bool
    domain_contains_digits: bool
    domain_contains_hyphen: bool
    credential_path_keyword: bool

    matched_credential_terms: List[str] = field(
        default_factory=list
    )

    evidence: List[str] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError(
                "url must not be empty"
            )

        if self.signal_count < 0:
            raise ValueError(
                "signal_count must not be negative"
            )


def inspect_url_evidence(
    url: str,
) -> URLToolResult:
    """
    Inspect one URL using the platform's deterministic URL analyzer.

    This function is intentionally suitable for future Google ADK /
    Gemini function calling.

    Parameters
    ----------
    url:
        URL supplied as untrusted message evidence.

    Returns
    -------
    URLToolResult
        Structured deterministic evidence about the URL.

    Security
    --------
    The URL is NEVER visited or dereferenced.

    This tool performs local lexical and structural inspection only.
    """

    normalized_url = _normalize_url_input(
        url
    )

    features = analyze_urls(
        subject=None,
        body=normalized_url,
    )

    if not features.has_url:
        raise ValueError(
            "No supported URL could be extracted"
        )

    inspected_url = features.extracted_urls[0]

    domain = extract_domain(
        inspected_url
    )

    evidence = _build_evidence(
        uses_ip_address_url=(
            features.uses_ip_address_url
        ),
        uses_url_shortener=(
            features.uses_url_shortener
        ),
        suspicious_tld=(
            features.suspicious_tld
        ),
        punycode_domain=(
            features.punycode_domain
        ),
        excessive_subdomains=(
            features.excessive_subdomains
        ),
        domain_contains_digits=(
            features.domain_contains_digits
        ),
        domain_contains_hyphen=(
            features.domain_contains_hyphen
        ),
        credential_path_keyword=(
            features.credential_path_keyword
        ),
    )

    return URLToolResult(
        url=inspected_url,
        domain=domain,

        signal_count=len(
            evidence
        ),

        has_ip_address=(
            features.uses_ip_address_url
        ),

        uses_url_shortener=(
            features.uses_url_shortener
        ),

        suspicious_tld=(
            features.suspicious_tld
        ),

        punycode_domain=(
            features.punycode_domain
        ),

        excessive_subdomains=(
            features.excessive_subdomains
        ),

        domain_contains_digits=(
            features.domain_contains_digits
        ),

        domain_contains_hyphen=(
            features.domain_contains_hyphen
        ),

        credential_path_keyword=(
            features.credential_path_keyword
        ),

        matched_credential_terms=list(
            features.matched_credential_terms
        ),

        evidence=evidence,
    )


def inspect_url_evidence_dict(
    url: str,
) -> dict:
    """
    JSON-friendly wrapper around inspect_url_evidence().

    This wrapper is intended for agent/function-calling integrations
    where plain dictionaries are easier to serialize than dataclasses.
    """

    result = inspect_url_evidence(
        url
    )

    return asdict(
        result
    )


def _normalize_url_input(
    url: str,
) -> str:
    """
    Normalize agent-supplied URL input without dereferencing it.
    """

    if url is None:
        raise ValueError(
            "url must not be None"
        )

    normalized = str(
        url
    ).strip()

    if not normalized:
        raise ValueError(
            "url must not be empty"
        )

    # Keep the input bounded before passing it into parsing logic.
    if len(normalized) > 4096:
        raise ValueError(
            "url exceeds maximum supported length"
        )

    return normalized


def _build_evidence(
    *,
    uses_ip_address_url: bool,
    uses_url_shortener: bool,
    suspicious_tld: bool,
    punycode_domain: bool,
    excessive_subdomains: bool,
    domain_contains_digits: bool,
    domain_contains_hyphen: bool,
    credential_path_keyword: bool,
) -> List[str]:
    """
    Convert URL feature flags into stable, human-readable evidence.
    """

    evidence: List[str] = []

    if uses_ip_address_url:
        evidence.append(
            "URL uses a literal IP address"
        )

    if uses_url_shortener:
        evidence.append(
            "URL uses a known shortening service"
        )

    if suspicious_tld:
        evidence.append(
            "URL uses a configured suspicious TLD"
        )

    if punycode_domain:
        evidence.append(
            "URL contains an IDNA/punycode domain"
        )

    if excessive_subdomains:
        evidence.append(
            "URL contains an unusually deep subdomain structure"
        )

    if domain_contains_digits:
        evidence.append(
            "URL domain contains digits"
        )

    if domain_contains_hyphen:
        evidence.append(
            "URL domain contains hyphens"
        )

    if credential_path_keyword:
        evidence.append(
            "URL contains credential-related path terms"
        )

    return evidence