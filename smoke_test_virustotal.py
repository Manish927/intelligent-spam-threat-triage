from __future__ import annotations

from dotenv import load_dotenv

from threat_triage.agents.tools.threat_intel_tool import (
    IndicatorType,
    lookup_configured_threat_intelligence,
    resolve_threat_intel_provider,
)


load_dotenv()


def print_result(
    *,
    title: str,
    result,
) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

    print(
        "Indicator:",
        result.indicator,
    )

    print(
        "Indicator type:",
        result.indicator_type.value,
    )

    print(
        "Provider:",
        result.provider,
    )

    print(
        "Lookup performed:",
        result.lookup_performed,
    )

    print(
        "Found:",
        result.found,
    )

    print(
        "Reputation:",
        result.reputation.value,
    )

    print(
        "Confidence:",
        result.confidence,
    )

    print(
        "Categories:",
        result.categories,
    )

    print(
        "References:",
        result.references,
    )

    print(
        "Checked at:",
        result.checked_at.isoformat(),
    )

    print(
        "Error:",
        result.error,
    )


def main() -> None:
    provider = (
        resolve_threat_intel_provider()
    )

    print()
    print(
        "Configured threat-intelligence provider:",
        provider.name,
    )

    if provider.name != "virustotal":
        raise RuntimeError(
            "VirusTotal provider was not selected. "
            "Check VIRUSTOTAL_API_KEY in .env."
        )

    # ---------------------------------------------------------
    # 1. DOMAIN LOOKUP
    #
    # Use a well-known domain first so we can validate the
    # provider contract without deliberately querying malware.
    # ---------------------------------------------------------

    domain_result = (
        lookup_configured_threat_intelligence(
            indicator="google.com",
            indicator_type=IndicatorType.DOMAIN,
        )
    )

    print_result(
        title="DOMAIN LOOKUP",
        result=domain_result,
    )

    if (
        domain_result.provider
        != "virustotal"
    ):
        raise RuntimeError(
            "Domain lookup did not use VirusTotal."
        )

    # ---------------------------------------------------------
    # 2. URL LOOKUP
    #
    # GET only.
    #
    # We are not submitting/rescanning the URL.
    # ---------------------------------------------------------

    url_result = (
        lookup_configured_threat_intelligence(
            indicator="https://www.google.com/",
            indicator_type=IndicatorType.URL,
        )
    )

    print_result(
        title="URL LOOKUP",
        result=url_result,
    )

    if (
        url_result.provider
        != "virustotal"
    ):
        raise RuntimeError(
            "URL lookup did not use VirusTotal."
        )

    print()
    print("=" * 70)
    print("VIRUSTOTAL SMOKE TEST COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()