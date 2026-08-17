import base64

import pytest
import requests

from threat_triage.agents.tools.threat_intel_tool import (
    IndicatorType,
    Reputation,
)
from threat_triage.agents.tools.virustotal_provider import (
    VIRUSTOTAL_API_BASE_URL,
    VirusTotalThreatIntelProvider,
)


class FakeResponse:
    def __init__(
        self,
        *,
        status_code=200,
        payload=None,
    ):
        self.status_code = (
            status_code
        )

        self._payload = (
            payload
            if payload is not None
            else {}
        )

    def json(
        self,
    ):
        return self._payload

    def raise_for_status(
        self,
    ):
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}"
            )


def build_payload(
    *,
    malicious=0,
    suspicious=0,
    harmless=0,
    undetected=0,
    categories=None,
    object_id="object-001",
):
    return {
        "data": {
            "id": object_id,

            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },

                "categories": (
                    categories
                    if categories is not None
                    else {}
                ),
            },
        }
    }


def test_provider_name():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    assert (
        provider.name
        == "virustotal"
    )


def test_missing_api_key_rejected(
    monkeypatch,
):
    monkeypatch.delenv(
        "VIRUSTOTAL_API_KEY",
        raising=False,
    )

    with pytest.raises(
        ValueError,
        match=(
            "VirusTotal API key "
            "is not configured"
        ),
    ):
        VirusTotalThreatIntelProvider()


def test_whitespace_api_key_rejected():
    with pytest.raises(
        ValueError,
    ):
        VirusTotalThreatIntelProvider(
            api_key="   "
        )


def test_invalid_timeout_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "timeout_seconds must be "
            "greater than zero"
        ),
    ):
        VirusTotalThreatIntelProvider(
            api_key="test-key",
            timeout_seconds=0,
        )


def test_domain_lookup_uses_expected_endpoint(
    monkeypatch,
):
    captured = {}

    def fake_get(
        url,
        *,
        headers,
        timeout,
    ):
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout

        return FakeResponse(
            payload=build_payload(
                harmless=10
            )
        )

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    provider = (
        VirusTotalThreatIntelProvider(
            api_key="secret-key",
            timeout_seconds=5,
        )
    )

    provider.lookup(
        indicator="Example.COM",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert (
        captured["url"]
        == (
            f"{VIRUSTOTAL_API_BASE_URL}"
            "/domains/example.com"
        )
    )

    assert (
        captured["headers"]["x-apikey"]
        == "secret-key"
    )

    assert (
        captured["timeout"]
        == 5.0
    )


def test_url_lookup_uses_unpadded_base64_id(
    monkeypatch,
):
    captured = {}

    url = (
        "https://example.com/login"
    )

    expected_id = (
        base64
        .urlsafe_b64encode(
            url.encode()
        )
        .decode()
        .rstrip("=")
    )

    def fake_get(
        endpoint,
        *,
        headers,
        timeout,
    ):
        captured["url"] = endpoint

        return FakeResponse(
            payload=build_payload(
                harmless=10
            )
        )

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    provider.lookup(
        indicator=url,
        indicator_type=IndicatorType.URL,
    )

    assert (
        captured["url"]
        == (
            f"{VIRUSTOTAL_API_BASE_URL}"
            f"/urls/{expected_id}"
        )
    )

    assert (
        "="
        not in expected_id
    )


def test_not_found_returns_unknown(
    monkeypatch,
):
    def fake_get(
        url,
        *,
        headers,
        timeout,
    ):
        return FakeResponse(
            status_code=404
        )

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = provider.lookup(
        indicator="unknown.example",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert result.found is False

    assert (
        result.reputation
        == Reputation.UNKNOWN
    )

    assert result.confidence == 0.0


def test_multiple_malicious_votes_produce_malicious():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload(
                malicious=5,
                suspicious=1,
                harmless=10,
                undetected=20,
            )
        )
    )

    assert (
        result.reputation
        == Reputation.MALICIOUS
    )


def test_single_malicious_vote_produces_suspicious():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload(
                malicious=1,
                harmless=20,
            )
        )
    )

    assert (
        result.reputation
        == Reputation.SUSPICIOUS
    )


def test_suspicious_vote_produces_suspicious():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload(
                suspicious=2,
                harmless=20,
            )
        )
    )

    assert (
        result.reputation
        == Reputation.SUSPICIOUS
    )


def test_clean_result():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload(
                harmless=30,
                undetected=10,
            )
        )
    )

    assert (
        result.reputation
        == Reputation.CLEAN
    )


def test_no_votes_returns_unknown():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload()
        )
    )

    assert (
        result.reputation
        == Reputation.UNKNOWN
    )

    assert (
        result.confidence
        == 0.0
    )


def test_categories_are_normalized():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload(
                harmless=10,

                categories={
                    "vendor-a": "phishing",
                    "vendor-b": "malware",
                    "vendor-c": "phishing",
                },
            )
        )
    )

    assert (
        result.categories
        == [
            "malware",
            "phishing",
        ]
    )


def test_reference_contains_provider_object_id():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload(
                harmless=10,
                object_id="vt-object-123",
            )
        )
    )

    assert (
        result.references
        == [
            "virustotal:vt-object-123"
        ]
    )


def test_raw_provider_id_is_preserved():
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    result = (
        provider._parse_object_response(
            build_payload(
                harmless=10,
                object_id="vt-object-123",
            )
        )
    )

    assert (
        result.raw_provider_id
        == "vt-object-123"
    )


@pytest.mark.parametrize(
    "indicator_type",
    [
        IndicatorType.IP,
        IndicatorType.EMAIL,
        IndicatorType.HASH,
    ],
)
def test_unsupported_indicator_type_rejected(
    indicator_type,
):
    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    with pytest.raises(
        ValueError,
        match=(
            "currently supports "
            "DOMAIN and URL"
        ),
    ):
        provider.lookup(
            indicator="value",
            indicator_type=indicator_type,
        )


def test_http_error_propagates(
    monkeypatch,
):
    def fake_get(
        url,
        *,
        headers,
        timeout,
    ):
        return FakeResponse(
            status_code=500
        )

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    provider = (
        VirusTotalThreatIntelProvider(
            api_key="test-key"
        )
    )

    with pytest.raises(
        requests.HTTPError
    ):
        provider.lookup(
            indicator="example.com",
            indicator_type=IndicatorType.DOMAIN,
        )


def test_api_key_not_exposed_in_result(
    monkeypatch,
):
    def fake_get(
        url,
        *,
        headers,
        timeout,
    ):
        return FakeResponse(
            payload=build_payload(
                harmless=10
            )
        )

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    provider = (
        VirusTotalThreatIntelProvider(
            api_key="super-secret-key"
        )
    )

    result = provider.lookup(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert (
        "super-secret-key"
        not in str(result)
    )