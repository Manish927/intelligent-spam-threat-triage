import json
from datetime import datetime

import pytest

from threat_triage.agents.tools.threat_intel_tool import (
    IndicatorType,
    OfflineThreatIntelProvider,
    ProviderThreatIntelResult,
    Reputation,
    ThreatIntelToolResult,
    lookup_threat_intelligence,
    lookup_threat_intelligence_dict,
)


class MockThreatIntelProvider:
    def __init__(
        self,
        *,
        name: str = "mock",
        result: ProviderThreatIntelResult | None = None,
        error: Exception | None = None,
    ):
        self._name = name
        self._result = result
        self._error = error

    @property
    def name(self) -> str:
        return self._name

    def lookup(
        self,
        *,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ProviderThreatIntelResult:
        if self._error is not None:
            raise self._error

        if self._result is None:
            return ProviderThreatIntelResult(
                found=False,
                reputation=Reputation.UNKNOWN,
                confidence=0.0,
            )

        return self._result


def test_offline_provider_returns_unknown_result():
    result = lookup_threat_intelligence(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert isinstance(
        result,
        ThreatIntelToolResult,
    )

    assert result.indicator == "example.com"

    assert (
        result.indicator_type
        == IndicatorType.DOMAIN
    )

    assert result.provider == "offline"

    assert result.lookup_performed is True

    assert result.found is False

    assert (
        result.reputation
        == Reputation.UNKNOWN
    )

    assert result.confidence == 0.0

    assert result.categories == []
    assert result.references == []

    assert result.error is None


def test_offline_provider_name():
    provider = OfflineThreatIntelProvider()

    assert provider.name == "offline"


def test_mock_provider_clean_result():
    provider = MockThreatIntelProvider(
        result=ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.CLEAN,
            confidence=0.95,
            categories=[
                "known-good"
            ],
            references=[
                "mock://indicator/123"
            ],
        )
    )

    result = lookup_threat_intelligence(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
        provider=provider,
    )

    assert result.found is True

    assert (
        result.reputation
        == Reputation.CLEAN
    )

    assert result.confidence == 0.95

    assert result.categories == [
        "known-good"
    ]

    assert result.references == [
        "mock://indicator/123"
    ]


def test_mock_provider_suspicious_result():
    provider = MockThreatIntelProvider(
        result=ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.SUSPICIOUS,
            confidence=0.80,
            categories=[
                "phishing"
            ],
        )
    )

    result = lookup_threat_intelligence(
        indicator="suspicious.example",
        indicator_type="DOMAIN",
        provider=provider,
    )

    assert (
        result.reputation
        == Reputation.SUSPICIOUS
    )

    assert result.confidence == 0.80

    assert (
        "phishing"
        in result.categories
    )


def test_mock_provider_malicious_result():
    provider = MockThreatIntelProvider(
        result=ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.MALICIOUS,
            confidence=0.99,
            categories=[
                "phishing",
                "credential-theft",
            ],
            references=[
                "mock://malicious/indicator"
            ],
        )
    )

    result = lookup_threat_intelligence(
        indicator="evil.example",
        indicator_type=IndicatorType.DOMAIN,
        provider=provider,
    )

    assert result.found is True

    assert (
        result.reputation
        == Reputation.MALICIOUS
    )

    assert result.confidence == 0.99

    assert set(
        result.categories
    ) == {
        "phishing",
        "credential-theft",
    }


@pytest.mark.parametrize(
    "indicator_type",
    [
        IndicatorType.DOMAIN,
        IndicatorType.URL,
        IndicatorType.IP,
        IndicatorType.EMAIL,
        IndicatorType.HASH,
    ],
)
def test_all_indicator_types_supported(
    indicator_type,
):
    result = lookup_threat_intelligence(
        indicator="example-indicator",
        indicator_type=indicator_type,
    )

    assert (
        result.indicator_type
        == indicator_type
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        (
            "domain",
            IndicatorType.DOMAIN,
        ),
        (
            "DOMAIN",
            IndicatorType.DOMAIN,
        ),
        (
            "url",
            IndicatorType.URL,
        ),
        (
            "ip",
            IndicatorType.IP,
        ),
        (
            "email",
            IndicatorType.EMAIL,
        ),
        (
            "hash",
            IndicatorType.HASH,
        ),
    ],
)
def test_string_indicator_types_are_normalized(
    value,
    expected,
):
    result = lookup_threat_intelligence(
        indicator="example",
        indicator_type=value,
    )

    assert (
        result.indicator_type
        == expected
    )


def test_invalid_indicator_type_rejected():
    with pytest.raises(
        ValueError,
        match="Unsupported indicator_type",
    ):
        lookup_threat_intelligence(
            indicator="example.com",
            indicator_type="UNKNOWN",
        )


def test_none_indicator_rejected():
    with pytest.raises(
        ValueError,
        match="indicator must not be None",
    ):
        lookup_threat_intelligence(
            indicator=None,  # type: ignore[arg-type]
            indicator_type=IndicatorType.DOMAIN,
        )


def test_empty_indicator_rejected():
    with pytest.raises(
        ValueError,
        match="indicator must not be empty",
    ):
        lookup_threat_intelligence(
            indicator="",
            indicator_type=IndicatorType.DOMAIN,
        )


def test_whitespace_indicator_rejected():
    with pytest.raises(
        ValueError,
        match="indicator must not be empty",
    ):
        lookup_threat_intelligence(
            indicator="   ",
            indicator_type=IndicatorType.DOMAIN,
        )


def test_indicator_is_trimmed():
    result = lookup_threat_intelligence(
        indicator="   example.com   ",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert result.indicator == "example.com"


def test_oversized_indicator_rejected():
    oversized = "A" * 5000

    with pytest.raises(
        ValueError,
        match=(
            "indicator exceeds maximum supported length"
        ),
    ):
        lookup_threat_intelligence(
            indicator=oversized,
            indicator_type=IndicatorType.HASH,
        )


def test_provider_exception_returns_structured_error():
    provider = MockThreatIntelProvider(
        error=TimeoutError(
            "provider timeout"
        )
    )

    result = lookup_threat_intelligence(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
        provider=provider,
    )

    assert result.lookup_performed is True

    assert result.found is False

    assert (
        result.reputation
        == Reputation.UNKNOWN
    )

    assert result.confidence == 0.0

    assert result.error is not None

    assert (
        "TimeoutError"
        in result.error
    )


def test_provider_runtime_error_returns_structured_error():
    provider = MockThreatIntelProvider(
        error=RuntimeError(
            "service unavailable"
        )
    )

    result = lookup_threat_intelligence(
        indicator="example.com",
        indicator_type="DOMAIN",
        provider=provider,
    )

    assert result.error is not None

    assert (
        "RuntimeError"
        in result.error
    )


def test_provider_name_is_preserved():
    provider = MockThreatIntelProvider(
        name="test-provider",
    )

    result = lookup_threat_intelligence(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
        provider=provider,
    )

    assert (
        result.provider
        == "test-provider"
    )


def test_empty_provider_name_rejected():
    provider = MockThreatIntelProvider(
        name="   "
    )

    with pytest.raises(
        ValueError,
        match=(
            "Threat-intelligence provider name "
            "must not be empty"
        ),
    ):
        lookup_threat_intelligence(
            indicator="example.com",
            indicator_type=IndicatorType.DOMAIN,
            provider=provider,
        )


def test_provider_result_confidence_validation():
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.MALICIOUS,
            confidence=1.1,
        )


def test_provider_result_negative_confidence_rejected():
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.SUSPICIOUS,
            confidence=-0.1,
        )


def test_tool_result_confidence_validation():
    with pytest.raises(
        ValueError,
        match="confidence must be between 0 and 1",
    ):
        ThreatIntelToolResult(
            indicator="example.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="mock",
            lookup_performed=True,
            found=True,
            reputation=Reputation.CLEAN,
            confidence=2.0,
        )


def test_tool_result_requires_indicator():
    with pytest.raises(
        ValueError,
        match="indicator must not be empty",
    ):
        ThreatIntelToolResult(
            indicator="",
            indicator_type=IndicatorType.DOMAIN,
            provider="mock",
            lookup_performed=True,
            found=False,
            reputation=Reputation.UNKNOWN,
            confidence=0.0,
        )


def test_tool_result_requires_provider():
    with pytest.raises(
        ValueError,
        match="provider must not be empty",
    ):
        ThreatIntelToolResult(
            indicator="example.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="",
            lookup_performed=True,
            found=False,
            reputation=Reputation.UNKNOWN,
            confidence=0.0,
        )


def test_checked_at_is_timezone_aware():
    result = lookup_threat_intelligence(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert (
        result.checked_at.tzinfo
        is not None
    )


def test_naive_checked_at_rejected():
    with pytest.raises(
        ValueError,
        match=(
            "checked_at must be timezone-aware"
        ),
    ):
        ThreatIntelToolResult(
            indicator="example.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="mock",
            lookup_performed=True,
            found=False,
            reputation=Reputation.UNKNOWN,
            confidence=0.0,
            checked_at=datetime.now(),
        )


def test_dictionary_wrapper_returns_plain_dict():
    result = lookup_threat_intelligence_dict(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert isinstance(
        result,
        dict,
    )

    assert (
        result["indicator"]
        == "example.com"
    )

    assert (
        result["indicator_type"]
        == "DOMAIN"
    )

    assert (
        result["reputation"]
        == "UNKNOWN"
    )

    assert (
        result["provider"]
        == "offline"
    )

    assert isinstance(
        result["checked_at"],
        str,
    )


def test_dictionary_wrapper_is_json_serializable():
    result = lookup_threat_intelligence_dict(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    serialized = json.dumps(
        result
    )

    assert isinstance(
        serialized,
        str,
    )


def test_categories_are_copied_from_provider_result():
    provider_categories = [
        "phishing",
        "credential-theft",
    ]

    provider = MockThreatIntelProvider(
        result=ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.MALICIOUS,
            confidence=0.95,
            categories=provider_categories,
        )
    )

    result = lookup_threat_intelligence(
        indicator="evil.example",
        indicator_type="DOMAIN",
        provider=provider,
    )

    assert (
        result.categories
        == provider_categories
    )

    assert (
        result.categories
        is not provider_categories
    )


def test_references_are_copied_from_provider_result():
    references = [
        "mock://one",
        "mock://two",
    ]

    provider = MockThreatIntelProvider(
        result=ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.SUSPICIOUS,
            confidence=0.80,
            references=references,
        )
    )

    result = lookup_threat_intelligence(
        indicator="example.com",
        indicator_type="DOMAIN",
        provider=provider,
    )

    assert result.references == references

    assert (
        result.references
        is not references
    )


def test_tool_returns_intelligence_not_routing_decision():
    result = lookup_threat_intelligence_dict(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert "decision" not in result
    assert "disposition" not in result
    assert "routing" not in result
    assert "risk_score" not in result


def test_tool_does_not_modify_platform_classification():
    result = lookup_threat_intelligence_dict(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    assert "classification" not in result
    assert "predicted_label" not in result


def test_malicious_reputation_is_provider_evidence_only():
    provider = MockThreatIntelProvider(
        result=ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.MALICIOUS,
            confidence=0.99,
            categories=[
                "phishing"
            ],
        )
    )

    result = lookup_threat_intelligence(
        indicator="evil.example",
        indicator_type=IndicatorType.DOMAIN,
        provider=provider,
    )

    assert (
        result.reputation
        == Reputation.MALICIOUS
    )

    assert not hasattr(
        result,
        "decision",
    )

    assert not hasattr(
        result,
        "risk_score",
    )


def test_provider_receives_normalized_indicator_and_type():
    class RecordingProvider:
        def __init__(self):
            self.received_indicator = None
            self.received_type = None

        @property
        def name(self):
            return "recording"

        def lookup(
            self,
            *,
            indicator,
            indicator_type,
        ):
            self.received_indicator = indicator
            self.received_type = indicator_type

            return ProviderThreatIntelResult(
                found=False
            )

    provider = RecordingProvider()

    lookup_threat_intelligence(
        indicator="  example.com  ",
        indicator_type="domain",
        provider=provider,
    )

    assert (
        provider.received_indicator
        == "example.com"
    )

    assert (
        provider.received_type
        == IndicatorType.DOMAIN
    )


def test_provider_raw_id_does_not_leak_into_agent_contract():
    """
    Provider-specific IDs stay inside the provider-normalized object
    unless we deliberately add them to the public tool contract later.
    """

    provider = MockThreatIntelProvider(
        result=ProviderThreatIntelResult(
            found=True,
            reputation=Reputation.SUSPICIOUS,
            confidence=0.70,
            raw_provider_id="provider-object-123",
        )
    )

    result = lookup_threat_intelligence_dict(
        indicator="example.com",
        indicator_type="DOMAIN",
        provider=provider,
    )

    assert (
        "raw_provider_id"
        not in result
    )