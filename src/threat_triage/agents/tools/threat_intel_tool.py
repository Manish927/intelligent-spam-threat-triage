from __future__ import annotations

import os

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Protocol


class IndicatorType(str, Enum):
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    EMAIL = "EMAIL"
    HASH = "HASH"


class Reputation(str, Enum):
    UNKNOWN = "UNKNOWN"
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass(frozen=True)
class ProviderThreatIntelResult:
    """
    Normalized response returned by a threat-intelligence provider.

    Provider implementations map their native provider response into
    this contract before returning evidence to the agent tool layer.
    """

    found: bool

    reputation: Reputation = Reputation.UNKNOWN

    confidence: float = 0.0

    categories: List[str] = field(
        default_factory=list
    )

    references: List[str] = field(
        default_factory=list
    )

    raw_provider_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


class ThreatIntelProvider(Protocol):
    """
    Provider abstraction for external threat-intelligence services.

    Implementations may include:

        - OfflineThreatIntelProvider
        - VirusTotalThreatIntelProvider
        - enterprise reputation systems
        - internal threat-intelligence services
    """

    @property
    def name(self) -> str:
        ...

    def lookup(
        self,
        *,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ProviderThreatIntelResult:
        ...


@dataclass(frozen=True)
class ThreatIntelToolResult:
    """
    Agent-facing normalized threat-intelligence evidence.

    The result is evidence only.

    It does not:
        - modify ML predictions,
        - modify deterministic evidence,
        - modify risk scores,
        - modify routing,
        - make the platform enforcement decision.
    """

    indicator: str

    indicator_type: IndicatorType

    provider: str

    lookup_performed: bool

    found: bool

    reputation: Reputation

    confidence: float

    categories: List[str] = field(
        default_factory=list
    )

    references: List[str] = field(
        default_factory=list
    )

    checked_at: datetime = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    stale: bool = False

    error: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.indicator:
            raise ValueError(
                "indicator must not be empty"
            )

        if not self.provider:
            raise ValueError(
                "provider must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if self.checked_at.tzinfo is None:
            raise ValueError(
                "checked_at must be timezone-aware"
            )


class OfflineThreatIntelProvider:
    """
    Offline-safe threat-intelligence provider.

    This provider performs no network requests.

    It is used when a real provider has not been configured and is
    appropriate for:

        - unit tests,
        - CI,
        - offline development,
        - environments without threat-intelligence credentials.
    """

    @property
    def name(self) -> str:
        return "offline"

    def lookup(
        self,
        *,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ProviderThreatIntelResult:
        return ProviderThreatIntelResult(
            found=False,
            reputation=Reputation.UNKNOWN,
            confidence=0.0,
            categories=[],
            references=[],
        )


DEFAULT_PROVIDER = OfflineThreatIntelProvider()


def resolve_threat_intel_provider() -> ThreatIntelProvider:
    """
    Resolve the threat-intelligence provider from application
    configuration.

    Current policy:

        VIRUSTOTAL_API_KEY configured
                ↓
        VirusTotalThreatIntelProvider

        VIRUSTOTAL_API_KEY missing
                ↓
        OfflineThreatIntelProvider

    The VirusTotal import is intentionally lazy.

    This avoids a circular import because virustotal_provider.py uses
    the common threat-intelligence contracts defined in this module.

    The provider is resolved at execution time rather than import time,
    which also allows .env configuration to be loaded before the agent
    performs a lookup.
    """

    api_key = os.getenv(
        "VIRUSTOTAL_API_KEY"
    )

    if (
        api_key
        and api_key.strip()
    ):
        from threat_triage.agents.tools.virustotal_provider import (
            VirusTotalThreatIntelProvider,
        )

        return VirusTotalThreatIntelProvider(
            api_key=api_key.strip()
        )

    return DEFAULT_PROVIDER


def lookup_threat_intelligence(
    *,
    indicator: str,
    indicator_type: IndicatorType | str,
    provider: ThreatIntelProvider = DEFAULT_PROVIDER,
) -> ThreatIntelToolResult:
    """
    Look up one threat indicator through an explicitly supplied provider.

    This function remains provider-aware because it is useful for:

        - unit tests,
        - provider-specific integrations,
        - deterministic application orchestration.

    It should NOT be exposed directly to Gemini because the provider
    argument is application-controlled.
    """

    normalized_indicator = (
        _normalize_indicator(
            indicator
        )
    )

    normalized_type = (
        _normalize_indicator_type(
            indicator_type
        )
    )

    provider_name = (
        _provider_name(
            provider
        )
    )

    try:
        provider_result = (
            provider.lookup(
                indicator=normalized_indicator,
                indicator_type=normalized_type,
            )
        )

    except Exception as exc:
        return ThreatIntelToolResult(
            indicator=normalized_indicator,
            indicator_type=normalized_type,
            provider=provider_name,
            lookup_performed=True,
            found=False,
            reputation=Reputation.UNKNOWN,
            confidence=0.0,
            categories=[],
            references=[],
            stale=False,
            error=(
                "Threat intelligence provider "
                "lookup failed: "
                f"{type(exc).__name__}"
            ),
        )

    return ThreatIntelToolResult(
        indicator=normalized_indicator,
        indicator_type=normalized_type,
        provider=provider_name,
        lookup_performed=True,
        found=provider_result.found,
        reputation=provider_result.reputation,
        confidence=provider_result.confidence,
        categories=list(
            provider_result.categories
        ),
        references=list(
            provider_result.references
        ),
        stale=False,
        error=None,
    )


def lookup_threat_intelligence_dict(
    *,
    indicator: str,
    indicator_type: IndicatorType | str,
    provider: ThreatIntelProvider = DEFAULT_PROVIDER,
) -> dict:
    """
    JSON-friendly wrapper around lookup_threat_intelligence().

    This provider-aware function is primarily intended for deterministic
    application code and tests.
    """

    result = lookup_threat_intelligence(
        indicator=indicator,
        indicator_type=indicator_type,
        provider=provider,
    )

    return _tool_result_to_dict(
        result
    )


def lookup_configured_threat_intelligence(
    *,
    indicator: str,
    indicator_type: IndicatorType | str,
) -> ThreatIntelToolResult:
    """
    Perform a threat-intelligence lookup using the provider selected
    from application configuration.

    The provider itself is never exposed to the LLM.
    """

    provider = (
        resolve_threat_intel_provider()
    )

    return lookup_threat_intelligence(
        indicator=indicator,
        indicator_type=indicator_type,
        provider=provider,
    )


def lookup_configured_threat_intelligence_dict(
    *,
    indicator: str,
    indicator_type: IndicatorType | str,
) -> dict:
    """
    JSON-friendly configured-provider wrapper.

    This is the preferred function for the ADK-facing adapter because
    its public arguments contain only JSON-schema-friendly values:

        indicator
        indicator_type

    Provider selection remains application-controlled.
    """

    result = (
        lookup_configured_threat_intelligence(
            indicator=indicator,
            indicator_type=indicator_type,
        )
    )

    return _tool_result_to_dict(
        result
    )


def _tool_result_to_dict(
    result: ThreatIntelToolResult,
) -> dict:
    """
    Convert ThreatIntelToolResult into JSON-compatible primitives.
    """

    data = asdict(
        result
    )

    data["indicator_type"] = (
        result.indicator_type.value
    )

    data["reputation"] = (
        result.reputation.value
    )

    data["checked_at"] = (
        result.checked_at.isoformat()
    )

    return data


def _normalize_indicator(
    indicator: str,
) -> str:
    """
    Normalize and bound an indicator before provider lookup.
    """

    if indicator is None:
        raise ValueError(
            "indicator must not be None"
        )

    normalized = str(
        indicator
    ).strip()

    if not normalized:
        raise ValueError(
            "indicator must not be empty"
        )

    if len(normalized) > 4096:
        raise ValueError(
            "indicator exceeds maximum supported length"
        )

    return normalized


def _normalize_indicator_type(
    indicator_type: IndicatorType | str,
) -> IndicatorType:
    """
    Normalize indicator type into the platform enum.
    """

    if isinstance(
        indicator_type,
        IndicatorType,
    ):
        return indicator_type

    try:
        return IndicatorType(
            str(
                indicator_type
            )
            .strip()
            .upper()
        )

    except ValueError as exc:
        raise ValueError(
            "Unsupported indicator_type"
        ) from exc


def _provider_name(
    provider: ThreatIntelProvider,
) -> str:
    """
    Resolve and validate provider name.
    """

    name = str(
        provider.name
    ).strip()

    if not name:
        raise ValueError(
            "Threat-intelligence provider name "
            "must not be empty"
        )

    return name