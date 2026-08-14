from __future__ import annotations

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

    Provider implementations should map their native response
    into this contract before returning it to the tool layer.
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

    Future implementations may include:
        - VirusTotal
        - enterprise threat-intelligence platforms
        - internal reputation services
        - offline/local intelligence stores
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
    Agent-facing normalized threat-intelligence result.

    The tool returns provider evidence only.

    It does not:
        - make the final triage decision,
        - modify the ML prediction,
        - modify the deterministic security evidence,
        - assign the platform risk score.
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
    Offline-safe default provider.

    This implementation performs no network calls.

    It is useful for:
        - local development,
        - unit tests,
        - CI,
        - environments without credentials,
        - validating Agentic AI orchestration before integrating
          an external provider such as VirusTotal.
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


def lookup_threat_intelligence(
    *,
    indicator: str,
    indicator_type: IndicatorType | str,
    provider: ThreatIntelProvider = DEFAULT_PROVIDER,
) -> ThreatIntelToolResult:
    """
    Look up one threat indicator through a provider abstraction.

    Parameters
    ----------
    indicator:
        Domain, URL, IP, email address, or hash to inspect.

    indicator_type:
        Type of indicator being supplied.

    provider:
        Threat-intelligence provider implementation.

        The default provider is offline and performs no network call.

    Returns
    -------
    ThreatIntelToolResult
        Structured normalized threat-intelligence evidence.

    Failure Behavior
    ----------------
    Provider failures are converted into structured tool results
    rather than being allowed to crash the future agent workflow.
    """

    normalized_indicator = _normalize_indicator(
        indicator
    )

    normalized_type = _normalize_indicator_type(
        indicator_type
    )

    provider_name = _provider_name(
        provider
    )

    try:
        provider_result = provider.lookup(
            indicator=normalized_indicator,
            indicator_type=normalized_type,
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
                "Threat intelligence provider lookup failed: "
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
    JSON-friendly wrapper for future ADK/Gemini function calling.
    """

    result = lookup_threat_intelligence(
        indicator=indicator,
        indicator_type=indicator_type,
        provider=provider,
    )

    data = asdict(
        result
    )

    # Convert enum / datetime values into JSON-friendly primitives.
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
    Normalize indicator-type input into the enum contract.
    """

    if isinstance(
        indicator_type,
        IndicatorType,
    ):
        return indicator_type

    try:
        return IndicatorType(
            str(indicator_type)
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