from __future__ import annotations

import base64
import os
from typing import Any

import requests

from threat_triage.agents.tools.threat_intel_tool import (
    IndicatorType,
    ProviderThreatIntelResult,
    Reputation,
)


VIRUSTOTAL_API_BASE_URL = (
    "https://www.virustotal.com/api/v3"
)

DEFAULT_TIMEOUT_SECONDS = 10.0


class VirusTotalThreatIntelProvider:
    """
    VirusTotal API v3 threat-intelligence provider.

    Initial supported indicator types:

        DOMAIN
        URL

    The provider:
        - reads credentials from environment configuration,
        - uses HTTPS only,
        - does not expose the API key to Gemini,
        - converts VirusTotal responses into the platform's
          ProviderThreatIntelResult contract.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        resolved_key = (
            api_key
            or os.getenv(
                "VIRUSTOTAL_API_KEY"
            )
        )

        if (
            not resolved_key
            or not resolved_key.strip()
        ):
            raise ValueError(
                "VirusTotal API key is not configured"
            )

        if timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds must be greater than zero"
            )

        self._api_key = (
            resolved_key.strip()
        )

        self._timeout_seconds = (
            float(timeout_seconds)
        )

    @property
    def name(self) -> str:
        return "virustotal"

    def lookup(
        self,
        *,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ProviderThreatIntelResult:
        """
        Look up one indicator in VirusTotal.

        Supported:
            DOMAIN
            URL

        Unsupported indicator types are rejected explicitly.
        """

        if (
            indicator_type
            == IndicatorType.DOMAIN
        ):
            return self._lookup_domain(
                indicator
            )

        if (
            indicator_type
            == IndicatorType.URL
        ):
            return self._lookup_url(
                indicator
            )

        raise ValueError(
            "VirusTotal provider currently supports "
            "DOMAIN and URL indicators only"
        )

    def _lookup_domain(
        self,
        domain: str,
    ) -> ProviderThreatIntelResult:
        normalized = (
            domain
            .strip()
            .lower()
        )

        if not normalized:
            raise ValueError(
                "domain must not be empty"
            )

        endpoint = (
            f"{VIRUSTOTAL_API_BASE_URL}"
            f"/domains/{normalized}"
        )

        payload = self._get_json(
            endpoint
        )

        return self._parse_object_response(
            payload
        )

    def _lookup_url(
        self,
        url: str,
    ) -> ProviderThreatIntelResult:
        normalized = url.strip()

        if not normalized:
            raise ValueError(
                "url must not be empty"
            )

        url_id = (
            base64
            .urlsafe_b64encode(
                normalized.encode(
                    "utf-8"
                )
            )
            .decode(
                "ascii"
            )
            .rstrip("=")
        )

        endpoint = (
            f"{VIRUSTOTAL_API_BASE_URL}"
            f"/urls/{url_id}"
        )

        payload = self._get_json(
            endpoint
        )

        return self._parse_object_response(
            payload
        )

    def _get_json(
        self,
        endpoint: str,
    ) -> dict[str, Any]:
        response = requests.get(
            endpoint,
            headers={
                "x-apikey": self._api_key,
            },
            timeout=(
                self._timeout_seconds
            ),
        )

        if response.status_code == 404:
            return {
                "data": None
            }

        response.raise_for_status()

        return response.json()

    def _parse_object_response(
        self,
        payload: dict[str, Any],
    ) -> ProviderThreatIntelResult:
        data = payload.get(
            "data"
        )

        if not data:
            return ProviderThreatIntelResult(
                found=False,
                reputation=Reputation.UNKNOWN,
                confidence=0.0,
                categories=[],
                references=[],
            )

        attributes = (
            data.get(
                "attributes",
                {}
            )
        )

        stats = (
            attributes.get(
                "last_analysis_stats",
                {}
            )
        )

        malicious = int(
            stats.get(
                "malicious",
                0,
            )
            or 0
        )

        suspicious = int(
            stats.get(
                "suspicious",
                0,
            )
            or 0
        )

        harmless = int(
            stats.get(
                "harmless",
                0,
            )
            or 0
        )

        undetected = int(
            stats.get(
                "undetected",
                0,
            )
            or 0
        )

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
        )

        reputation = (
            self._derive_reputation(
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                total=total,
            )
        )

        confidence = (
            self._derive_confidence(
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                total=total,
            )
        )

        categories = (
            self._extract_categories(
                attributes
            )
        )

        object_id = data.get(
            "id"
        )

        references = []

        if object_id:
            references.append(
                f"virustotal:{object_id}"
            )

        return ProviderThreatIntelResult(
            found=True,
            reputation=reputation,
            confidence=confidence,
            categories=categories,
            references=references,
            raw_provider_id=object_id,
        )

    @staticmethod
    def _derive_reputation(
        *,
        malicious: int,
        suspicious: int,
        harmless: int,
        total: int,
    ) -> Reputation:
        if total <= 0:
            return Reputation.UNKNOWN

        if malicious >= 2:
            return Reputation.MALICIOUS

        if (
            malicious == 1
            or suspicious >= 1
        ):
            return Reputation.SUSPICIOUS

        if (
            harmless > 0
            and malicious == 0
            and suspicious == 0
        ):
            return Reputation.CLEAN

        return Reputation.UNKNOWN

    @staticmethod
    def _derive_confidence(
        *,
        malicious: int,
        suspicious: int,
        harmless: int,
        total: int,
    ) -> float:
        if total <= 0:
            return 0.0

        if malicious > 0:
            return min(
                1.0,
                (
                    malicious
                    + 0.5 * suspicious
                )
                / total,
            )

        if suspicious > 0:
            return min(
                1.0,
                suspicious / total,
            )

        if harmless > 0:
            return min(
                1.0,
                harmless / total,
            )

        return 0.0

    @staticmethod
    def _extract_categories(
        attributes: dict[str, Any],
    ) -> list[str]:
        categories = attributes.get(
            "categories",
            {}
        )

        if not isinstance(
            categories,
            dict,
        ):
            return []

        values = {
            str(value).strip()
            for value in categories.values()
            if value
            and str(value).strip()
        }

        return sorted(
            values
        )