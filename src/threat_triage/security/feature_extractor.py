from __future__ import annotations

from typing import Mapping, Any

from .language_analyzer import analyze_language
from .models import SecurityFeatures
from .sender_analyzer import analyze_sender
from .url_analyzer import analyze_urls


def extract_security_features(
    message_id: str,
    subject: str | None,
    body: str | None,
    sender: str | None,
) -> SecurityFeatures:
    """
    Build the complete deterministic security evidence bundle
    for a single email.

    This function orchestrates the individual security analyzers:

        - URL analysis
        - sender analysis
        - language / social-engineering analysis

    It intentionally does not:
        - calculate a risk score,
        - classify BENIGN vs THREAT,
        - perform threat-intelligence lookups,
        - invoke an LLM,
        - make a triage decision.

    Parameters
    ----------
    message_id:
        Stable identifier for the email.

    subject:
        Email subject.

    body:
        Email body.

    sender:
        Sender address or RFC-style sender string.

    Returns
    -------
    SecurityFeatures
        Typed deterministic security evidence.
    """

    _validate_message_id(message_id)

    url_features = analyze_urls(
        subject=subject,
        body=body,
    )

    sender_features = analyze_sender(
        sender=sender,
    )

    language_features = analyze_language(
        subject=subject,
        body=body,
    )

    return SecurityFeatures(
        message_id=message_id,
        url=url_features,
        sender=sender_features,
        language=language_features,
    )


def extract_security_features_from_record(
    record: Mapping[str, Any],
) -> SecurityFeatures:
    """
    Build a SecurityFeatures bundle from a canonical message record.

    Expected canonical fields:

        message_id
        subject
        body
        sender

    This helper allows the feature extractor to consume records
    produced by data_loader.py without coupling the analyzers
    directly to Pandas or Hugging Face datasets.
    """

    required_fields = {
        "message_id",
        "subject",
        "body",
        "sender",
    }

    missing_fields = (
        required_fields
        - set(record.keys())
    )

    if missing_fields:
        raise ValueError(
            "Canonical record is missing required fields: "
            f"{sorted(missing_fields)}"
        )

    return extract_security_features(
        message_id=str(record["message_id"]),
        subject=_optional_string(
            record.get("subject")
        ),
        body=_optional_string(
            record.get("body")
        ),
        sender=_optional_string(
            record.get("sender")
        ),
    )


def _validate_message_id(
    message_id: str,
) -> None:
    """
    Validate the message identifier required by the evidence bundle.
    """

    if message_id is None:
        raise ValueError(
            "message_id must not be None"
        )

    normalized = str(message_id).strip()

    if not normalized:
        raise ValueError(
            "message_id must not be empty"
        )


def _optional_string(
    value: Any,
) -> str | None:
    """
    Convert nullable record values into Optional[str].

    Empty strings are normalized to None for analyzer input.
    """

    if value is None:
        return None

    text = str(value).strip()

    return text if text else None