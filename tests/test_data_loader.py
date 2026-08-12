import pandas as pd
import pytest

from threat_triage.data_loader import (
    CANONICAL_COLUMNS,
    LABEL_MAP,
    canonicalize_record,
    create_message_id,
    normalize_has_url,
    validate_canonical_schema,
)


def test_label_map():
    assert LABEL_MAP == {
        0: "BENIGN",
        1: "THREAT",
    }


def test_create_message_id_is_deterministic():
    message_id_1 = create_message_id(
        subject="Security Alert",
        body="Please verify your account.",
        source_dataset="test-dataset",
    )

    message_id_2 = create_message_id(
        subject="Security Alert",
        body="Please verify your account.",
        source_dataset="test-dataset",
    )

    assert message_id_1 == message_id_2
    assert len(message_id_1) == 64


def test_create_message_id_changes_when_content_changes():
    message_id_1 = create_message_id(
        subject="Security Alert",
        body="Message A",
        source_dataset="test-dataset",
    )

    message_id_2 = create_message_id(
        subject="Security Alert",
        body="Message B",
        source_dataset="test-dataset",
    )

    assert message_id_1 != message_id_2


@pytest.mark.parametrize(
    "source_value, expected",
    [
        (0, False),
        (0.0, False),
        (1, True),
        (1.0, True),
        (None, None),
        (float("nan"), None),
    ],
)
def test_normalize_has_url(source_value, expected):
    assert normalize_has_url(source_value) is expected


def test_normalize_has_url_rejects_invalid_value():
    with pytest.raises(ValueError):
        normalize_has_url(2)


def test_canonicalize_benign_record():
    record = {
        "text": "This is a normal business email.",
        "subject": "Project Update",
        "label": 0,
        "sender": "alice@example.com",
        "receiver": "bob@example.com",
        "date": pd.Timestamp("2026-01-01"),
        "urls": 0,
        "dataset_name": "unit-test",
    }

    result = canonicalize_record(record)

    assert result["subject"] == "Project Update"
    assert result["body"] == "This is a normal business email."
    assert result["canonical_label"] == "BENIGN"
    assert result["label_id"] == 0
    assert result["original_label"] == 0
    assert result["has_url"] is False
    assert result["source_dataset"] == "unit-test"

    assert result["combined_text"] == (
        "Project Update\n\n"
        "This is a normal business email."
    )

    assert len(result["message_id"]) == 64


def test_canonicalize_threat_record():
    record = {
        "text": "Verify your password immediately.",
        "subject": "Urgent Account Verification",
        "label": 1,
        "sender": None,
        "receiver": None,
        "date": None,
        "urls": 1,
        "dataset_name": "unit-test",
    }

    result = canonicalize_record(record)

    assert result["canonical_label"] == "THREAT"
    assert result["label_id"] == 1
    assert result["has_url"] is True
    assert result["sender"] is None
    assert result["receiver"] is None


def test_canonicalize_record_rejects_unknown_label():
    record = {
        "text": "Unknown message",
        "subject": "Unknown",
        "label": 99,
        "sender": None,
        "receiver": None,
        "date": None,
        "urls": 0,
        "dataset_name": "unit-test",
    }

    with pytest.raises(ValueError):
        canonicalize_record(record)


def test_validate_canonical_schema():
    dataframe = pd.DataFrame(
        [
            {
                "message_id": "a" * 64,
                "subject": "Subject",
                "body": "Body",
                "sender": None,
                "receiver": None,
                "timestamp": None,
                "has_url": False,
                "source_dataset": "unit-test",
                "original_label": 0,
                "canonical_label": "BENIGN",
                "label_id": 0,
                "combined_text": "Subject\n\nBody",
            }
        ],
        columns=CANONICAL_COLUMNS,
    )

    validate_canonical_schema(dataframe)


def test_validate_canonical_schema_rejects_invalid_columns():
    dataframe = pd.DataFrame(
        {
            "message_id": ["abc"],
            "subject": ["test"],
        }
    )

    with pytest.raises(ValueError):
        validate_canonical_schema(dataframe)