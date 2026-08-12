from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Optional

import pandas as pd
from datasets import Dataset, DatasetDict, load_dataset
from sklearn.model_selection import train_test_split


DEFAULT_DATASET_NAME = "puyang2025/seven-phishing-email-datasets"

LABEL_MAP: Dict[int, str] = {
    0: "BENIGN",
    1: "THREAT",
}

REQUIRED_SOURCE_COLUMNS = {
    "text",
    "subject",
    "label",
    "sender",
    "receiver",
    "date",
    "urls",
    "dataset_name",
}

CANONICAL_COLUMNS = [
    "message_id",
    "subject",
    "body",
    "sender",
    "receiver",
    "timestamp",
    "has_url",
    "source_dataset",
    "original_label",
    "canonical_label",
    "label_id",
    "combined_text",
]


@dataclass(frozen=True)
class DatasetSplits:
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame


def load_raw_dataset(
    dataset_name: str = DEFAULT_DATASET_NAME,
) -> DatasetDict:
    """Load the source dataset from Hugging Face and preserve train/test splits."""

    dataset = load_dataset(dataset_name)

    if not isinstance(dataset, DatasetDict):
        raise TypeError(
            f"Expected DatasetDict, received {type(dataset).__name__}"
        )

    required_splits = {"train", "test"}
    missing_splits = required_splits - set(dataset.keys())

    if missing_splits:
        raise ValueError(
            f"Dataset is missing required splits: {sorted(missing_splits)}"
        )

    return dataset


def validate_source_schema(dataset: Dataset) -> None:
    """Validate the source dataset schema."""

    available_columns = set(dataset.column_names)
    required_columns = set(REQUIRED_SOURCE_COLUMNS)

    missing_columns = required_columns - available_columns

    if missing_columns:
        raise ValueError(
            "Source dataset is missing required columns: "
            f"{sorted(missing_columns)}"
        )


def create_message_id(
    subject: Optional[str],
    body: Optional[str],
    source_dataset: Optional[str],
) -> str:
    """Create a deterministic SHA-256 identifier for a message."""

    payload = "||".join(
        [
            _safe_string(subject),
            _safe_string(body),
            _safe_string(source_dataset),
        ]
    )

    return hashlib.sha256(
        payload.encode("utf-8", errors="ignore")
    ).hexdigest()


def normalize_has_url(value) -> Optional[bool]:
    """
    Normalize source 'urls' into Optional[bool].

    0 -> False
    1 -> True
    missing -> None
    """

    if pd.isna(value):
        return None

    numeric_value = int(value)

    if numeric_value == 0:
        return False

    if numeric_value == 1:
        return True

    raise ValueError(
        f"Unexpected value for source 'urls' field: {value}"
    )


def canonicalize_record(record: dict) -> dict:
    """Convert one source record into the project's canonical schema."""

    original_label = int(record["label"])

    if original_label not in LABEL_MAP:
        raise ValueError(
            f"Unsupported label value: {original_label}"
        )

    subject = _safe_string(record.get("subject"))
    body = _safe_string(record.get("text"))
    source_dataset = _safe_string(record.get("dataset_name"))

    return {
        "message_id": create_message_id(
            subject=subject,
            body=body,
            source_dataset=source_dataset,
        ),
        "subject": subject,
        "body": body,
        "sender": _nullable_string(record.get("sender")),
        "receiver": _nullable_string(record.get("receiver")),
        "timestamp": record.get("date"),
        "has_url": normalize_has_url(record.get("urls")),
        "source_dataset": source_dataset,
        "original_label": original_label,
        "canonical_label": LABEL_MAP[original_label],
        "label_id": original_label,
        "combined_text": _combine_subject_and_body(
            subject=subject,
            body=body,
        ),
    }


def canonicalize_dataset(dataset: Dataset) -> pd.DataFrame:
    """Convert a Hugging Face split into a canonical Pandas DataFrame."""

    validate_source_schema(dataset)

    dataframe = pd.DataFrame(
        (canonicalize_record(record) for record in dataset),
        columns=CANONICAL_COLUMNS,
    )

    validate_canonical_schema(dataframe)

    return dataframe


def validate_canonical_schema(dataframe: pd.DataFrame) -> None:
    """Validate the canonical DataFrame structure and labels."""

    actual_columns = list(dataframe.columns)

    if actual_columns != CANONICAL_COLUMNS:
        raise ValueError(
            "Canonical schema mismatch.\n"
            f"Expected: {CANONICAL_COLUMNS}\n"
            f"Actual:   {actual_columns}"
        )

    if dataframe["message_id"].isna().any():
        raise ValueError(
            "Canonical dataset contains missing message IDs."
        )

    invalid_labels = (
        set(dataframe["canonical_label"].dropna().unique())
        - set(LABEL_MAP.values())
    )

    if invalid_labels:
        raise ValueError(
            f"Unexpected canonical labels: {sorted(invalid_labels)}"
        )


def get_train_validation_test(
    dataset_name: str = DEFAULT_DATASET_NAME,
    validation_size: float = 0.20,
    random_state: int = 42,
) -> DatasetSplits:
    """
    Load, canonicalize, and return train/validation/test splits.

    The supplied Hugging Face test split remains untouched.
    Only the supplied training split is divided into train and validation.
    """

    if not 0.0 < validation_size < 1.0:
        raise ValueError(
            "validation_size must be between 0 and 1."
        )

    dataset = load_raw_dataset(dataset_name)

    canonical_train = canonicalize_dataset(dataset["train"])
    canonical_test = canonicalize_dataset(dataset["test"])

    train_df, validation_df = train_test_split(
        canonical_train,
        test_size=validation_size,
        random_state=random_state,
        stratify=canonical_train["label_id"],
    )

    return DatasetSplits(
        train=train_df.reset_index(drop=True),
        validation=validation_df.reset_index(drop=True),
        test=canonical_test.reset_index(drop=True),
    )


def _safe_string(value) -> str:
    """Convert nullable input into a trimmed string."""

    if value is None or pd.isna(value):
        return ""

    return str(value).strip()


def _nullable_string(value) -> Optional[str]:
    """Convert nullable metadata into Optional[str]."""

    if value is None or pd.isna(value):
        return None

    text = str(value).strip()

    return text if text else None


def _combine_subject_and_body(
    subject: str,
    body: str,
) -> str:
    """Combine subject and body for baseline text classification."""

    if subject and body:
        return f"{subject}\n\n{body}"

    if subject:
        return subject

    return body
