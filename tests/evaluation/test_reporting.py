from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from threat_triage.evaluation.reporting import (
    compute_false_negative_recovery,
    generate_evaluation_report,
)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _fixture_artifacts(tmp_path: Path) -> Path:
    artifact_dir = tmp_path / "evaluation"
    artifact_dir.mkdir()

    _write_json(
        artifact_dir / "ml_locked_test_summary.json",
        {
            "mode": "ML_ONLY",
            "selected_threshold": 0.75,
            "metrics": {
                "total_samples": 40604,
                "successful_samples": 40604,
                "failed_samples": 0,
                "true_positive": 17909,
                "true_negative": 21620,
                "false_positive": 118,
                "false_negative": 957,
                "accuracy": 0.973525,
                "precision": 0.993454,
                "recall": 0.949274,
                "f1": 0.970862,
                "false_positive_rate": 0.005428,
                "false_negative_rate": 0.050726,
                "average_latency_ms": 2.0,
            },
        },
    )

    _write_json(
        artifact_dir / "ml_vs_hybrid_challenge_summary.json",
        {
            "gemini_model": "gemini-3.5-flash-lite",
            "live_sample_count": 12,
            "ml_only": {
                "accuracy": 0.1667,
                "precision": 0.2857,
                "recall": 0.2857,
                "f1": 0.2857,
                "false_positive_rate": 1.0,
                "false_negative_rate": 0.7143,
                "average_latency_ms": 2.38,
            },
            "hybrid": {
                "accuracy": 0.5833,
                "precision": 0.625,
                "recall": 0.7143,
                "f1": 0.6667,
                "false_positive_rate": 0.6,
                "false_negative_rate": 0.2857,
                "agent_invocation_rate": 1.0,
                "average_latency_ms": 5236.13,
                "failed_samples": 0,
            },
        },
    )

    sample_rows = [
        {"evaluation_id": "1", "true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "THREAT", "routing_decision": "AGENT_REVIEW"},
        {"evaluation_id": "2", "true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "THREAT", "routing_decision": "AGENT_REVIEW"},
        {"evaluation_id": "3", "true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "THREAT", "routing_decision": "AGENT_REVIEW"},
        {"evaluation_id": "4", "true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "BENIGN", "routing_decision": "AGENT_REVIEW"},
        {"evaluation_id": "5", "true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "BENIGN", "routing_decision": "AGENT_REVIEW"},
        {"evaluation_id": "6", "true_label": "BENIGN", "ml_label": "THREAT", "hybrid_label": "BENIGN", "routing_decision": "AGENT_REVIEW"},
        {"evaluation_id": "7", "true_label": "THREAT", "ml_label": "THREAT", "hybrid_label": "THREAT", "routing_decision": "AGENT_REVIEW"},
    ]
    _write_csv(artifact_dir / "ml_vs_hybrid_sample_results.csv", sample_rows)
    _write_csv(
        artifact_dir / "hybrid_challenge_set.csv",
        [
            {"evaluation_id": "1", "ml_outcome": "FALSE_NEGATIVE"},
            {"evaluation_id": "2", "ml_outcome": "FALSE_NEGATIVE"},
            {"evaluation_id": "3", "ml_outcome": "TRUE_POSITIVE"},
            {"evaluation_id": "4", "ml_outcome": "FALSE_POSITIVE"},
        ],
    )
    return artifact_dir


def test_compute_false_negative_recovery() -> None:
    rows = [
        {"true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "THREAT"},
        {"true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "THREAT"},
        {"true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "THREAT"},
        {"true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "BENIGN"},
        {"true_label": "THREAT", "ml_label": "BENIGN", "hybrid_label": "BENIGN"},
    ]
    total, recovered, rate = compute_false_negative_recovery(rows)
    assert total == 5
    assert recovered == 3
    assert rate == pytest.approx(0.6)


def test_generate_evaluation_report(tmp_path: Path) -> None:
    artifact_dir = _fixture_artifacts(tmp_path)
    result = generate_evaluation_report(artifact_dir)

    assert result.report_path.exists()
    assert result.metrics_figure_path.exists()
    assert result.recovery_figure_path.exists()
    assert result.latency_figure_path.exists()
    assert result.false_negative_count == 5
    assert result.recovered_false_negative_count == 3
    assert result.false_negative_recovery_rate == pytest.approx(0.6)

    report = result.report_path.read_text(encoding="utf-8")
    assert "97.35%" in report
    assert "71.43%" in report
    assert "3/5" in report
    assert "60.00%" in report
    assert "challenge-set metrics are not population metrics" in report


def test_missing_required_artifact_fails_cleanly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Run Notebook 04 artifact-export cells first"):
        generate_evaluation_report(tmp_path)
