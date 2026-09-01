"""Portfolio-ready reporting for Notebook 04 hybrid evaluation artifacts.

This module intentionally consumes the persisted B6 artifacts instead of notebook
state. That keeps the published report reproducible and prevents manual metric
copy/paste drift.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import matplotlib.pyplot as plt


REQUIRED_ARTIFACTS = (
    "ml_locked_test_summary.json",
    "ml_vs_hybrid_challenge_summary.json",
    "ml_vs_hybrid_sample_results.csv",
)
OPTIONAL_ARTIFACTS = (
    "hybrid_challenge_set.csv",
    "hybrid_route_preview.csv",
)


@dataclass(frozen=True)
class ReportResult:
    report_path: Path
    metrics_figure_path: Path
    recovery_figure_path: Path
    latency_figure_path: Path
    false_negative_count: int
    recovered_false_negative_count: int
    false_negative_recovery_rate: float | None


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _fmt_pct(value: float | int | None, digits: int = 2) -> str:
    if value is None:
        return "N/A"
    return f"{float(value) * 100:.{digits}f}%"


def _fmt_float(value: float | int | None, digits: int = 4) -> str:
    if value is None:
        return "N/A"
    return f"{float(value):.{digits}f}"


def _fmt_ms(value: float | int | None) -> str:
    if value is None:
        return "N/A"
    value = float(value)
    if value >= 1000:
        return f"{value / 1000:.2f} s"
    return f"{value:.2f} ms"


def _require_files(artifact_dir: Path) -> None:
    missing = [name for name in REQUIRED_ARTIFACTS if not (artifact_dir / name).exists()]
    if missing:
        joined = ", ".join(missing)
        raise FileNotFoundError(
            f"Missing B6 evaluation artifact(s) in {artifact_dir}: {joined}. "
            "Run Notebook 04 artifact-export cells first."
        )


def compute_false_negative_recovery(
    sample_rows: Iterable[dict[str, str]],
) -> tuple[int, int, float | None]:
    """Return ML false negatives, recovered count, and recovery rate."""
    false_negatives = [
        row
        for row in sample_rows
        if row.get("true_label") == "THREAT" and row.get("ml_label") == "BENIGN"
    ]
    recovered = sum(1 for row in false_negatives if row.get("hybrid_label") == "THREAT")
    rate = recovered / len(false_negatives) if false_negatives else None
    return len(false_negatives), recovered, rate


def _challenge_composition(challenge_rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in challenge_rows:
        key = row.get("ml_outcome") or "UNKNOWN"
        counts[key] = counts.get(key, 0) + 1
    return counts


def _route_distribution(sample_rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in sample_rows:
        key = row.get("routing_decision") or "UNKNOWN"
        counts[key] = counts.get(key, 0) + 1
    return counts


def _save_metrics_figure(summary: dict[str, Any], destination: Path) -> None:
    labels = ["Accuracy", "Precision", "Recall", "F1"]
    ml = summary["ml_only"]
    hybrid = summary["hybrid"]
    ml_values = [ml["accuracy"], ml["precision"], ml["recall"], ml["f1"]]
    hybrid_values = [
        hybrid["accuracy"],
        hybrid["precision"],
        hybrid["recall"],
        hybrid["f1"],
    ]

    x = list(range(len(labels)))
    width = 0.36
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([i - width / 2 for i in x], ml_values, width=width, label="ML_ONLY")
    ax.bar([i + width / 2 for i in x], hybrid_values, width=width, label="HYBRID")
    ax.set_title("Challenge-set ML_ONLY vs HYBRID")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1)
    ax.set_xticks(x, labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.2)
    fig.tight_layout()
    fig.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(fig)


def _save_recovery_figure(total: int, recovered: int, destination: Path) -> None:
    remaining = max(total - recovered, 0)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.bar(["Recovered by Hybrid", "Still missed"], [recovered, remaining])
    ax.set_title("ML False-Negative Recovery")
    ax.set_ylabel("Threat messages")
    ax.set_ylim(0, max(total, 1))
    for index, value in enumerate([recovered, remaining]):
        ax.text(index, value + 0.05, str(value), ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(fig)


def _save_latency_figure(summary: dict[str, Any], destination: Path) -> None:
    ml_ms = float(summary["ml_only"]["average_latency_ms"])
    hybrid_ms = float(summary["hybrid"]["average_latency_ms"])
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.bar(["ML_ONLY", "HYBRID"], [ml_ms, hybrid_ms])
    ax.set_title("Average Evaluation Latency")
    ax.set_ylabel("Milliseconds (log scale)")
    ax.set_yscale("log")
    for index, value in enumerate([ml_ms, hybrid_ms]):
        ax.text(index, value * 1.12, f"{value:.2f} ms", ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(fig)


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def generate_evaluation_report(
    artifact_dir: str | Path,
    output_dir: str | Path | None = None,
) -> ReportResult:
    """Generate a Markdown evaluation report and portfolio figures.

    Parameters
    ----------
    artifact_dir:
        Directory containing Notebook 04 persisted evaluation artifacts.
    output_dir:
        Destination directory. Defaults to ``artifact_dir``.
    """
    artifact_dir = Path(artifact_dir).resolve()
    output_dir = Path(output_dir).resolve() if output_dir else artifact_dir
    _require_files(artifact_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    locked = _load_json(artifact_dir / "ml_locked_test_summary.json")
    challenge = _load_json(artifact_dir / "ml_vs_hybrid_challenge_summary.json")
    samples = _load_csv(artifact_dir / "ml_vs_hybrid_sample_results.csv")

    challenge_rows: list[dict[str, str]] = []
    challenge_path = artifact_dir / "hybrid_challenge_set.csv"
    if challenge_path.exists():
        challenge_rows = _load_csv(challenge_path)

    fn_total, fn_recovered, fn_rate = compute_false_negative_recovery(samples)
    route_counts = _route_distribution(samples)
    composition = _challenge_composition(challenge_rows)

    metrics_figure = figures_dir / "ml_vs_hybrid_metrics.png"
    recovery_figure = figures_dir / "false_negative_recovery.png"
    latency_figure = figures_dir / "latency_comparison.png"

    _save_metrics_figure(challenge, metrics_figure)
    _save_recovery_figure(fn_total, fn_recovered, recovery_figure)
    _save_latency_figure(challenge, latency_figure)

    locked_metrics = locked["metrics"]
    ml = challenge["ml_only"]
    hybrid = challenge["hybrid"]

    challenge_metrics_table = _markdown_table(
        ["Metric", "ML_ONLY", "HYBRID", "Direction"],
        [
            ["Accuracy", _fmt_pct(ml["accuracy"]), _fmt_pct(hybrid["accuracy"]), "Higher is better"],
            ["Precision", _fmt_pct(ml["precision"]), _fmt_pct(hybrid["precision"]), "Higher is better"],
            ["Recall", _fmt_pct(ml["recall"]), _fmt_pct(hybrid["recall"]), "Higher is better"],
            ["F1", _fmt_pct(ml["f1"]), _fmt_pct(hybrid["f1"]), "Higher is better"],
            ["False-positive rate", _fmt_pct(ml["false_positive_rate"]), _fmt_pct(hybrid["false_positive_rate"]), "Lower is better"],
            ["False-negative rate", _fmt_pct(ml["false_negative_rate"]), _fmt_pct(hybrid["false_negative_rate"]), "Lower is better"],
            ["Average latency", _fmt_ms(ml["average_latency_ms"]), _fmt_ms(hybrid["average_latency_ms"]), "Operational trade-off"],
        ],
    )

    composition_text = (
        ", ".join(f"{key}={value}" for key, value in sorted(composition.items()))
        if composition
        else "Challenge composition artifact not available"
    )
    route_text = ", ".join(f"{key}={value}" for key, value in sorted(route_counts.items()))

    report = f"""# Hybrid Threat-Triage Evaluation Report

## Executive Summary

The project combines a high-performing classical ML classifier with deterministic security evidence, risk-based routing, and selective Google ADK/Gemini review. The locked test set remains the population-level baseline. A separate, deliberately difficult challenge set is used to measure whether Hybrid triage can recover security-critical ML failures.

On the live challenge rows, Hybrid threat recall improved from **{_fmt_pct(ml['recall'])}** to **{_fmt_pct(hybrid['recall'])}**, while the false-negative rate fell from **{_fmt_pct(ml['false_negative_rate'])}** to **{_fmt_pct(hybrid['false_negative_rate'])}**. Hybrid recovered **{fn_recovered}/{fn_total}** ML false negatives (**{_fmt_pct(fn_rate) if fn_rate is not None else 'N/A'} recovery**).

> These challenge-set metrics are not population metrics. The challenge is intentionally enriched with ML errors to test failure recovery.

## 1. Population Baseline — Locked Test Set

The classical ML model was evaluated on **{int(locked_metrics['total_samples']):,}** locked-test messages.

| Metric | Value |
| --- | ---: |
| Accuracy | {_fmt_pct(locked_metrics['accuracy'])} |
| Precision | {_fmt_pct(locked_metrics['precision'])} |
| Recall | {_fmt_pct(locked_metrics['recall'])} |
| F1 | {_fmt_pct(locked_metrics['f1'])} |
| False-positive rate | {_fmt_pct(locked_metrics['false_positive_rate'])} |
| False-negative rate | {_fmt_pct(locked_metrics['false_negative_rate'])} |
| False negatives | {int(locked_metrics['false_negative'])} |
| Selected threshold | {_fmt_float(locked.get('selected_threshold'), 4)} |

This is the correct baseline for generalization claims. The selected challenge set below should not be compared to it as if both represented the same data distribution.

## 2. Challenge-Set Design

The persisted challenge artifact contains: **{composition_text}**.

The live benchmark evaluated **{int(challenge['live_sample_count'])}** rows using **`{challenge['gemini_model']}`**. Live routing distribution: **{route_text}**.

Agent invocation rate on the live challenge was **{_fmt_pct(hybrid.get('agent_invocation_rate'))}**. This high rate is expected for an intentionally difficult challenge subset and is not a production traffic estimate.

## 3. ML_ONLY vs HYBRID on Identical Live Rows

{challenge_metrics_table}

![ML_ONLY vs HYBRID metrics](figures/ml_vs_hybrid_metrics.png)

The main security result is the improvement in recall and corresponding reduction in false negatives. Hybrid also reduced the false-positive rate on this selected challenge, rather than improving recall only by indiscriminately classifying more messages as threats.

## 4. False-Negative Recovery

- ML false negatives represented in live challenge: **{fn_total}**
- Recovered by Hybrid: **{fn_recovered}**
- Still missed by Hybrid: **{fn_total - fn_recovered}**
- Recovery rate: **{_fmt_pct(fn_rate) if fn_rate is not None else 'N/A'}**

![False-negative recovery](figures/false_negative_recovery.png)

This supports the architecture's intended role: use deterministic processing to identify risk/uncertainty and escalate selected difficult cases for deeper semantic review. It does **not** imply that agent review eliminates all classification errors.

## 5. Operational Trade-off

Average evaluation latency increased from **{_fmt_ms(ml['average_latency_ms'])}** for ML_ONLY to **{_fmt_ms(hybrid['average_latency_ms'])}** for HYBRID.

![Latency comparison](figures/latency_comparison.png)

The latency cost is acceptable only when agent review is selective. A production deployment should keep ALLOW/MONITOR decisions on the deterministic fast path and reserve model-backed analysis for messages whose risk or ambiguity justifies the additional latency and external-provider dependency.

## 6. Architecture Interpretation

```text
Message
  -> ML classification
  -> deterministic security feature extraction
  -> risk scoring
  -> deterministic routing
       -> ALLOW / MONITOR / HUMAN_REVIEW: no Gemini required
       -> AGENT_REVIEW: Google ADK/Gemini + optional threat-intelligence tools
  -> structured decision + audit evidence
```

The experiment supports a layered decision system rather than an LLM-first security architecture. Security-critical boundaries stay deterministic; the LLM interprets evidence for selected cases.

## 7. Limitations

- The live challenge deliberately oversamples ML errors and is not representative of production prevalence.
- Gemini/tool output can be nondeterministic and provider availability can change over time.
- The canonical evaluation is binary **BENIGN / THREAT**; fine-grained labels should not be inferred without a supported taxonomy.
- Historical email corpora may not represent current enterprise phishing/BEC distributions.
- A direct Gemini-only benchmark is intentionally excluded until a separately tested raw-message contract exists.
- Token/cost claims are intentionally omitted because this evaluation did not persist authoritative usage telemetry.

## 8. Portfolio Result

**Locked population baseline:** accuracy **{_fmt_pct(locked_metrics['accuracy'])}**, recall **{_fmt_pct(locked_metrics['recall'])}**, F1 **{_fmt_pct(locked_metrics['f1'])}** on **{int(locked_metrics['total_samples']):,}** messages.

**Challenge-set recovery:** Hybrid increased threat recall from **{_fmt_pct(ml['recall'])}** to **{_fmt_pct(hybrid['recall'])}** and recovered **{fn_recovered}/{fn_total} ({_fmt_pct(fn_rate) if fn_rate is not None else 'N/A'})** ML false negatives represented in the live challenge, at the cost of higher inference latency.

---

Generated from persisted Notebook 04 evaluation artifacts. Full message bodies are intentionally excluded from the report.
"""

    report_path = output_dir / "evaluation_report.md"
    report_path.write_text(report, encoding="utf-8")

    return ReportResult(
        report_path=report_path,
        metrics_figure_path=metrics_figure,
        recovery_figure_path=recovery_figure,
        latency_figure_path=latency_figure,
        false_negative_count=fn_total,
        recovered_false_negative_count=fn_recovered,
        false_negative_recovery_rate=fn_rate,
    )
