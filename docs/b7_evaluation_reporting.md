# B7 — Portfolio-Ready Evaluation Report

B7 converts the persisted Notebook 04 evaluation artifacts into a reproducible Markdown report and three portfolio figures. It does **not** rerun Gemini, the ML model, or threat-intelligence calls.

## Files added

```text
src/threat_triage/evaluation/reporting.py
scripts/generate_evaluation_report.py
tests/evaluation/test_reporting.py
```

Generated at runtime:

```text
artifacts/evaluation/evaluation_report.md
artifacts/evaluation/figures/ml_vs_hybrid_metrics.png
artifacts/evaluation/figures/false_negative_recovery.png
artifacts/evaluation/figures/latency_comparison.png
```

## Prerequisite

Notebook 04 must already have generated:

```text
artifacts/evaluation/ml_locked_test_summary.json
artifacts/evaluation/ml_vs_hybrid_challenge_summary.json
artifacts/evaluation/ml_vs_hybrid_sample_results.csv
```

The existing optional `hybrid_challenge_set.csv` is also consumed when present.

## Run

From the repository root:

```bash
python scripts/generate_evaluation_report.py
```

Then run the test suite:

```bash
pytest -q
```

No API keys are required for B7 because it consumes already persisted B6 results.

## Design rule

The report intentionally separates:

1. **Locked-test population baseline** — general model performance.
2. **Error-enriched challenge benchmark** — Hybrid failure-recovery evidence.

The challenge result must never be presented as population-wide accuracy.
