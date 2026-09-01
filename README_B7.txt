B7 ADDITIVE PACKAGE
===================

Extract this ZIP into the ROOT of the existing intelligent-spam-threat-triage repository.
It only adds B7 reporting files; it does not replace Notebook 04 or existing production modules.

Then run:

  python scripts/generate_evaluation_report.py
  pytest -q

Expected report:
  artifacts/evaluation/evaluation_report.md

Expected figures:
  artifacts/evaluation/figures/ml_vs_hybrid_metrics.png
  artifacts/evaluation/figures/false_negative_recovery.png
  artifacts/evaluation/figures/latency_comparison.png
