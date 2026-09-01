#!/usr/bin/env python3
"""Generate B7 portfolio evaluation report from Notebook 04 artifacts."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


ROOT = _project_root()
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threat_triage.evaluation.reporting import generate_evaluation_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate portfolio-ready B7 evaluation report and figures."
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=ROOT / "artifacts" / "evaluation",
        help="Directory containing Notebook 04 evaluation artifacts.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional report destination. Defaults to --artifact-dir.",
    )
    args = parser.parse_args()

    result = generate_evaluation_report(args.artifact_dir, args.output_dir)

    print("B7 EVALUATION REPORT COMPLETE")
    print(f"Report: {result.report_path}")
    print(f"Metrics figure: {result.metrics_figure_path}")
    print(f"FN recovery figure: {result.recovery_figure_path}")
    print(f"Latency figure: {result.latency_figure_path}")
    print(
        "False-negative recovery: "
        f"{result.recovered_false_negative_count}/{result.false_negative_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
