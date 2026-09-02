from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    project_root: Path
    model_path: Path
    metrics_path: Path
    gemini_model: str
    enable_agent_review: bool
    api_title: str
    api_version: str
    max_body_chars: int

    @classmethod
    def from_env(cls) -> "Settings":
        project_root = Path(
            os.getenv("THREAT_TRIAGE_PROJECT_ROOT", Path.cwd())
        ).resolve()

        return cls(
            project_root=project_root,
            model_path=Path(
                os.getenv(
                    "THREAT_TRIAGE_MODEL_PATH",
                    project_root
                    / "artifacts"
                    / "ml_baseline"
                    / "tfidf_logistic_regression.joblib",
                )
            ),
            metrics_path=Path(
                os.getenv(
                    "THREAT_TRIAGE_METRICS_PATH",
                    project_root
                    / "artifacts"
                    / "ml_baseline"
                    / "metrics.json",
                )
            ),
            gemini_model=os.getenv(
                "THREAT_TRIAGE_GEMINI_MODEL",
                "gemini-3.5-flash-lite",
            ),
            enable_agent_review=_env_bool(
                "THREAT_TRIAGE_ENABLE_AGENT_REVIEW",
                True,
            ),
            api_title=os.getenv(
                "THREAT_TRIAGE_API_TITLE",
                "Intelligent Spam & Threat Triage API",
            ),
            api_version=os.getenv(
                "THREAT_TRIAGE_API_VERSION",
                "1.0.0",
            ),
            max_body_chars=int(
                os.getenv(
                    "THREAT_TRIAGE_MAX_BODY_CHARS",
                    "50000",
                )
            ),
        )
