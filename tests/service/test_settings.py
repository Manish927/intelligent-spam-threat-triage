from pathlib import Path

from threat_triage.config.settings import Settings


def test_settings_default_model(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "THREAT_TRIAGE_PROJECT_ROOT",
        str(tmp_path),
    )
    monkeypatch.delenv(
        "THREAT_TRIAGE_GEMINI_MODEL",
        raising=False,
    )

    settings = Settings.from_env()

    assert settings.gemini_model == "gemini-3.5-flash-lite"
    assert settings.project_root == tmp_path.resolve()
    assert (
        settings.model_path
        == tmp_path
        / "artifacts"
        / "ml_baseline"
        / "tfidf_logistic_regression.joblib"
    )
