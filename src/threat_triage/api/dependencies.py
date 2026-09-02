from __future__ import annotations

from functools import lru_cache

from threat_triage.config.settings import Settings
from threat_triage.service.triage_service import ProductionTriageService


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()


@lru_cache(maxsize=1)
def get_triage_service() -> ProductionTriageService:
    return ProductionTriageService(
        settings=get_settings()
    )
