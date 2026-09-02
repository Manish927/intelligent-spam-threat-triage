from __future__ import annotations

import logging
import uuid

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from threat_triage.api.dependencies import (
    get_settings,
    get_triage_service,
)
from threat_triage.api.models import (
    ErrorResponse,
    HealthResponse,
    TriageRequest,
    TriageResponse,
)
from threat_triage.config.settings import Settings
from threat_triage.service.triage_service import ProductionTriageService

logger = logging.getLogger(__name__)

settings = get_settings()

app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description=(
        "Deterministic-first email threat triage with selective "
        "Google ADK/Gemini review."
    ),
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
):
    request_id = request.headers.get(
        "x-request-id",
        str(uuid.uuid4()),
    )
    logger.exception(
        "Unhandled triage API error request_id=%s",
        request_id,
    )
    payload = ErrorResponse(
        error="internal_server_error",
        detail=(
            "The request could not be completed. "
            "See server logs using the request id."
        ),
        request_id=request_id,
    )
    return JSONResponse(
        status_code=500,
        content=payload.model_dump(),
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Operations"],
)
async def health(
    service: ProductionTriageService = Depends(
        get_triage_service
    ),
    cfg: Settings = Depends(get_settings),
) -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=cfg.api_version,
        model_loaded=service.model_loaded,
        agent_review_enabled=cfg.enable_agent_review,
        gemini_model=cfg.gemini_model,
    )


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["Operations"],
)
async def versioned_health(
    service: ProductionTriageService = Depends(
        get_triage_service
    ),
    cfg: Settings = Depends(get_settings),
) -> HealthResponse:
    return await health(service, cfg)


@app.post(
    "/api/v1/triage",
    response_model=TriageResponse,
    responses={500: {"model": ErrorResponse}},
    tags=["Triage"],
)
async def triage_message(
    request: TriageRequest,
    service: ProductionTriageService = Depends(
        get_triage_service
    ),
) -> TriageResponse:
    return await service.triage(request)
