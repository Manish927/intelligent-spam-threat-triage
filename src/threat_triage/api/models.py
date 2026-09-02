from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class TriageRequest(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    message_id: Optional[str] = Field(
        default=None,
        description="Caller-provided stable message id. Generated when omitted.",
        max_length=256,
    )
    subject: Optional[str] = Field(
        default=None,
        max_length=2000,
    )
    body: str = Field(
        min_length=1,
        max_length=50000,
    )
    sender: Optional[str] = Field(
        default=None,
        max_length=2000,
    )


class MLEvidenceResponse(BaseModel):
    predicted_label: str
    threat_probability: float
    decision_threshold: float
    model_name: str
    model_version: str


class SecurityEvidenceResponse(BaseModel):
    total_signal_count: int
    strong_signals: list[str]
    evidence_categories: list[str]


class RiskResponse(BaseModel):
    score: float
    severity: str
    confidence: float
    requires_deep_analysis: bool
    reasons: list[str]


class RoutingResponse(BaseModel):
    decision: str
    reason: str
    requires_human_review: bool


class AgentResponse(BaseModel):
    invoked: bool
    model: Optional[str] = None
    disposition: Optional[str] = None
    confidence: Optional[float] = None
    explanation: Optional[str] = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class TriageResponse(BaseModel):
    message_id: str
    final_label: str
    final_disposition: str
    ml: MLEvidenceResponse
    security: SecurityEvidenceResponse
    risk: RiskResponse
    routing: RoutingResponse
    agent: AgentResponse
    latency_ms: float


class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool
    agent_review_enabled: bool
    gemini_model: str


class ErrorResponse(BaseModel):
    error: str
    detail: str
    request_id: Optional[str] = None
