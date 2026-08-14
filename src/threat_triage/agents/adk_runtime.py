from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from threat_triage.agents.message_review_agent import (
    AGENT_NAME,
    AGENT_VERSION,
    MESSAGE_REVIEW_INSTRUCTION,
    get_message_review_tool_functions,
)
from threat_triage.agents.models import (
    AgentDisposition,
    AgentFindingCategory,
    AgentFindingSeverity,
)


class ADKAgentFinding(BaseModel):
    """
    Structured finding produced by Gemini/ADK.

    Enum-backed fields ensure the model is constrained to the same
    vocabulary used by the platform contract.
    """

    category: AgentFindingCategory

    finding: str

    severity: AgentFindingSeverity

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    evidence_refs: list[str] = Field(
        default_factory=list
    )


class ADKAgentRecommendation(BaseModel):
    """
    Structured recommendation produced by Gemini/ADK.
    """

    disposition: AgentDisposition

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    reasons: list[str]

    requires_human_review: bool = False


class ADKAgentModelMetadata(BaseModel):
    provider: str
    model_name: str
    agent_version: str
    request_id: str | None = None


class ADKAgentReviewResult(BaseModel):
    message_id: str

    findings: list[ADKAgentFinding]

    recommendation: ADKAgentRecommendation

    explanation: str

    model_metadata: ADKAgentModelMetadata


def create_message_review_agent(
    *,
    model: str,
) -> Any:
    normalized_model = _validate_model_name(
        model
    )

    try:
        from google.adk.agents import Agent

    except ImportError as exc:
        raise RuntimeError(
            "google-adk is not installed. "
            "Install the optional ADK dependency "
            "before creating the runtime agent."
        ) from exc

    return Agent(
        name=AGENT_NAME,
        model=normalized_model,
        description=(
            "Reviews enterprise email-security evidence "
            "and produces a constrained recommendation."
        ),
        instruction=MESSAGE_REVIEW_INSTRUCTION,
        tools=get_message_review_tool_functions(),
        output_schema=ADKAgentReviewResult,
        output_key="message_review_result",
    )


def get_agent_runtime_metadata(
    *,
    model: str,
) -> dict[str, str]:
    normalized_model = _validate_model_name(
        model
    )

    return {
        "agent_name": AGENT_NAME,
        "agent_version": AGENT_VERSION,
        "provider": "google",
        "model": normalized_model,
    }


def _validate_model_name(
    model: str,
) -> str:
    if model is None:
        raise ValueError(
            "model must not be empty"
        )

    normalized = str(
        model
    ).strip()

    if not normalized:
        raise ValueError(
            "model must not be empty"
        )

    return normalized