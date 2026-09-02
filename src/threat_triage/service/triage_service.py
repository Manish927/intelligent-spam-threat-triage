from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Optional

import joblib

from threat_triage.agents.adk_runner import run_agent_review
from threat_triage.api.models import (
    AgentResponse,
    MLEvidenceResponse,
    RiskResponse,
    RoutingResponse,
    SecurityEvidenceResponse,
    TriageRequest,
    TriageResponse,
)
from threat_triage.config.settings import Settings
from threat_triage.risk.evidence_builder import build_risk_evidence
from threat_triage.risk.models import MLEvidence, RoutingDecision
from threat_triage.agents.review_context import build_agent_review_input
from threat_triage.risk.risk_scorer import score_risk
from threat_triage.risk.routing_policy import route_message
from threat_triage.security.feature_extractor import extract_security_features
from threat_triage.service.serialization import to_jsonable


class ProductionTriageService:
    """
    Stateless production orchestration boundary.

    Flow:
      ML -> deterministic security -> risk -> routing
         -> optional Google ADK/Gemini review
         -> structured explainable response

    Security-critical routing stays deterministic. Gemini is invoked
    only when the policy returns AGENT_REVIEW.
    """

    MODEL_NAME = "tfidf-logistic-regression"
    MODEL_VERSION = "0.1.0"

    def __init__(
        self,
        *,
        settings: Settings,
        model=None,
        decision_threshold: Optional[float] = None,
        agent_executor=run_agent_review,
    ) -> None:
        self.settings = settings
        self._agent_executor = agent_executor

        self._model = (
            model
            if model is not None
            else joblib.load(settings.model_path)
        )

        self._decision_threshold = (
            float(decision_threshold)
            if decision_threshold is not None
            else self._load_threshold(settings.metrics_path)
        )

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    @property
    def decision_threshold(self) -> float:
        return self._decision_threshold

    @staticmethod
    def _load_threshold(metrics_path: Path) -> float:
        with open(metrics_path, "r", encoding="utf-8") as file:
            metadata = json.load(file)
        return float(metadata["selected_threshold"])

    @staticmethod
    def _combined_text(
        subject: Optional[str],
        body: str,
    ) -> str:
        # Mirrors the public-service contract: subject and body are
        # presented as one textual document to the sklearn pipeline.
        # Keep this function centralized so it can be synchronized with
        # canonical data_loader behavior if that format changes.
        parts = [
            value.strip()
            for value in (subject or "", body or "")
            if value and value.strip()
        ]
        return "\n".join(parts)

    def _build_ml_evidence(
        self,
        *,
        subject: Optional[str],
        body: str,
    ) -> MLEvidence:
        text = self._combined_text(subject, body)
        probability = float(
            self._model.predict_proba([text])[0][1]
        )
        label = (
            "THREAT"
            if probability >= self._decision_threshold
            else "BENIGN"
        )
        return MLEvidence(
            predicted_label=label,
            threat_probability=probability,
            decision_threshold=self._decision_threshold,
            model_name=self.MODEL_NAME,
            model_version=self.MODEL_VERSION,
        )

    async def triage(
        self,
        request: TriageRequest,
    ) -> TriageResponse:
        started = time.perf_counter()

        message_id = (
            request.message_id.strip()
            if request.message_id
            else str(uuid.uuid4())
        )

        ml = self._build_ml_evidence(
            subject=request.subject,
            body=request.body,
        )

        security = extract_security_features(
            message_id=message_id,
            subject=request.subject,
            body=request.body,
            sender=request.sender,
        )

        evidence = build_risk_evidence(
            message_id=message_id,
            ml_evidence=ml,
            security_features=security,
        )

        assessment = score_risk(evidence)

        routing = route_message(
            evidence=evidence,
            assessment=assessment,
        )

        final_label = ml.predicted_label
        final_disposition = routing.decision.value

        agent_response = AgentResponse(
            invoked=False,
        )

        if routing.decision == RoutingDecision.AGENT_REVIEW:
            if self.settings.enable_agent_review:
                review_input = build_agent_review_input(
                    message_id=message_id,
                    subject=request.subject,
                    body=request.body,
                    sender=request.sender,
                    risk_evidence=evidence,
                    risk_assessment=assessment,
                    routing_result=routing,
                )

                agent_result = await self._agent_executor(
                    review_input=review_input,
                    model=self.settings.gemini_model,
                )

                recommendation = agent_result.recommendation
                disposition = recommendation.disposition.value

                # The current binary API taxonomy maps ALLOW to BENIGN.
                # MONITOR/QUARANTINE/HUMAN_REVIEW represent security concern
                # and therefore map to THREAT at the classification layer.
                final_label = (
                    "BENIGN"
                    if disposition == "ALLOW"
                    else "THREAT"
                )
                final_disposition = disposition

                findings = [
                    to_jsonable(item)
                    for item in agent_result.findings
                ]

                agent_response = AgentResponse(
                    invoked=True,
                    model=self.settings.gemini_model,
                    disposition=disposition,
                    confidence=float(
                        recommendation.confidence
                    ),
                    explanation=agent_result.explanation,
                    findings=findings,
                    reasons=list(
                        recommendation.reasons
                    ),
                )
            else:
                # Useful for local/offline operation: the deterministic
                # pipeline still reports that agent review is required.
                final_disposition = "AGENT_REVIEW"

        elapsed_ms = (
            time.perf_counter() - started
        ) * 1000.0

        return TriageResponse(
            message_id=message_id,
            final_label=str(final_label),
            final_disposition=str(final_disposition),
            ml=MLEvidenceResponse(
                predicted_label=str(ml.predicted_label),
                threat_probability=float(
                    ml.threat_probability
                ),
                decision_threshold=float(
                    ml.decision_threshold
                ),
                model_name=ml.model_name,
                model_version=ml.model_version,
            ),
            security=SecurityEvidenceResponse(
                total_signal_count=(
                    evidence.summary.total_signal_count
                ),
                strong_signals=list(
                    evidence.summary.strong_signals
                ),
                evidence_categories=list(
                    evidence.summary.evidence_categories
                ),
            ),
            risk=RiskResponse(
                score=float(assessment.risk_score),
                severity=assessment.severity.value,
                confidence=float(assessment.confidence),
                requires_deep_analysis=(
                    assessment.requires_deep_analysis
                ),
                reasons=list(assessment.reasons),
            ),
            routing=RoutingResponse(
                decision=routing.decision.value,
                reason=routing.reason,
                requires_human_review=(
                    routing.requires_human_review
                ),
            ),
            agent=agent_response,
            latency_ms=round(elapsed_ms, 2),
        )
