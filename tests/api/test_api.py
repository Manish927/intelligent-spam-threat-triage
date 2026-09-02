from __future__ import annotations

from fastapi.testclient import TestClient

from threat_triage.api.app import app
from threat_triage.api.dependencies import get_triage_service
from threat_triage.api.models import (
    AgentResponse,
    MLEvidenceResponse,
    RiskResponse,
    RoutingResponse,
    SecurityEvidenceResponse,
    TriageResponse,
)


class FakeService:
    model_loaded = True

    async def triage(self, request):
        return TriageResponse(
            message_id=request.message_id or "generated-id",
            final_label="THREAT",
            final_disposition="QUARANTINE",
            ml=MLEvidenceResponse(
                predicted_label="BENIGN",
                threat_probability=0.35,
                decision_threshold=0.7364,
                model_name="tfidf-logistic-regression",
                model_version="0.1.0",
            ),
            security=SecurityEvidenceResponse(
                total_signal_count=3,
                strong_signals=["lang_urgency"],
                evidence_categories=["LANGUAGE"],
            ),
            risk=RiskResponse(
                score=48.0,
                severity="MEDIUM",
                confidence=0.8,
                requires_deep_analysis=True,
                reasons=["Conflicting evidence"],
            ),
            routing=RoutingResponse(
                decision="AGENT_REVIEW",
                reason="Message requires Agentic AI review",
                requires_human_review=False,
            ),
            agent=AgentResponse(
                invoked=True,
                model="gemini-3.5-flash-lite",
                disposition="QUARANTINE",
                confidence=0.91,
                explanation="Suspicious contextual evidence.",
                findings=[],
                reasons=["Credential-harvesting indicators"],
            ),
            latency_ms=125.0,
        )


def override_service():
    return FakeService()


app.dependency_overrides[get_triage_service] = override_service
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["model_loaded"] is True


def test_triage():
    response = client.post(
        "/api/v1/triage",
        json={
            "sender": "security@example.com",
            "subject": "Urgent",
            "body": "Verify your account immediately.",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["final_label"] == "THREAT"
    assert payload["final_disposition"] == "QUARANTINE"
    assert payload["routing"]["decision"] == "AGENT_REVIEW"
    assert payload["agent"]["invoked"] is True


def test_empty_body_rejected():
    response = client.post(
        "/api/v1/triage",
        json={
            "subject": "Test",
            "body": "",
        },
    )
    assert response.status_code == 422
