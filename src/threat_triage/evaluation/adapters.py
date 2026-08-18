from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from threat_triage.agents.models import (
    AgentDisposition,
    AgentReviewResult,
)
from threat_triage.agents.review_context import (
    build_agent_review_input,
)
from threat_triage.evaluation.models import (
    EvaluationDisposition,
    EvaluationLabel,
    EvaluationPrediction,
    EvaluationSample,
)
from threat_triage.risk.evidence_builder import (
    build_risk_evidence,
)
from threat_triage.risk.models import (
    MLEvidence,
    RoutingDecision,
)
from threat_triage.risk.risk_scorer import (
    score_risk,
)
from threat_triage.risk.routing_policy import (
    route_message,
)
from threat_triage.security.feature_extractor import (
    extract_security_features,
)


DEFAULT_ML_THRESHOLD = 0.7364
DEFAULT_MODEL_NAME = "tfidf-logistic-regression"
DEFAULT_MODEL_VERSION = "0.1.0"


class ProbabilityModel(Protocol):
    """
    Minimal interface required from the trained sklearn/joblib
    baseline artifact.
    """

    def predict_proba(
        self,
        values,
    ):
        ...


AgentReviewExecutor = Callable[
    ...,
    Awaitable[AgentReviewResult],
]


@dataclass(frozen=True)
class MLArtifactAdapter:
    """
    Adapter between the trained TF-IDF / Logistic Regression artifact
    and the normalized evaluation contract.

    The evaluation layer does not need to know whether the artifact is
    a sklearn Pipeline, LogisticRegression wrapper, or another object.

    It only requires predict_proba().
    """

    model: ProbabilityModel

    decision_threshold: float = (
        DEFAULT_ML_THRESHOLD
    )

    model_name: str = (
        DEFAULT_MODEL_NAME
    )

    model_version: str = (
        DEFAULT_MODEL_VERSION
    )

    def __post_init__(self) -> None:
        if not 0.0 <= self.decision_threshold <= 1.0:
            raise ValueError(
                "decision_threshold must be "
                "between 0 and 1"
            )

        if not self.model_name:
            raise ValueError(
                "model_name must not be empty"
            )

        if not self.model_version:
            raise ValueError(
                "model_version must not be empty"
            )

        if not hasattr(
            self.model,
            "predict_proba",
        ):
            raise TypeError(
                "model must provide predict_proba"
            )

    def build_model_text(
        self,
        sample: EvaluationSample,
    ) -> str:
        """
        Construct the text consumed by the baseline artifact.

        The current baseline is text-oriented, so sender/URL structural
        evidence remains outside this ML-only input and is handled by
        the deterministic security layer in HYBRID mode.
        """

        parts: list[str] = []

        if sample.subject:
            parts.append(
                str(sample.subject).strip()
            )

        if sample.body:
            parts.append(
                str(sample.body).strip()
            )

        return "\n".join(
            part
            for part in parts
            if part
        )

    def predict_probability(
        self,
        sample: EvaluationSample,
    ) -> float:
        """
        Return probability for the positive THREAT class.

        The existing sklearn-style baseline is expected to return
        two probability columns:

            [:, 0] benign
            [:, 1] threat
        """

        text = self.build_model_text(
            sample
        )

        probabilities = (
            self.model.predict_proba(
                [text]
            )
        )

        try:
            probability = float(
                probabilities[0][1]
            )

        except (
            IndexError,
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                "model predict_proba returned "
                "an unsupported result"
            ) from exc

        if not 0.0 <= probability <= 1.0:
            raise ValueError(
                "model threat probability must be "
                "between 0 and 1"
            )

        return probability

    def build_ml_evidence(
        self,
        sample: EvaluationSample,
    ) -> MLEvidence:
        """
        Produce the existing platform MLEvidence contract.
        """

        probability = (
            self.predict_probability(
                sample
            )
        )

        predicted_label = (
            "THREAT"
            if probability
            >= self.decision_threshold
            else "BENIGN"
        )

        return MLEvidence(
            predicted_label=predicted_label,
            threat_probability=probability,
            decision_threshold=(
                self.decision_threshold
            ),
            model_name=self.model_name,
            model_version=self.model_version,
        )

    def evaluate(
        self,
        sample: EvaluationSample,
    ) -> EvaluationPrediction:
        """
        Produce normalized ML_ONLY prediction.
        """

        evidence = (
            self.build_ml_evidence(
                sample
            )
        )

        label = (
            EvaluationLabel.THREAT
            if evidence.predicted_label
            == "THREAT"
            else EvaluationLabel.BENIGN
        )

        probability = (
            evidence.threat_probability
        )

        confidence = (
            probability
            if label == EvaluationLabel.THREAT
            else 1.0 - probability
        )

        return EvaluationPrediction(
            predicted_label=label,
            confidence=confidence,
            disposition=(
                EvaluationDisposition
                .NOT_APPLICABLE
            ),
            threat_probability=probability,
            explanation=(
                "Classical TF-IDF / Logistic "
                "Regression baseline prediction."
            ),
        )


@dataclass(frozen=True)
class HybridEvaluationAdapter:
    """
    Production-style hybrid evaluation adapter.

    Flow:

        ML baseline
            +
        deterministic security features
            ↓
        RiskEvidence
            ↓
        deterministic risk scorer
            ↓
        routing policy
            ↓
        Gemini only when AGENT_REVIEW
    """

    ml_adapter: MLArtifactAdapter

    agent_executor: AgentReviewExecutor | None = None

    gemini_model: str = "gemini-3.6-flash"

    def __post_init__(self) -> None:
        if not self.gemini_model:
            raise ValueError(
                "gemini_model must not be empty"
            )

    async def evaluate(
        self,
        sample: EvaluationSample,
    ) -> EvaluationPrediction:
        ml_evidence = (
            self.ml_adapter
            .build_ml_evidence(
                sample
            )
        )

        security_features = (
            extract_security_features(
                message_id=sample.sample_id,
                subject=sample.subject,
                body=sample.body,
                sender=sample.sender,
            )
        )

        risk_evidence = (
            build_risk_evidence(
                message_id=sample.sample_id,
                ml_evidence=ml_evidence,
                security_features=(
                    security_features
                ),
            )
        )

        assessment = score_risk(
            risk_evidence
        )

        routing = route_message(
            evidence=risk_evidence,
            assessment=assessment,
        )

        if (
            routing.decision
            == RoutingDecision.AGENT_REVIEW
        ):
            return await (
                self._evaluate_with_agent(
                    sample=sample,
                    risk_evidence=(
                        risk_evidence
                    ),
                    assessment=assessment,
                    routing=routing,
                )
            )

        return (
            self._prediction_from_routing(
                ml_evidence=ml_evidence,
                assessment=assessment,
                routing=routing,
            )
        )

    async def _evaluate_with_agent(
        self,
        *,
        sample: EvaluationSample,
        risk_evidence,
        assessment,
        routing,
    ) -> EvaluationPrediction:
        if self.agent_executor is None:
            raise RuntimeError(
                "Hybrid evaluation requires "
                "agent_executor for AGENT_REVIEW"
            )

        review_input = (
            build_agent_review_input(
                message_id=sample.sample_id,
                subject=sample.subject,
                body=sample.body,
                sender=sample.sender,
                risk_evidence=(
                    risk_evidence
                ),
                risk_assessment=assessment,
                routing_result=routing,
            )
        )

        result = await self.agent_executor(
            review_input=review_input,
            model=self.gemini_model,
        )

        label = (
            _label_from_agent_disposition(
                result
                .recommendation
                .disposition
            )
        )

        disposition = (
            _evaluation_disposition_from_agent(
                result
                .recommendation
                .disposition
            )
        )

        return EvaluationPrediction(
            predicted_label=label,
            confidence=(
                result
                .recommendation
                .confidence
            ),
            disposition=disposition,
            threat_probability=(
                risk_evidence
                .ml
                .threat_probability
            ),
            explanation=(
                result.explanation
            ),
        )

    @staticmethod
    def _prediction_from_routing(
        *,
        ml_evidence: MLEvidence,
        assessment,
        routing,
    ) -> EvaluationPrediction:
        decision = routing.decision

        if (
            decision
            == RoutingDecision.ALLOW
        ):
            label = EvaluationLabel.BENIGN
            disposition = (
                EvaluationDisposition.ALLOW
            )

        elif (
            decision
            == RoutingDecision.MONITOR
        ):
            # MONITOR is conservatively treated as THREAT for
            # binary detection evaluation while preserving the
            # operational disposition separately.
            label = EvaluationLabel.THREAT
            disposition = (
                EvaluationDisposition.MONITOR
            )

        elif (
            decision
            == RoutingDecision.HUMAN_REVIEW
        ):
            label = EvaluationLabel.THREAT
            disposition = (
                EvaluationDisposition
                .HUMAN_REVIEW
            )

        else:
            raise ValueError(
                "Unsupported direct routing decision"
            )

        return EvaluationPrediction(
            predicted_label=label,
            confidence=assessment.confidence,
            disposition=disposition,
            threat_probability=(
                ml_evidence.threat_probability
            ),
            explanation=routing.reason,
        )


def _label_from_agent_disposition(
    disposition: AgentDisposition,
) -> EvaluationLabel:
    if (
        disposition
        == AgentDisposition.ALLOW
    ):
        return EvaluationLabel.BENIGN

    return EvaluationLabel.THREAT


def _evaluation_disposition_from_agent(
    disposition: AgentDisposition,
) -> EvaluationDisposition:
    mapping = {
        AgentDisposition.ALLOW: (
            EvaluationDisposition.ALLOW
        ),

        AgentDisposition.MONITOR: (
            EvaluationDisposition.MONITOR
        ),

        AgentDisposition.QUARANTINE: (
            EvaluationDisposition
            .QUARANTINE
        ),

        AgentDisposition.HUMAN_REVIEW: (
            EvaluationDisposition
            .HUMAN_REVIEW
        ),
    }

    try:
        return mapping[
            disposition
        ]

    except KeyError as exc:
        raise ValueError(
            "Unsupported agent disposition"
        ) from exc