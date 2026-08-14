import asyncio

from dotenv import load_dotenv

from threat_triage.agents.adk_runner import (
    run_agent_review,
)
from threat_triage.agents.review_context import (
    build_agent_review_input,
)
from threat_triage.risk import (
    MLEvidence,
    build_risk_evidence,
    route_message,
    score_risk,
)
from threat_triage.security import (
    extract_security_features,
)


load_dotenv()


MESSAGE_ID = "gemini-smoke-001"

SUBJECT = "URGENT: Account verification required"

BODY = (
    "Your account will be suspended. "
    "Verify your identity immediately at "
    "https://paypa1-security.xyz/login."
)

SENDER = (
    "PayPal Security "
    "<support@paypa1-security.example>"
)


async def main():
    # ---------------------------------------------------------
    # 1. Deterministic security evidence
    # ---------------------------------------------------------

    security_features = extract_security_features(
        message_id=MESSAGE_ID,
        subject=SUBJECT,
        body=BODY,
        sender=SENDER,
    )

    print("\nSecurity features created.")
    print(
        "Message ID:",
        security_features.message_id,
    )

    # ---------------------------------------------------------
    # 2. Simulated classical ML evidence
    #
    # For this smoke test we provide a known probability rather
    # than loading the Notebook-02 model artifact.
    # ---------------------------------------------------------

    ml_evidence = MLEvidence(
        predicted_label="BENIGN",
        threat_probability=0.10,
        decision_threshold=0.7364,
        model_name="tfidf-logistic-regression",
        model_version="0.1.0",
    )

    # ---------------------------------------------------------
    # 3. Build RiskEvidence
    # ---------------------------------------------------------

    risk_evidence = build_risk_evidence(
        message_id=MESSAGE_ID,
        ml_evidence=ml_evidence,
        security_features=security_features,
    )

    print("\nRisk evidence created.")

    print(
        "Total signals:",
        risk_evidence.summary.total_signal_count,
    )

    print(
        "Strong signals:",
        risk_evidence.summary.strong_signals,
    )

    # ---------------------------------------------------------
    # 4. Score risk
    # ---------------------------------------------------------

    risk_assessment = score_risk(
        risk_evidence
    )

    print("\nRisk assessment:")

    print(
        "Risk score:",
        risk_assessment.risk_score,
    )

    print(
        "Severity:",
        risk_assessment.severity.value,
    )

    print(
        "Deep analysis:",
        risk_assessment.requires_deep_analysis,
    )

    # ---------------------------------------------------------
    # 5. Route
    # ---------------------------------------------------------

    routing_result = route_message(
        evidence=risk_evidence,
        assessment=risk_assessment,
    )

    print("\nRouting decision:")
    print(
        routing_result.decision.value
    )

    if (
        routing_result.decision.value
        != "AGENT_REVIEW"
    ):
        raise RuntimeError(
            "Smoke-test case did not route to AGENT_REVIEW. "
            "Adjust test evidence before invoking Gemini."
        )

    # ---------------------------------------------------------
    # 6. Build bounded agent context
    # ---------------------------------------------------------

    review_input = build_agent_review_input(
        message_id=MESSAGE_ID,
        subject=SUBJECT,
        body=BODY,
        sender=SENDER,
        risk_evidence=risk_evidence,
        risk_assessment=risk_assessment,
        routing_result=routing_result,
    )

    print("\nAgent review input created.")

    # ---------------------------------------------------------
    # 7. LIVE Gemini / Google ADK invocation
    # ---------------------------------------------------------

    print(
        "\nCalling Gemini..."
    )

    result = await run_agent_review(
        review_input=review_input,
        model="gemini-3.6-flash",
    )

    # ---------------------------------------------------------
    # 8. Structured result
    # ---------------------------------------------------------

    print("\n==============================")
    print("AGENT REVIEW RESULT")
    print("==============================")

    print(
        "Message ID:",
        result.message_id,
    )

    print(
        "\nDisposition:",
        result.recommendation.disposition.value,
    )

    print(
        "Recommendation confidence:",
        result.recommendation.confidence,
    )

    print(
        "Human review required:",
        result.recommendation.requires_human_review,
    )

    print("\nFindings:")

    for index, finding in enumerate(
        result.findings,
        start=1,
    ):
        print(
            f"\nFinding {index}"
        )

        print(
            "Category:",
            finding.category.value,
        )

        print(
            "Severity:",
            finding.severity.value,
        )

        print(
            "Confidence:",
            finding.confidence,
        )

        print(
            "Finding:",
            finding.finding,
        )

        print(
            "Evidence refs:",
            finding.evidence_refs,
        )

    print("\nExplanation:")
    print(
        result.explanation
    )

    print("\nModel metadata:")
    print(
        result.model_metadata
    )


if __name__ == "__main__":
    asyncio.run(
        main()
    )