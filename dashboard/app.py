from __future__ import annotations

import os
from typing import Any

import requests
import streamlit as st

API_BASE_URL = os.getenv(
    "THREAT_TRIAGE_API_BASE_URL",
    "http://localhost:8000",
).rstrip("/")

st.set_page_config(
    page_title="Intelligent Threat Triage",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Intelligent Spam & Threat Triage")
st.caption(
    "Deterministic-first security analysis with selective Agentic AI review"
)

with st.sidebar:
    st.header("Service")
    st.code(API_BASE_URL)
    try:
        health = requests.get(
            f"{API_BASE_URL}/health",
            timeout=5,
        )
        if health.ok:
            payload = health.json()
            st.success("API online")
            st.write(
                "Gemini:",
                payload.get("gemini_model"),
            )
            st.write(
                "Agent review:",
                "Enabled"
                if payload.get("agent_review_enabled")
                else "Disabled",
            )
        else:
            st.warning("API health check failed")
    except requests.RequestException:
        st.warning("API is not reachable")

st.subheader("Analyze an email")

sender = st.text_input(
    "Sender",
    placeholder="Security Team <security@example.com>",
)
subject = st.text_input(
    "Subject",
    placeholder="Urgent account verification",
)
body = st.text_area(
    "Message body",
    height=220,
    placeholder="Paste the email body here...",
)

analyze = st.button(
    "🔎 Triage message",
    type="primary",
    use_container_width=True,
)

if analyze:
    if not body.strip():
        st.error("Message body is required.")
        st.stop()

    request_payload = {
        "sender": sender or None,
        "subject": subject or None,
        "body": body,
    }

    try:
        with st.spinner(
            "Running ML, deterministic security, risk and routing..."
        ):
            response = requests.post(
                f"{API_BASE_URL}/api/v1/triage",
                json=request_payload,
                timeout=90,
            )

        if not response.ok:
            st.error(
                f"API error {response.status_code}: "
                f"{response.text}"
            )
            st.stop()

        result: dict[str, Any] = response.json()

    except requests.RequestException as exc:
        st.error(f"Could not call API: {exc}")
        st.stop()

    final_label = result["final_label"]
    disposition = result["final_disposition"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Final label", final_label)
    c2.metric("Disposition", disposition)
    c3.metric(
        "Risk score",
        f'{result["risk"]["score"]:.2f}',
    )
    c4.metric(
        "Latency",
        f'{result["latency_ms"]:.0f} ms',
    )

    st.divider()

    left, middle, right = st.columns(3)

    with left:
        st.subheader("Classical ML")
        st.metric(
            "Threat probability",
            f'{result["ml"]["threat_probability"]:.2%}',
        )
        st.write(
            "Prediction:",
            result["ml"]["predicted_label"],
        )
        st.write(
            "Decision threshold:",
            result["ml"]["decision_threshold"],
        )

    with middle:
        st.subheader("Security Evidence")
        st.metric(
            "Signals",
            result["security"]["total_signal_count"],
        )
        strong = result["security"]["strong_signals"]
        if strong:
            for signal in strong:
                st.warning(signal)
        else:
            st.info("No strong deterministic signals")

    with right:
        st.subheader("Routing")
        st.write(
            "**Decision:**",
            result["routing"]["decision"],
        )
        st.write(result["routing"]["reason"])
        if result["routing"]["requires_human_review"]:
            st.error("Human review required")

    st.divider()
    st.subheader("Agentic AI Review")

    if result["agent"]["invoked"]:
        st.success(
            f'Gemini invoked — {result["agent"]["model"]}'
        )
        ac1, ac2 = st.columns(2)
        ac1.metric(
            "Agent disposition",
            result["agent"]["disposition"],
        )
        confidence = result["agent"].get("confidence")
        ac2.metric(
            "Agent confidence",
            (
                f"{confidence:.2%}"
                if confidence is not None
                else "N/A"
            ),
        )
        if result["agent"].get("explanation"):
            st.write(
                result["agent"]["explanation"]
            )
        if result["agent"].get("reasons"):
            st.write("**Reasons**")
            for reason in result["agent"]["reasons"]:
                st.write("•", reason)
        if result["agent"].get("findings"):
            with st.expander("Agent findings"):
                st.json(result["agent"]["findings"])
    else:
        st.info(
            "Gemini was not invoked. "
            "The message stayed on the deterministic path."
        )

    with st.expander("Full structured API response"):
        st.json(result)
