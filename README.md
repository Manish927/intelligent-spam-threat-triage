# Intelligent Spam Classification & Threat Triage Platform

An enterprise-grade portfolio project demonstrating how **Agentic AI, machine learning, deterministic security controls, threat intelligence, explainability, human-in-the-loop review, and production architecture** can work together to classify email/message threats and drive operational triage decisions.

This project evolves architectural ideas, decision-support project into the cybersecurity domain. The reusable pattern is:

> **Extract → Assess → Retrieve Evidence → Decide → Explain → Audit → Escalate**

The goal is not to build a toy "spam vs. not spam" classifier. The goal is to model a realistic **enterprise security decision platform** in which ML and LLM agents provide signals, while policy controls and human review protect high-impact decisions.

---

## 1. Project Objectives

The platform is designed to demonstrate:

- Agentic AI using **Google ADK + Gemini**
- Supervised ML classification
- Enterprise email/security domain knowledge
- Threat intelligence enrichment
- Explainable AI and evidence attribution
- Deterministic policy guardrails
- Human-in-the-loop analyst workflows
- Security-focused evaluation and error analysis
- Continuous learning from analyst feedback
- Production-ready service boundaries and deployment architecture

## 2. Core Design Principle

The platform deliberately avoids making Gemini the sole security decision-maker.

It combines three layers of intelligence:

### Layer 1 — Deterministic Security Analysis

Examples:

- Sender/header analysis
- SPF/DKIM/DMARC signals
- URL/domain indicators
- Attachment metadata
- Lexical and structural features
- Security policies and hard rules

### Layer 2 — Machine Learning Classification

A supervised model produces probabilities and classifications from message content and engineered features.

### Layer 3 — Agentic Threat Reasoning

Google ADK/Gemini agents consume evidence, invoke tools, reason over uncertainty, determine risk and triage recommendations, and generate analyst-readable explanations.

A key architectural principle is:

> **LLMs interpret evidence; deterministic controls enforce security-critical boundaries.**

---

## 3. High-Level Architecture

```text
                         ┌───────────────────────────┐
                         │     Email / Message       │
                         │      Ingestion API        │
                         └─────────────┬─────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────┐
                    │     PREPROCESSING PIPELINE      │
                    │ MIME Parsing                    │
                    │ Header Extraction               │
                    │ URL Extraction                  │
                    │ Attachment Metadata             │
                    │ Text Normalization              │
                    │ Feature Engineering             │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
              ┌───────────────────────────────────────────┐
              │        PARALLEL SIGNAL ANALYSIS           │
              │                                           │
              │ ML Spam/Threat Classifier                 │
              │ Threat Intelligence Analyzer              │
              │ URL / Domain Analyzer                     │
              │ Header / Authentication Analyzer          │
              └───────────────────┬───────────────────────┘
                                  │
                                  ▼
              ┌─────────────────────────────────────────┐
              │          GOOGLE ADK PIPELINE            │
              │                                         │
              │  1. Message Intelligence Agent          │
              │              ↓                          │
              │  2. Threat Evidence Agent               │
              │              ↓                          │
              │  3. Risk Scoring Agent                  │
              │              ↓                          │
              │  4. Threat Triage Agent                 │
              │              ↓                          │
              │  5. Explainability Agent                │
              │              ↓                          │
              │  6. Security Policy / Audit Agent       │
              └─────────────────┬───────────────────────┘
                                │
                                ▼
                       ┌────────────────┐
                       │ TRIAGE ENGINE  │
                       └───────┬────────┘
                               │
              ┌────────────────┼──────────────────┐
              ▼                ▼                  ▼
            ALLOW           REVIEW            QUARANTINE
                                                  │
                                                  ▼
                                             ESCALATE
                                                  │
                                                  ▼
                                      ┌──────────────────┐
                                      │ Security Analyst │
                                      │      HITL        │
                                      └────────┬─────────┘
                                               │
                                               ▼
                                        Analyst Feedback
                                               │
                                               ▼
                                  Evaluation / Retraining Loop
```

---

## 4. Classification Taxonomy

The project uses richer enterprise categories rather than binary spam classification.

```text
Message Classification
│
├── BENIGN
│    ├── PERSONAL
│    ├── BUSINESS
│    └── MARKETING
│
├── SPAM
│    ├── BULK_SPAM
│    ├── SCAM
│    └── SUSPICIOUS_PROMOTION
│
└── THREAT
     ├── PHISHING
     ├── CREDENTIAL_THEFT
     ├── BEC
     ├── MALWARE_DELIVERY
     ├── MALICIOUS_URL
     └── SOCIAL_ENGINEERING
```

Classification and operational triage are intentionally separated.

Example:

```text
Classification: PHISHING
Confidence:     0.94
Risk Score:     87/100
Triage:         QUARANTINE
Escalation:     SOC REVIEW
```

---

## 5. Triage Outcomes

The first version uses four operational outcomes:

```text
ALLOW
REVIEW
QUARANTINE
ESCALATE
```

An initial score-to-action mapping may be:

```text
0–29    → ALLOW
30–54   → REVIEW
55–79   → QUARANTINE
80–100  → ESCALATE
```

These thresholds will be validated experimentally rather than treated as fixed truth.

Risk will combine multiple signals rather than simply copying ML probability.

Potential inputs include:

- ML classification confidence
- Sender reputation
- Domain reputation
- URL risk
- SPF/DKIM/DMARC failures
- Social-engineering indicators
- Attachment risk
- Similar threat campaign evidence
- Historical sender behavior
- Agent-generated evidence interpretation

---

## 6. Agent Architecture

### 6.1 Message Intelligence Agent

Purpose: convert raw email/message content into structured security evidence.

Conceptually equivalent to the Symptom Parser in Sahayak Health AI.

Example output:

```json
{
  "sender": "support@paypa1-security.com",
  "display_name": "PayPal Security",
  "subject": "Urgent: Account suspended",
  "urls": ["https://paypa1-security.com/login"],
  "attachments": [],
  "urgency_language": true,
  "credential_request": true,
  "financial_language": false
}
```

### 6.2 Threat Evidence Agent

Purpose: enrich the message with external and historical security evidence.

Planned tools include:

```text
lookup_domain_reputation()
lookup_url_reputation()
lookup_sender_history()
lookup_known_campaign()
search_similar_threats()
check_email_authentication()
inspect_attachment_metadata()
```

### 6.3 Risk Scoring Agent

Purpose: combine security evidence into a normalized risk score with primary indicators.

Example:

```json
{
  "risk_score": 91,
  "risk_level": "CRITICAL",
  "primary_indicators": [
    "credential solicitation",
    "look-alike domain",
    "SPF failure",
    "malicious login URL"
  ]
}
```

### 6.4 Threat Triage Agent

Purpose: recommend operational response using ML output, deterministic controls, threat evidence, and risk score.

Example:

```json
{
  "classification": "CREDENTIAL_PHISHING",
  "triage": "QUARANTINE",
  "confidence": 0.96,
  "requires_human_review": true
}
```

### 6.5 Explainability Agent

Purpose: produce an analyst-readable explanation grounded in evidence.

Example:

```text
WHY THIS MESSAGE WAS FLAGGED

1. Sender domain resembles the legitimate PayPal domain.
2. SPF and DMARC authentication failed.
3. Message contains strong urgency language.
4. User is asked to enter credentials.
5. Embedded URL points to an unrelated domain.
6. ML classifier assigns high phishing probability.
```

### 6.6 Security Policy / Audit Agent

Purpose: validate decisions against hard safety and security policies.

Examples:

```python
if action == "ALLOW" and risk_score >= 80:
    reject_decision()

if confidence < 0.65:
    force_human_review()

if malicious_attachment:
    triage = "QUARANTINE"

if suspected_bec:
    force_human_review()
```

---

## 7. Human-in-the-Loop

High-impact, uncertain, or policy-sensitive decisions can be escalated to a security analyst.

Example analyst view:

```text
Classification: BEC / CEO Fraud
Confidence:     72%
Risk:           78 / HIGH
Suggested:      QUARANTINE
Human Review:   REQUIRED
```

Potential analyst actions:

```text
CONFIRM THREAT
MARK BENIGN
CHANGE CATEGORY
RELEASE MESSAGE
BLOCK SENDER
```

Analyst feedback becomes training and evaluation data for future iterations.

```text
Analyst Feedback Store
        │
        ├── evaluation dataset
        ├── false-positive dataset
        ├── false-negative dataset
        └── retraining dataset
```

---

## 8. Machine Learning Strategy

Initial models to compare:

1. TF-IDF + Logistic Regression
2. TF-IDF + Linear SVM
3. Transformer-based text classifier

The ML subsystem should expose structured outputs such as:

```json
{
  "spam_probability": 0.93,
  "phishing_probability": 0.81,
  "predicted_class": "PHISHING"
}
```

A core experiment will compare:

```text
ML-only
vs.
Gemini-only
vs.
Hybrid ML + Agentic AI
```

This comparison should become one of the main technical narratives in the project.

---

## 9. Evaluation Framework

Security evaluation must go beyond overall accuracy.

Planned metrics:

- Precision
- Recall
- F1
- ROC-AUC / PR-AUC where appropriate
- Phishing recall
- Malware recall
- Critical-threat recall
- False-positive rate
- False-negative rate
- Under-triage rate
- Over-triage rate
- Human escalation rate
- Agent agreement/disagreement rate
- Latency
- LLM token usage / estimated cost

A core project principle is that **security errors have asymmetric cost**.

A benign newsletter quarantined is inconvenient.

A credential-phishing message allowed through may become a security incident.

Therefore, high-risk false negatives and under-triage deserve special measurement.

---

## 10. Production Reference Architecture

```text
                    EMAIL SOURCES
                         │
                         ▼
                 API / Message Queue
                         │
                         ▼
               Preprocessing Service
                         │
                  ┌──────┴──────┐
                  ▼             ▼
            ML Inference    Feature Store
                  │
                  └──────┬──────┘
                         ▼
                  ADK Orchestrator
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         Threat Intel  Security   RAG /
           Tools        Rules     History
              └──────────┼──────────┘
                         ▼
                   Decision Engine
                         │
                  ┌──────┼──────┐
                  ▼      ▼      ▼
                Allow Review Quarantine
                         │
                         ▼
                  Analyst Console
                         │
                         ▼
                   Feedback Store
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        Model Retraining        Evaluation
```

Potential implementation stack:

- Python 3.11+
- Google ADK
- Gemini
- scikit-learn
- Hugging Face Transformers
- FastAPI
- PostgreSQL / SQLite for initial version
- Redis where useful
- Streamlit or React for dashboard
- Docker
- Prometheus / Grafana in the scale-out architecture
- Kafka as an optional production-scale extension

The runnable GitHub project should stay lightweight; large-scale infrastructure should be documented as a reference architecture rather than added only for visual complexity.


## 11. Five-Layer Target Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     EXPERIENCE LAYER                        │
│ SOC Dashboard │ Investigation │ Explainability │ HITL       │
├─────────────────────────────────────────────────────────────┤
│                 AGENTIC DECISION LAYER                      │
│ Intelligence → Evidence → Risk → Triage → Explain → Audit  │
│                 Google ADK + Gemini                         │
├─────────────────────────────────────────────────────────────┤
│                  DETECTION / ML LAYER                       │
│ Spam ML │ Phishing ML │ URL │ Header │ Rules │ Anomalies   │
├─────────────────────────────────────────────────────────────┤
│                  KNOWLEDGE / TOOL LAYER                     │
│ Threat Intel │ Historical Cases │ Reputation │ RAG │ Policy │
├─────────────────────────────────────────────────────────────┤
│                   PLATFORM LAYER                            │
│ APIs │ Events │ Storage │ Evaluation │ Monitoring │ Models  │
└─────────────────────────────────────────────────────────────┘
```

This is the current **Architecture V1** baseline.

---

## 13. Planned Delivery Sequence

1. Architecture V2 — detailed component and execution design
2. Dataset selection and taxonomy
3. ML baseline
4. Google ADK agent implementation
5. Threat-intelligence and retrieval tools
6. Security policy and deterministic guardrails
7. Evaluation harness
8. FastAPI service
9. SOC analyst dashboard
10. Architecture diagrams
11. Dockerized GitHub-ready repository
12. README and technical documentation refinement

---

## 14. Repository Direction

A future repository may evolve toward:

```text
intelligent-threat-triage/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── evaluation.md
│   ├── threat-model.md
│   └── images/
├── notebooks/
│   ├── 01_data_analysis.ipynb
│   ├── 02_ml_baseline.ipynb
│   └── 03_agent_evaluation.ipynb
├── src/
│   ├── agents/
│   ├── api/
│   ├── classifiers/
│   ├── features/
│   ├── policies/
│   ├── tools/
│   ├── triage/
│   └── evaluation/
├── dashboard/
├── tests/
├── data/
├── docker/
├── requirements.txt
└── pyproject.toml
```

This structure is provisional and will be finalized when Architecture V2 is defined.

---

## Status

**Current phase:** Architecture V1 complete.

**Next phase:** detailed Architecture V2 covering exact agents, tools, state contracts, input/output schemas, ML/data strategy, execution flow, evaluation contracts, and component boundaries.
