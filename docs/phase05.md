Yes. We’re now at the point where the project can move into Phase 5 — Google ADK / Gemini Agentic Review.

I checked the current Gemini guidance because this layer is version-sensitive. Google’s current docs distinguish structured outputs from function calling: structured outputs are for getting a final response in a strict schema, while function calling is for letting the model request actions/tools during reasoning. Google also recommends strong typing, clear function descriptions, validation, and keeping the active tool set reasonably small.

For our project, that maps very naturally to:

RoutingResult == AGENT_REVIEW
            │
            ▼
      AgentReviewInput
            │
     ┌──────┼────────┐
     ▼      ▼        ▼
 ML Evidence  Security Evidence  Risk Assessment
     │      │        │
     └──────┼────────┘
            ▼
      Google ADK / Gemini
            │
       tool calling
            │
     ┌──────┼────────────┐
     ▼      ▼            ▼
  URL Tool  Sender Tool  Threat Intel Tool
            │
            ▼
      Structured Output
            │
            ▼
      AgentReviewResult
            │
      ┌─────┴────────┐
      ▼              ▼
 Risk Update      Human Review
 
 
The important design decision is: Gemini should not receive only raw email text. It should receive the structured evidence contract we already built, plus sanitized message context. That preserves all the engineering discipline from Phases 1–4.

The recommend this new production structure:
 
src/threat_triage/
│
├── risk/
│   └── ...
│
└── agents/
    ├── __init__.py
    ├── models.py              ← START HERE
    ├── review_context.py
    ├── tools/
    │   ├── __init__.py
    │   ├── url_tool.py
    │   ├── sender_tool.py
    │   └── threat_intel_tool.py
    │
    ├── message_review_agent.py
    └── orchestrator.py

tests/
└── agents/
    ├── __init__.py
    ├── test_models.py
    ├── test_review_context.py
    ├── test_tools.py
    └── test_orchestrator.py
	

In models.py The 4 main contracts are 

AgentReviewInput
├── message_id
├── subject
├── body_preview
├── sender
├── ml_evidence
├── evidence_summary
├── risk_assessment
└── routing_result

AgentFinding
├── category
├── finding
├── severity
├── confidence
└── evidence_refs[]

AgentRecommendation
├── disposition
├── confidence
├── reasons[]
└── requires_human_review

AgentReviewResult
├── message_id
├── findings[]
├── recommendation
├── explanation
└── model_metadata



The flow looks like
RoutingResult == AGENT_REVIEW
             │
             ▼
       AgentReviewInput
             │
   ┌─────────┼──────────┐
   ▼         ▼          ▼
ML Evidence  Evidence   Risk Assessment
             Summary
   └─────────┼──────────┘
             ▼
        Future Agent
             │
             ▼
       AgentFinding[]
             │
             ▼
    AgentRecommendation
             │
             ▼
      AgentReviewResult

A few design decisions are intentional.
AgentDisposition is constrained to:
ALLOW
MONITOR
QUARANTINE
HUMAN_REVIEW

so Gemini will eventually return a machine-consumable result instead of arbitrary prose.

AgentFinding keeps each observation separate from the final recommendation. For example:

`
Finding 1
URL contains credential path
HIGH
confidence 0.91

Finding 2
Sender display name conflicts with domain
MEDIUM
confidence 0.8
`

Then AgentRecommendation can synthesize those findings into:

QUARANTINE
confidence = 0.93

We also preserve evidence_refs. Later a finding could say:
evidence_refs=[
    "security.url.credential_path_keyword",
    "security.sender.possible_display_name_mismatch",
    "risk.ml.threat_probability",
]

That gives us traceable explainability rather than unsupported LLM assertions.

One more important separation remains:
AgentReviewResult

Eventually:

Agent recommendation
       ↓
Policy validation
       ↓
Automated action / HITL

That keeps the LLM outside the final control boundary.

Risk / Routing Layer
        │
        ▼
AgentReviewInput
        │
        ▼
Google ADK / Gemini
        │
        ▼
AgentFinding[]
        │
        ▼
AgentRecommendation
        │
        ▼
AgentReviewResult


This is an important boundary in 
src/threat_triage/agents/review_context.py

Canonical Email / Message
          +
RiskEvidence
          +
RiskAssessment
          +
RoutingResult
          │
          ▼
    review_context.py
          │
          ├── validate identity
          ├── normalize text
          ├── bound subject
          ├── bound body
          ├── normalize sender
          └── preserve structured evidence
          │
          ▼
    AgentReviewInput
	

In this layer we are not doing something like
prompt = f"""
Analyze this email:

{entire_raw_email}
"""

instead:
Raw/untrusted message
        │
        ▼
review_context.py
        │
        ├── bounded subject
        ├── bounded body preview
        ├── bounded sender
        └── normalized text
        │
        ▼
AgentReviewInput

The future agent therefore receives a controlled contract.

Also notice that I deliberately described _normalize_and_bound_text() as context preparation, not semantic sanitization. Truncating strings or removing NULs does not protect an LLM from prompt injection. Later, the agent instructions must explicitly treat email content as untrusted evidence rather than instructions.

Another important guardrail

By default:

require_agent_review_route=True

So this works:

RoutingResult
    AGENT_REVIEW
         ↓
AgentReviewInput

but this does not accidentally invoke the agent path:

ALLOW
   ↓
AgentReviewInput     ✗


HUMAN_REVIEW
   ↓
AgentReviewInput     ✗

We can explicitly override that in controlled tests or future offline evaluation using: