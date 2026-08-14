Phase 3 — Security Feature Engineering
├── deterministic URL evidence          ✓
├── sender evidence                     ✓
├── language/social-engineering signals ✓
├── integrated SecurityFeatures bundle  ✓
├── unit tests                          ✓
├── locked-test feature analysis        ✓
├── ML false-negative analysis          ✓
├── broad/strong escalation analysis    ✓
├── source-level recoverability         ✓
├── false-positive evidence analysis    ✓
├── confidence-band evidence analysis   ✓
└── hybrid architecture findings        ✓




The design boudry is:

SecurityFeatures
      +
MLEvidence
      ↓
RiskEvidence
      ↓
RiskScorer          ← later
      ↓
RiskAssessment
      ↓
RoutingPolicy       ← later
      ↓
RoutingResult


The V! scoring model is intentionally simple

ML threat probability
      │
      × 60
      │
      ▼
  ML contribution
      +
Strong deterministic signals
      │
      × 8 each
      +
Weak deterministic signals
      │
      × 2 each
      │
      ▼
 Security contribution
   capped at 40
      │
      ▼
 Risk Score 0–100
 
 e:g:
 
 P(THREAT) = 0.80

ML contribution
= 0.80 × 60
= 48

2 strong signals
= 16

1 weak signal
= 2

Total risk
= 66

Severity
= HIGH


The decision precedence is kept in this manner

CRITICAL
    → HUMAN_REVIEW

HIGH + multiple strong signals
    → HUMAN_REVIEW

requires_deep_analysis
    → AGENT_REVIEW

otherwise:
    score ≤ 20
        → ALLOW

    score ≤ 40
        → MONITOR

    score ≤ 75
        → AGENT_REVIEW

    score > 75
        → HUMAN_REVIEW
		
		
		
The flow is:

MLEvidence ─────────────┐
                       │
SecurityFeatures ───────┤
                       ▼
                build_risk_evidence()
                       │
                       ▼
                   RiskEvidence
                       │
                       ▼
                    score_risk()
                       │
                       ▼
                  RiskAssessment
                       │
                       ▼
                  route_message()
                       │
                       ▼
                  RoutingResult
				  
				  
The current architecture is :

01 Dataset Exploration
        ↓
02 ML Baseline
        ↓
03 Security Feature Engineering
        ↓
Production Security Analyzers
        ↓
Evidence Builder
        ↓
Risk Scorer
        ↓
Routing Policy
        ↓
┌────────┬─────────┬──────────────┬──────────────┐
│ ALLOW  │ MONITOR │ AGENT_REVIEW │ HUMAN_REVIEW │
└────────┴─────────┴──────────────┴──────────────┘
                         │
                         ▼
                 Google ADK / Gemini
                    [NEXT PHASE]