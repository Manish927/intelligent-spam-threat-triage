# 02_ml_baseline.ipynb --- Execution Review & Baseline Analysis

**Project:** Intelligent Spam Classification & Threat Triage Platform\
**Notebook:** `02_ml_baseline.ipynb`\
**Purpose:** Preserve the executed classical-ML baseline results,
security interpretation, model limitations, and architectural
implications before subsequent notebook cleanup/refinement.

------------------------------------------------------------------------

## 1. Executive Summary

The executed notebook successfully establishes a strong and reproducible
classical machine-learning benchmark using:

**Canonical Email → TF-IDF → Logistic Regression → BENIGN / THREAT**

The model demonstrates excellent aggregate classification performance.
At the selected operating threshold of **0.7364**, the locked test set
achieved:

-   **Accuracy:** 97.35%
-   **THREAT Precision:** 99.35%
-   **THREAT Recall:** 94.93%
-   **THREAT F1:** 97.09%
-   **ROC-AUC:** 99.84%
-   **PR-AUC:** 99.81%
-   **False Positive Rate:** 0.54%
-   **False Negative Rate:** 5.07%

However, the detailed analysis also exposes important
production-security limitations. In particular:

1.  Performance differs materially across source datasets.
2.  The **Ling** corpus has a **21.51% false-negative rate** at the
    selected threshold.
3.  TF-IDF coefficients reveal evidence of **dataset/source shortcut
    learning**.
4.  Some missed threats receive extremely low threat probabilities,
    demonstrating that ML confidence alone cannot safely define the
    future Agentic AI routing strategy.
5.  The selected threshold substantially reduces false positives, but at
    the cost of additional missed threats.

Therefore, the classical classifier is strong enough to **lock as the ML
baseline**, but it should become an evidence-producing component of the
larger threat-triage platform rather than the final security authority.

------------------------------------------------------------------------

# 2. Baseline Pipeline

The executed pipeline is:

``` text
Canonical Dataset
      ↓
Train / Validation / Locked Test
      ↓
combined_text
      ↓
TF-IDF
      ↓
75,000-dimensional sparse feature space
      ↓
Logistic Regression
      ↓
P(THREAT)
      ↓
Decision Threshold
      ↓
BENIGN / THREAT
```

The fitted TF-IDF vocabulary contained **75,000 features**, and the
Logistic Regression classifier learned one coefficient vector for the
binary classification problem.

------------------------------------------------------------------------

# 3. Dataset Split

The canonical dataset was divided into:

-   **Training:** 129,930 records
-   **Validation:** 32,483 records
-   **Locked Test:** 40,604 records

The label distribution remained approximately:

-   **BENIGN:** 53.54%
-   **THREAT:** 46.46%

The supplied test set remained locked during model development and
threshold selection.

This is important because:

-   TF-IDF vocabulary was learned only from training data.
-   Logistic Regression parameters were fitted only from training data.
-   Threshold selection was performed on validation data.
-   The locked test set was evaluated only after threshold selection.

------------------------------------------------------------------------

# 4. Default Threshold 0.50 --- Validation Results

At the standard classification threshold:

**P(THREAT) ≥ 0.50 → THREAT**

the validation results were:

  Metric               Result
  ------------------ --------
  Accuracy             98.26%
  THREAT Precision     97.89%
  THREAT Recall        98.38%
  THREAT F1            98.13%
  ROC-AUC              99.82%
  PR-AUC               99.79%

The THREAT classification report showed:

-   Precision: **0.9789**
-   Recall: **0.9838**
-   F1: **0.9813**
-   Support: **15,093**

The BENIGN class showed:

-   Precision: **0.9859**
-   Recall: **0.9816**
-   F1: **0.9837**
-   Support: **17,390**

## Validation Confusion Matrix at 0.50

``` text
                         Predicted
                    BENIGN       THREAT
Actual BENIGN       17,070          320
Actual THREAT          245       14,848
```

Therefore:

-   False Positives = **320**
-   False Negatives = **245**

This default threshold provides extremely high THREAT recall.

------------------------------------------------------------------------

# 5. Decision Threshold Selection

The notebook deliberately did not assume that `0.50` was the correct
enterprise operating point.

The validation policy was:

> Find thresholds achieving at least 95% THREAT recall, then select the
> eligible threshold with the highest precision.

The resulting operating threshold was:

**Selected Threshold = 0.7364**

**Target Validation Recall = 95%**

------------------------------------------------------------------------

# 6. Validation Results at Selected Threshold 0.7364

At the selected threshold:

  Metric        Result
  ----------- --------
  Accuracy      97.35%
  Precision     99.25%
  Recall        95.02%
  F1            97.09%
  ROC-AUC       99.82%
  PR-AUC        99.79%

Security-specific validation metrics:

  Metric                  Result
  --------------------- --------
  True Negatives          17,281
  False Positives            109
  False Negatives            752
  True Positives          14,341
  False Positive Rate      0.63%
  False Negative Rate      4.98%
  Specificity             99.37%

------------------------------------------------------------------------

# 7. Threshold Trade-off

Changing the threshold from **0.50 → 0.7364** produced an important
security trade-off.

## Threshold 0.50

-   False Positives: **320**
-   False Negatives: **245**

## Threshold 0.7364

-   False Positives: **109**
-   False Negatives: **752**

Therefore, raising the threshold produced approximately:

-   **211 fewer false positives**
-   **507 additional false negatives**

This is operationally significant.

A high threshold is attractive when minimizing legitimate-email
quarantine and analyst workload, but missed threats have a potentially
much higher security cost.

Therefore, **0.7364 should not automatically be interpreted as the final
production blocking threshold**. It is the threshold selected by the
notebook's explicit 95%-recall validation policy.

Future production policy should account for:

-   cost of missed threats,
-   cost of false quarantine,
-   analyst capacity,
-   sender/domain reputation,
-   URL intelligence,
-   authentication evidence,
-   Agentic AI reasoning,
-   human review policy.

------------------------------------------------------------------------

# 8. Locked Test Evaluation

The selected threshold was then applied to the previously untouched test
set.

## Locked Test Metrics

  Metric            Result
  ----------- ------------
  Accuracy      **97.35%**
  Precision     **99.35%**
  Recall        **94.93%**
  F1            **97.09%**
  ROC-AUC       **99.84%**
  PR-AUC        **99.81%**

Security metrics:

  Metric                      Result
  --------------------- ------------
  True Negatives              21,620
  False Positives                118
  False Negatives                957
  True Positives              17,909
  False Positive Rate      **0.54%**
  False Negative Rate      **5.07%**
  Specificity             **99.46%**

## Locked Test Confusion Matrix

``` text
                         Predicted
                    BENIGN       THREAT

Actual BENIGN       21,620          118
Actual THREAT          957       17,909
```

## Test Classification Report

### BENIGN

-   Precision: 95.76%
-   Recall: 99.46%
-   F1: 97.57%
-   Support: 21,738

### THREAT

-   Precision: 99.35%
-   Recall: 94.93%
-   F1: 97.09%
-   Support: 18,866

------------------------------------------------------------------------

# 9. Validation vs Locked Test Consistency

The validation and locked-test metrics are highly consistent:

  Metric        Validation   Locked Test
  ----------- ------------ -------------
  Accuracy          97.35%        97.35%
  Precision         99.25%        99.35%
  Recall            95.02%        94.93%
  F1                97.09%        97.09%
  ROC-AUC           99.82%        99.84%
  PR-AUC            99.79%        99.81%

This consistency is a positive sign that the selected threshold and
fitted model generalize from validation to the supplied locked test set.

------------------------------------------------------------------------

# 10. Per-Source Locked-Test Performance

Aggregate performance hides substantial source-level variation.

  Source       Accuracy   Precision       Recall       F1          FNR
  ---------- ---------- ----------- ------------ -------- ------------
  CEAS-08        99.31%      99.57%   **99.20%**   99.38%    **0.80%**
  Enron          97.43%      99.73%       94.77%   97.19%        5.23%
  TREC-07        96.52%      99.75%       93.83%   96.70%        6.17%
  TREC-05        96.77%      98.67%       93.53%   96.03%        6.47%
  TREC-06        97.72%      98.76%       91.54%   95.01%        8.46%
  Assassin       96.15%      96.78%       90.19%   93.37%        9.81%
  Ling           96.30%      98.65%   **78.49%**   87.43%   **21.51%**

Additional source-level AUC metrics remained high, including:

-   CEAS-08 ROC-AUC 0.9996 / PR-AUC 0.9997
-   Enron ROC-AUC 0.9989 / PR-AUC 0.9988
-   TREC-07 ROC-AUC 0.9992 / PR-AUC 0.9993
-   TREC-05 ROC-AUC 0.9968 / PR-AUC 0.9955
-   TREC-06 ROC-AUC 0.9971 / PR-AUC 0.9933
-   Assassin ROC-AUC 0.9954 / PR-AUC 0.9890
-   Ling ROC-AUC 0.9929 / PR-AUC 0.9736

## Critical Finding: Ling

The most important source-level result is:

**Ling THREAT Recall = 78.49%**

**Ling False Negative Rate = 21.51%**

This demonstrates why a security platform should not report only global
accuracy or aggregate F1.

A portfolio statement such as:

> "The classifier achieves 97% accuracy."

would hide an important production weakness.

A stronger engineering statement is:

> "The classical baseline achieved 97.35% locked-test accuracy and
> 99.35% THREAT precision, while source-level analysis exposed
> materially different generalization behavior, including a 21.51%
> false-negative rate on the weakest source corpus."

This better represents production-oriented security engineering.

------------------------------------------------------------------------

# 11. False Positive Analysis

At the default 0.50 validation threshold, there were:

**320 false positives**

Several highly confident false positives had promotional or spam-like
lexical patterns despite being labeled BENIGN.

Examples included subjects such as:

-   `"Tarzan of the Apes" for Monday April 23, 2007`
-   `See where your Competion is advertising`
-   `[Reform] Photoshop, Windows, Office`
-   `You received a PassionUp Greeting Page!`
-   `Weekend Sale - Up to 50% off!`
-   `Translation Soft 6 by Systran...`

Some received THREAT probabilities above **0.90**.

This illustrates a core limitation of lexical classification:

> A message can strongly resemble spam lexically while still carrying a
> BENIGN ground-truth label.

This is one reason later system decisions should combine multiple
evidence sources.

------------------------------------------------------------------------

# 12. False Negative Analysis

At the default validation threshold there were:

**245 false negatives**

Some of the most confidently missed threats had extremely low predicted
threat probabilities.

Examples included:

  Subject                                         Approx. P(THREAT)
  --------------------------------------------- -------------------
  ISDA's Annual Primary Contact Update (2001)                0.0064
  Power Plant Outages Information!                           0.0091
  Secondary CD/DVD Image Downloading                         0.0191
  PowerMarketers.com Daily Power Report                      0.0273
  Chronic illness / NY Times message                         0.0278
  Amnesty International event message                        0.0299
  Conference announcement                                    0.0426
  Microsoft Windows News / Free Shop Alert                   \~0.05

These examples are particularly important.

They demonstrate that some messages labeled THREAT can look like:

-   legitimate organizational communication,
-   industry information,
-   conference announcements,
-   newsletters,
-   software/news alerts.

The classifier can therefore be **confidently wrong**.

This means:

**Low ML threat probability must not automatically be interpreted as low
enterprise risk.**

That observation directly influences the future Agentic AI routing
architecture.

------------------------------------------------------------------------

# 13. Global Explainability --- THREAT Features

The strongest positive Logistic Regression coefficients included:

-   `your`
-   `our`
-   `http`
-   `life`
-   `he`
-   `com`
-   `her`
-   `men`
-   `2005`
-   `money`
-   `quality`
-   `enron com`
-   `meds`
-   `pills`
-   `viagra`
-   `info`
-   `2004`
-   `for you`
-   `his`
-   `site`
-   `hk`
-   `offer`
-   `yourself`
-   `here`
-   `cialis`
-   `love`
-   `remove`
-   `product`
-   `huge`
-   `weight`

Some features are intuitively related to spam/threat content:

-   `http`
-   `money`
-   `meds`
-   `pills`
-   `viagra`
-   `offer`
-   `cialis`
-   `product`
-   `weight`

However, others are suspicious from a modeling perspective:

-   `2005`
-   `2004`
-   `enron com`
-   pronouns such as `he`, `her`, `his`
-   `hk`

These may reflect corpus-specific characteristics rather than general
threat semantics.

------------------------------------------------------------------------

# 14. Global Explainability --- BENIGN Features

The strongest BENIGN-associated features included:

-   `thanks`
-   `wrote`
-   `the`
-   `enron`
-   `713`
-   `org`
-   `to`
-   `2001`
-   `edu`
-   `attached`
-   `perl`
-   `for`
-   `please`
-   `2007`
-   `on`
-   `list`
-   `gas`
-   `date`
-   `vince`
-   `re`
-   `2002`
-   `fax`
-   `dmdx`
-   `university`
-   `opensuse`
-   `meeting`
-   `anyone`
-   `louise`
-   `at http`
-   `doc`

Again, several features appear to encode dataset identity, historical
period, organization, or mailing-list context rather than universally
benign semantics.

Examples:

-   `enron`
-   `713`
-   `2001`
-   `2002`
-   `2007`
-   `perl`
-   `vince`
-   `opensuse`

------------------------------------------------------------------------

# 15. Shortcut-Learning Risk

The coefficient analysis provides evidence that the model is learning
two things simultaneously:

1.  genuine lexical signals associated with spam/threat content;
2.  characteristics associated with the source datasets themselves.

This is a form of **shortcut learning / source bias**.

The model may partly learn:

``` text
"This looks like an Enron-era message"
```

instead of exclusively learning:

``` text
"This message contains security-relevant malicious intent."
```

This helps explain why excellent aggregate ROC-AUC does not eliminate
the need for source-level evaluation and future multi-signal reasoning.

------------------------------------------------------------------------

# 16. Why ROC-AUC Alone Is Not Enough

The locked-test ROC-AUC is:

**99.84%**

This is excellent.

However:

-   Ling FNR = 21.51%
-   Assassin FNR = 9.81%
-   TREC-06 FNR = 8.46%
-   some false negatives receive P(THREAT) below 0.01

Therefore:

> A high global ROC-AUC does not imply uniformly safe operational
> performance.

Production security evaluation must include:

-   precision,
-   recall,
-   FPR,
-   FNR,
-   per-source metrics,
-   threshold behavior,
-   error analysis,
-   model explainability,
-   drift/generalization testing.

------------------------------------------------------------------------

# 17. Architectural Consequence

The results support a hybrid architecture rather than replacing
classical ML with an LLM.

``` text
                         Incoming Email
                               │
                               ▼
                      Canonical Data Layer
                               │
                               ▼
                   TF-IDF + Logistic Regression
                               │
                         Threat Probability
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
       Strong BENIGN       Gray Zone       Strong THREAT
             │                 │                 │
             │                 ▼                 │
             │          Agentic Analysis         │
             │                 │                 │
             │       ┌─────────┼─────────┐       │
             │       ▼         ▼         ▼       │
             │     URL      Sender     Gemini    │
             │   Analysis   Signals    Reasoning │
             │       └─────────┼─────────┘       │
             │                 ▼                 │
             │           Risk Scoring            │
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                         Triage Decision
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
               Automated              Human
                Action                Review
```

------------------------------------------------------------------------

# 18. Important Refinement: "Gray Zone" Must Be Multi-Signal

A simple architecture might route only probabilities near `0.50` to
Agentic AI.

The false-negative analysis shows that this is insufficient.

Some missed threats had probabilities such as:

-   0.0064
-   0.0091
-   0.0191
-   0.0273

Therefore, a future message should be routed to deeper analysis not only
because ML is uncertain, but also because deterministic security
evidence conflicts with the ML prediction.

Future routing should consider signals such as:

``` text
ML probability
      +
URL/domain evidence
      +
sender/authentication evidence
      +
message structure
      +
threat intelligence
      +
distribution/source drift
      ↓
Agent routing policy
```

Possible routing logic:

``` text
IF ML uncertainty is high
    → Agentic analysis

OR suspicious URL/domain evidence exists
    → Agentic analysis

OR sender/authentication evidence conflicts
    → Agentic analysis

OR message is out-of-distribution
    → Agentic analysis

OR risk policy requires human review
    → Agentic analysis / HITL
```

This is a stronger production design than simply:

``` text
0.4 < P(THREAT) < 0.6 → LLM
```

------------------------------------------------------------------------

# 19. Role of the Classical ML Model

The Logistic Regression model should remain part of the final
architecture because it provides:

-   fast inference,
-   deterministic behavior,
-   low computational cost,
-   reproducibility,
-   useful threat probability,
-   interpretable global coefficients,
-   a benchmark against which more expensive reasoning can be measured.

Its role should be:

> **Fast statistical evidence provider**

rather than:

> **Final security decision authority**

------------------------------------------------------------------------

# 20. Future Agentic AI Comparison

The project should eventually compare:

  Approach                 Purpose
  ------------------------ -------------------------------------
  ML-only                  Fast deterministic benchmark
  Gemini-only              Semantic reasoning benchmark
  Hybrid ML + Agentic AI   Multi-signal threat decisioning
  Hybrid + HITL            Enterprise operational architecture

This allows the portfolio project to quantify whether Agentic AI
provides measurable value over a strong classical baseline.

------------------------------------------------------------------------

# 21. Recommended Portfolio Narrative

A technically credible summary is:

> Built a reproducible TF-IDF + Logistic Regression email-threat
> baseline achieving 97.35% locked-test accuracy, 99.35% THREAT
> precision, and 94.93% THREAT recall. Extended evaluation beyond
> aggregate metrics to include FPR/FNR, source-level generalization,
> error analysis, model explainability, and threshold optimization.
> Source-level analysis exposed up to 21.51% false-negative rate on the
> weakest corpus and coefficient analysis identified source-specific
> shortcut learning, motivating a hybrid multi-signal Agentic AI
> architecture with deterministic security analysis and
> human-in-the-loop escalation.

This narrative is stronger than presenting only the headline accuracy.

------------------------------------------------------------------------

# 22. Current Baseline Status

The classical ML baseline can now be considered:

**IMPLEMENTED → EXECUTED → EVALUATED → READY TO LOCK**

Before finalizing the notebook, two cleanup activities remain:

1.  Remove the Pandas `DataFrameGroupBy.apply` deprecation warnings.
2.  Replace the notebook's placeholder Findings section with the actual
    executed metrics and conclusions preserved in this document.

After those changes, the ML baseline can be committed as a completed
project milestone.

------------------------------------------------------------------------

# 23. Next Engineering Phase

After notebook cleanup, the recommended sequence is:

``` text
Classical ML Baseline
        ✓
        ↓
Security Feature Engineering
        ↓
URL / Domain Analysis
        ↓
Sender / Header / Authentication Signals
        ↓
Threat Intelligence
        ↓
Google ADK Orchestration
        ↓
Gemini Semantic Analysis
        ↓
Evidence Aggregation
        ↓
Risk Scoring
        ↓
Triage Decision
        ↓
Explainability
        ↓
Human-in-the-Loop
```

The next major implementation phase should therefore be **Security
Feature Engineering**, giving future Google ADK/Gemini agents
deterministic security tools and evidence rather than asking an LLM to
reason from raw email text alone.

------------------------------------------------------------------------

## Preserved Key Numbers

``` text
MODEL
TF-IDF + Logistic Regression
Vocabulary = 75,000

DATA
Train      = 129,930
Validation = 32,483
Test       = 40,604

DEFAULT VALIDATION @ 0.50
Accuracy  = 0.9826
Precision = 0.9789
Recall    = 0.9838
F1        = 0.9813
ROC-AUC   = 0.9982
PR-AUC    = 0.9979
FP        = 320
FN        = 245

SELECTED THRESHOLD
0.7364
Target validation recall = 0.95

VALIDATION @ 0.7364
Accuracy  = 0.9735
Precision = 0.9925
Recall    = 0.9502
F1        = 0.9709
ROC-AUC   = 0.9982
PR-AUC    = 0.9979
FP        = 109
FN        = 752
FPR       = 0.006268
FNR       = 0.049824

LOCKED TEST @ 0.7364
Accuracy  = 0.9735
Precision = 0.9935
Recall    = 0.9493
F1        = 0.9709
ROC-AUC   = 0.9984
PR-AUC    = 0.9981
TN        = 21,620
FP        = 118
FN        = 957
TP        = 17,909
FPR       = 0.005428
FNR       = 0.050726
Specificity = 0.994572

WEAKEST SOURCE
Ling
Recall = 0.7849
FNR    = 0.2151
```
