# C1 — FastAPI + Docker + Dashboard

## Objective

Expose the existing deterministic-first Hybrid threat-triage pipeline through a production-style API and a portfolio/demo dashboard.

## Runtime flow

```text
Client / Streamlit
       |
       v
POST /api/v1/triage
       |
       v
Classical ML
       |
       v
Deterministic Security Features
       |
       v
Risk Scoring
       |
       v
Policy Routing
   +---+-------------------+
   |       |       |       |
 ALLOW  MONITOR  HUMAN   AGENT_REVIEW
                         |
                         v
                    Google ADK/Gemini
                         |
                         v
                 Threat-intel tools
                         |
                         v
                Explainable response
```

## Local API

Install the repository's normal requirements, then:

```powershell
python.exe -m pip install -r requirements-service.txt
$env:PYTHONPATH="$PWD\src"
python.exe -m uvicorn threat_triage.api.app:app --reload
```

Swagger:
- http://localhost:8000/docs

Health:
- http://localhost:8000/health

## Dashboard

```powershell
python.exe -m streamlit run .\dashboard\app.py
```

Open:
- http://localhost:8501

The dashboard calls FastAPI. It does not import production internals.

## Docker

```powershell
docker compose build
docker compose up
```

API:
- http://localhost:8000/docs

Dashboard:
- http://localhost:8501

## Secrets

Never copy secrets into Docker images or Git.

Use a local `.env` file (ignored by Git) or the deployment platform's secret manager.

Required only for live agent review:
- `GOOGLE_API_KEY` or `GEMINI_API_KEY`

Optional:
- `VIRUSTOTAL_API_KEY`

## Offline deterministic mode

For local development without Gemini:

```powershell
$env:THREAT_TRIAGE_ENABLE_AGENT_REVIEW="false"
```

The API still runs ML, deterministic security, risk scoring, and routing. `AGENT_REVIEW` routes are reported without making a provider call.

## Important

The service reuses the existing production modules. Notebook logic is not duplicated.

The current model input formatter is centralized in
`ProductionTriageService._combined_text()`. If the canonical
`combined_text` construction changes, synchronize that helper with
`data_loader.py` before release.
