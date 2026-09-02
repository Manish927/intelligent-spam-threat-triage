C1 FASTAPI + DOCKER + STREAMLIT DASHBOARD
=========================================

FIRST LOCAL RUN
---------------
1. Merge ZIP into repo root.
2. Install:
   python.exe -m pip install -r requirements-service.txt

3. Run all tests:
   python.exe -m pytest -q

4. Start API:
   $env:PYTHONPATH="$PWD\src"
   python.exe -m uvicorn threat_triage.api.app:app --reload

5. Open Swagger:
   http://localhost:8000/docs

6. Start dashboard in another PowerShell:
   python.exe -m streamlit run .\dashboard\app.py

7. Open:
   http://localhost:8501

DOCKER
------
docker compose build
docker compose up

IMPORTANT
---------
Do not commit a real .env file.
Do not put GOOGLE_API_KEY, GEMINI_API_KEY, or VIRUSTOTAL_API_KEY into Dockerfile.

For first smoke test you may disable live Gemini:
  $env:THREAT_TRIAGE_ENABLE_AGENT_REVIEW="false"

Then enable it after deterministic/API tests are green.
