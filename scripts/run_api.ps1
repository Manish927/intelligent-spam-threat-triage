$env:PYTHONPATH = "$PSScriptRoot\..\src"
python.exe -m uvicorn threat_triage.api.app:app --host 0.0.0.0 --port 8000 --reload
