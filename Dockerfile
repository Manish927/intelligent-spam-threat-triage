FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN groupadd --system appgroup \
    && useradd --system --gid appgroup --create-home appuser

COPY requirements.txt /app/requirements.txt
COPY requirements-service.txt /app/requirements-service.txt

RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install -r requirements-service.txt

COPY src /app/src
COPY artifacts/ml_baseline /app/artifacts/ml_baseline

RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 8080

CMD ["sh", "-c", "exec uvicorn threat_triage.api.app:app --host 0.0.0.0 --port ${PORT:-8080}"]