# syntax=docker/dockerfile:1.6

# ---- builder ---------------------------------------------------------
# Installs Python dependencies into an isolated venv. We split this from
# the runtime image so the final image is small and free of build tools.
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/encoder
COPY deployments/encoder/requirements.txt /opt/encoder/requirements.txt
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r /opt/encoder/requirements.txt

# ---- runtime ---------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    MODEL_NAME="xlm-roberta-base" \
    MODEL_DIR="/models" \
    HOST="0.0.0.0" \
    PORT="8080" \
    WARMUP_ON_STARTUP="1"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 encoder

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY deployments/encoder/app /app
RUN chown -R encoder:encoder /app
USER encoder

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
