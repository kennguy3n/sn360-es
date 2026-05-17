# syntax=docker/dockerfile:1.6
#
# SN360-ES Tier 2 LLM — Ternary-Bonsai-8B (Q2_0 GGUF) served by the
# llama.cpp HTTP server.
#
# The server binary is built from kennguy3n's llama.cpp fork:
#   https://github.com/kennguy3n/llama.cpp
#
# The model weights themselves are NOT baked into this image — they are
# pulled at pod start time by an init container running
# deployments/llm/download-model.sh into a shared volume. This keeps the
# image small (~150MB) and lets us iterate on the runtime without
# repeatedly shipping a 3GB tensor blob through the registry.

# ---- builder ---------------------------------------------------------
# Compiles llama-server from kennguy3n/llama.cpp. We pin to a specific
# commit at deploy time via the LLAMA_CPP_REF build arg; the default is
# `main` for development convenience.
FROM ubuntu:22.04 AS builder

ARG LLAMA_CPP_REPO=https://github.com/kennguy3n/llama.cpp
ARG LLAMA_CPP_REF=main

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        git \
        libcurl4-openssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 "$LLAMA_CPP_REPO" /src/llama.cpp \
    && cd /src/llama.cpp \
    && git fetch --depth 1 origin "$LLAMA_CPP_REF" \
    && git checkout FETCH_HEAD

WORKDIR /src/llama.cpp
# LLAMA_CURL=ON lets llama-server fetch HuggingFace artefacts directly
# when LLAMA_ARG_MODEL_URL is set. We don't rely on that in production
# (we use the init container), but it is useful for local docker-run
# smoke tests.
RUN cmake -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLAMA_CURL=ON \
        -DGGML_NATIVE=OFF \
        -DBUILD_SHARED_LIBS=OFF \
    && cmake --build build --target llama-server -j"$(nproc)"

# ---- runtime ---------------------------------------------------------
# Minimal runtime image. No build toolchain, no model weights — those
# come from the init container into /models.
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    MODEL_DIR=/models \
    MODEL_FILE=Ternary-Bonsai-8B-Q2_0.gguf \
    HOST=0.0.0.0 \
    PORT=9000 \
    CTX_SIZE=4096 \
    THREADS=4

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libcurl4 \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10002 llm \
    && mkdir -p /models \
    && chown -R llm:llm /models

COPY --from=builder /src/llama.cpp/build/bin/llama-server /usr/local/bin/llama-server

WORKDIR /models
USER llm

EXPOSE 9000

# llama-server exposes /health (200 once the model is loaded) and the
# OpenAI-compatible /v1/chat/completions endpoint that the SN360-ES
# `AI` client consumes.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/llama-server"]
CMD ["--model", "/models/Ternary-Bonsai-8B-Q2_0.gguf", \
     "--ctx-size", "4096", \
     "--threads", "4", \
     "--host", "0.0.0.0", \
     "--port", "9000"]
