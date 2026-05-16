"""SN360-ES Tier 1 encoder inference service.

This is a thin FastAPI wrapper around an XLM-RoBERTa-based risk scorer.
The actual model weights are loaded from disk at startup; this file
defines the HTTP surface (``/health``, ``/predict``, ``/predict/batch``,
``/metrics``) and the inference pipeline (tokenise → ONNX runtime →
sigmoid → 0..100 score).

Design notes:
* The model is loaded ONCE on startup and shared across requests via
  module-level globals. ONNX Runtime is fully thread-safe so the GIL
  is the only contention point and uvicorn's worker model spreads
  parallel requests across processes anyway.
* A small in-process LRU cache keys on the tuple
  ``(subject, body, sender_domain)`` so repeated polls of the same
  message do not re-tokenise.
* Language detection runs CPU-side via langdetect; the encoder is
  multilingual so the hint is advisory only.
* When ``MODEL_DIR`` does not contain a model.onnx, the service starts
  in DEGRADED mode: ``/health`` returns 200 with ``{"degraded": true}``
  and ``/predict`` returns a uniform 50/100 with ``confidence: 0`` so
  callers can detect the condition and fall back to Tier 0 + Rspamd
  per the SN360-ES degradation table.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.responses import Response

logger = logging.getLogger("encoder")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

MODEL_DIR = os.environ.get("MODEL_DIR", "/models")
MODEL_NAME = os.environ.get("MODEL_NAME", "xlm-roberta-base")
MAX_LENGTH = int(os.environ.get("MAX_LENGTH", "256"))
WARMUP = os.environ.get("WARMUP_ON_STARTUP", "1") == "1"
DEFAULT_SUBJECT_WEIGHT = float(os.environ.get("SUBJECT_WEIGHT", "0.3"))

# ---------------------------------------------------------------------------
# Models loaded at startup
# ---------------------------------------------------------------------------

_tokenizer = None
_session = None
_degraded = False
_model_tag = "unknown"


def _safe_import_langdetect():
    try:
        from langdetect import detect_langs  # type: ignore
        return detect_langs
    except Exception:  # noqa: BLE001
        return None


_detect_langs = _safe_import_langdetect()


def _load() -> None:
    global _tokenizer, _session, _degraded, _model_tag

    model_path = os.path.join(MODEL_DIR, "model.onnx")
    tokenizer_dir = os.environ.get("TOKENIZER_DIR", MODEL_DIR)
    if not os.path.exists(model_path):
        logger.warning("encoder: model not found at %s; starting in DEGRADED mode", model_path)
        _degraded = True
        return

    import onnxruntime as ort  # type: ignore
    from transformers import AutoTokenizer  # type: ignore

    providers = ["CPUExecutionProvider"]
    if os.environ.get("USE_CUDA", "0") == "1":
        providers.insert(0, "CUDAExecutionProvider")
    sess_options = ort.SessionOptions()
    sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

    _tokenizer = AutoTokenizer.from_pretrained(tokenizer_dir)
    _session = ort.InferenceSession(model_path, sess_options=sess_options, providers=providers)
    _model_tag = os.environ.get("MODEL_TAG", MODEL_NAME)

    if WARMUP:
        try:
            _infer_one("Subject: hello", "Body for warmup")
            logger.info("encoder: warmup OK; model_tag=%s providers=%s", _model_tag, providers)
        except Exception:  # noqa: BLE001
            logger.exception("encoder: warmup failed")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

PREDICTIONS = Counter("encoder_predictions_total", "Total predictions", ["mode"])
LATENCY = Histogram(
    "encoder_predict_latency_seconds",
    "End-to-end predict latency",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0),
    labelnames=("mode",),
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PredictRequest(BaseModel):
    subject: str = Field(default="", description="Email subject (normalised).")
    body: str = Field(default="", description="Plaintext body (normalised, no signatures).")
    sender_domain: Optional[str] = Field(default=None)
    message_id: Optional[str] = Field(default=None, description="Caller-supplied pseudonymised ID.")


class PredictResponse(BaseModel):
    message_id: Optional[str] = None
    score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    language: Optional[str] = None
    model_tag: str
    reason_codes: List[str] = Field(default_factory=list)


class BatchRequest(BaseModel):
    items: List[PredictRequest]


class BatchResponse(BaseModel):
    items: List[PredictResponse]


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def _detect_language(text: str) -> Optional[str]:
    if not text or _detect_langs is None:
        return None
    try:
        results = _detect_langs(text[:512])
        if results:
            return results[0].lang
    except Exception:  # noqa: BLE001
        return None
    return None


def _signals(subject: str, body: str) -> List[str]:
    out: List[str] = []
    blob = (subject + "\n" + body).lower()
    if any(t in blob for t in ("urgent", "asap", "immediately", "wire", "invoice")):
        out.append("URGENT_TONE")
    if "click" in blob and ("link" in blob or "below" in blob):
        out.append("CLICK_HERE")
    if "verify your" in blob or "confirm your" in blob:
        out.append("CRED_HARVESTING_LEX")
    return out


def _sigmoid(x: np.ndarray) -> np.ndarray:
    # Numerically stable.
    return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))


@dataclass
class _Inferred:
    score: int
    confidence: float
    language: Optional[str]
    reasons: List[str]


def _infer_one(subject: str, body: str) -> _Inferred:
    """Inference for a single (subject, body) pair.

    Falls back to a deterministic heuristic when ``_session`` is None
    (degraded mode) so callers always get a usable response.
    """
    lang = _detect_language(subject + "\n" + body)
    reasons = _signals(subject, body)
    if _session is None or _tokenizer is None:
        # Degraded fallback: deterministic mid-band score so callers can
        # detect the regime via the "degraded" health bit.
        return _Inferred(score=50, confidence=0.0, language=lang, reasons=reasons)

    # Two-tower trick: tokenise subject and body separately, take the
    # weighted softmax average of the [CLS] logit. The model is assumed
    # to output a single sigmoid over "risk".
    enc_subject = _tokenizer(subject, truncation=True, max_length=MAX_LENGTH, return_tensors="np")
    enc_body = _tokenizer(body, truncation=True, max_length=MAX_LENGTH, return_tensors="np")

    feeds_subject = {k: v for k, v in enc_subject.items()}
    feeds_body = {k: v for k, v in enc_body.items()}

    logits_subject = _session.run(None, feeds_subject)[0]
    logits_body = _session.run(None, feeds_body)[0]

    prob_subject = float(_sigmoid(logits_subject).reshape(-1)[0])
    prob_body = float(_sigmoid(logits_body).reshape(-1)[0])
    w = DEFAULT_SUBJECT_WEIGHT
    prob = w * prob_subject + (1.0 - w) * prob_body

    score = int(round(prob * 100))
    # Confidence is the distance from the 0.5 boundary, mapped to [0, 1].
    confidence = float(min(1.0, abs(prob - 0.5) * 2.0))
    return _Inferred(score=score, confidence=confidence, language=lang, reasons=reasons)


@lru_cache(maxsize=1024)
def _cached_infer(subject: str, body: str) -> _Inferred:
    return _infer_one(subject, body)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="SN360-ES Tier1 Encoder")


@app.on_event("startup")
def on_startup() -> None:
    _load()


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "degraded": _degraded,
        "model_tag": _model_tag,
        "model_name": MODEL_NAME,
    }


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _to_response(req: PredictRequest, inferred: _Inferred) -> PredictResponse:
    return PredictResponse(
        message_id=req.message_id,
        score=max(0, min(100, inferred.score)),
        confidence=max(0.0, min(1.0, inferred.confidence)),
        language=inferred.language,
        model_tag=_model_tag,
        reason_codes=inferred.reasons,
    )


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest) -> PredictResponse:
    if not req.subject and not req.body:
        raise HTTPException(status_code=400, detail="empty input")
    t0 = time.perf_counter()
    inferred = _cached_infer(req.subject, req.body)
    PREDICTIONS.labels(mode="single").inc()
    LATENCY.labels(mode="single").observe(time.perf_counter() - t0)
    return _to_response(req, inferred)


@app.post("/predict/batch", response_model=BatchResponse)
def predict_batch(req: BatchRequest) -> BatchResponse:
    if not req.items:
        return BatchResponse(items=[])
    t0 = time.perf_counter()
    out: List[PredictResponse] = []
    for item in req.items:
        if not item.subject and not item.body:
            out.append(
                PredictResponse(
                    message_id=item.message_id,
                    score=0,
                    confidence=0.0,
                    language=None,
                    model_tag=_model_tag,
                    reason_codes=["EMPTY_INPUT"],
                )
            )
            continue
        inferred = _cached_infer(item.subject, item.body)
        out.append(_to_response(item, inferred))
    PREDICTIONS.labels(mode="batch").inc(len(req.items))
    LATENCY.labels(mode="batch").observe(time.perf_counter() - t0)
    return BatchResponse(items=out)
