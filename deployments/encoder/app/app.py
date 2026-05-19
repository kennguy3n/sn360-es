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


# ---------------------------------------------------------------------------
# Sensitivity role classification endpoint
# ---------------------------------------------------------------------------

# Infrastructure-access keywords that map to "critical" tier. If the
# encoder model was not fine-tuned on "critical" examples, this
# post-processing step catches them via keyword match.
_INFRA_KEYWORDS = (
    "database administrator", "dba ", "system administrator", "sysadmin",
    "domain admin", "cloud administrator", "infrastructure engineer",
    "devops lead", "sre lead", "network administrator",
    "security administrator", "platform engineer", "root access",
    # Japanese
    "データベース管理者", "システム管理者", "インフラエンジニア", "クラウド管理者",
    # Korean
    "데이터베이스 관리자", "시스템 관리자", "인프라 엔지니어",
    # Chinese
    "数据库管理员", "系统管理员", "运维工程师", "云管理员", "基础设施工程师",
    # Vietnamese
    "quản trị cơ sở dữ liệu", "quản trị hệ thống",
)


class RoleClassifyItem(BaseModel):
    index: int = Field(..., ge=0)
    job_title: str = Field(default="")
    department: str = Field(default="")
    display_name: str = Field(default="")
    group_names: List[str] = Field(default_factory=list)


class RoleClassifyResult(BaseModel):
    index: int
    sensitivity: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str = ""


class RoleClassifyRequest(BaseModel):
    users: List[RoleClassifyItem]


class RoleClassifyResponse(BaseModel):
    results: List[RoleClassifyResult]


# Tier-based keyword matching consistent with the Go sensitivityKeywords map.
_TIER_KEYWORDS: dict[str, list[str]] = {
    "max": [
        "ceo", "cfo", " coo ", " cto ", "ciso", "founder",
        "chief executive", "chief financial", "owner",
        "首席执行官", "首席财务官", "总裁", "创始人", "董事长",
        "代表取締役", "社長", "대표이사", "창업자",
    ],
    "high": [
        # English — Finance / HR / Legal
        "finance", "treasury", "controller", "human resources",
        " legal", "compliance", "general counsel",
        # English — Technology
        "site reliability engineer", "security engineer", "security analyst",
        "cloud engineer", "network engineer", "data engineer",
        # English — M&A / Strategy
        "m&a", "corporate development", "investor relations",
        "board secretary", "corporate strategy",
        # English — Healthcare
        "physician", "pharmacist", "medical director", "chief medical",
        "clinical director", "surgeon",
        # English — R&D
        "research director", "data scientist", "ml engineer", "patent",
        # Japanese
        "財務", "経理", "人事", "法務", "コンプライアンス",
        "データベースエンジニア", "セキュリティエンジニア", "クラウドエンジニア",
        "医師", "薬剤師", "看護師長", "医療情報",
        "経営企画", "事業開発", "投資家向け広報",
        # Korean
        "재무", "회계", "인사", "법무", "컴플라이언스",
        "보안 엔지니어", "클라우드 엔지니어", "데이터 엔지니어",
        "의사", "약사", "간호부장",
        "경영기획", "사업개발", "투자자 관계",
        # Thai
        "การเงิน", "บัญชี", "ทรัพยากรบุคคล", "กฎหมาย",
        "แพทย์", "เภสัชกร", "หัวหน้าพยาบาล",
        # Vietnamese
        "tài chính", "kế toán", "nhân sự", "pháp lý",
        "bác sĩ", "dược sĩ", "trưởng phòng y tế",
        "phát triển doanh nghiệp", "quan hệ nhà đầu tư",
        # Chinese
        "财务", "会计", "人力资源", "法务", "合规",
        "安全工程师", "云工程师", "数据工程师",
        "医生", "药剂师", "护士长", "医疗信息",
        "企业发展", "并购", "投资者关系", "董事会秘书",
    ],
    "elevated": [
        # English
        "executive assistant", "admin assistant", "office manager",
        "procurement", "vendor management",
        "devops engineer", "devops", "junior dba", "help desk manager",
        "nurse", "lab technician", "radiologist",
        "paralegal", "privacy officer", "data protection officer",
        "sales director", "customer success",
        # Japanese
        "秘書", "調達", "購買", "事務長",
        "看護師", "検査技師", "パラリーガル",
        # Korean
        "비서", "조달", "사무장",
        "간호사", "검사기사", "법률보조원",
        # Thai
        "ผู้ช่วยผู้บริหาร", "จัดซื้อ", "พยาบาล",
        # Vietnamese
        "trợ lý giám đốc", "mua sắm",
        "y tá", "kỹ thuật viên xét nghiệm",
        # Chinese
        "行政助理", "采购", "供应商管理", "办公室经理",
        "护士", "检验技师", "法律助理",
    ],
}


def _classify_role_sensitivity(item: RoleClassifyItem) -> RoleClassifyResult:
    """Classify a single user's sensitivity tier using keyword matching.

    When the encoder model supports "critical" as a fine-tuned label this
    function can be replaced with model inference; currently it uses the
    same multilingual keyword map the Go keyword classifier uses.
    """
    # Pad with spaces so word-boundary keywords (e.g. " coo ", "dba ")
    # work correctly at start/end of the string.
    hay = " " + " ".join([
        item.job_title, item.department,
        item.display_name, " ".join(item.group_names),
    ]).lower() + " "

    # Check for infrastructure-level (critical) keywords first.
    for kw in _INFRA_KEYWORDS:
        if kw in hay:
            return RoleClassifyResult(
                index=item.index,
                sensitivity="critical",
                confidence=0.92,
                reason=f"infrastructure keyword: {kw}",
            )

    for tier, keywords in _TIER_KEYWORDS.items():
        for kw in keywords:
            if kw in hay:
                return RoleClassifyResult(
                    index=item.index,
                    sensitivity=tier,
                    confidence=0.85,
                    reason=f"keyword: {kw}",
                )

    return RoleClassifyResult(
        index=item.index,
        sensitivity="default",
        confidence=0.50,
        reason="no matching keywords",
    )


@app.post("/classify/roles", response_model=RoleClassifyResponse)
def classify_roles(req: RoleClassifyRequest) -> RoleClassifyResponse:
    """Classify users into sensitivity tiers based on role signals.

    Uses keyword matching as a fallback when the encoder model has not
    been fine-tuned on the full 5-tier sensitivity vocabulary. Results
    are consistent with the Go-side KeywordClassifyInput function.
    """
    if not req.users:
        return RoleClassifyResponse(results=[])
    t0 = time.perf_counter()
    results = [_classify_role_sensitivity(u) for u in req.users]
    PREDICTIONS.labels(mode="roles").inc(len(req.users))
    LATENCY.labels(mode="roles").observe(time.perf_counter() - t0)
    return RoleClassifyResponse(results=results)
