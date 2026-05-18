package evaluate

import (
	"context"
	"errors"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
)

// Tier1Adapter bridges the concrete tier1.Client to the evaluate.Tier1Client
// interface that the orchestrator depends on. The adapter is the only piece
// of code that knows about both the HTTP-shaped tier1.PredictRequest /
// PredictResponse and the orchestrator-shaped dto.EvaluateRequest /
// dto.Tier1Outcome.
//
// Construction: pass an already-validated *tier1.Client. Thresholds are
// kept here only so callers can also use this adapter as a Score helper;
// the orchestrator itself recomputes pass/flag/escalate from its own
// configured thresholds (see Evaluator.runTier1).
type Tier1Adapter struct {
	client     *tier1.Client
	thresholds tier1.Thresholds
}

// NewTier1Adapter returns an adapter that satisfies evaluate.Tier1Client.
// client must be non-nil; thresholds may be the zero value (the
// orchestrator applies its own thresholds in that case).
func NewTier1Adapter(client *tier1.Client, thresholds tier1.Thresholds) *Tier1Adapter {
	return &Tier1Adapter{client: client, thresholds: thresholds}
}

// Evaluate implements evaluate.Tier1Client. It maps the orchestrator's
// EvaluateRequest into the encoder's PredictRequest, dispatches the
// call, and projects the response back into the orchestrator's
// Tier1Outcome shape.
//
// LatencyMs is captured wall-clock so callers (the Evaluator + the
// telemetry observer) see the round-trip the encoder cost, not just
// the HTTP body decode time.
func (a *Tier1Adapter) Evaluate(ctx context.Context, req dto.EvaluateRequest) (dto.Tier1Outcome, error) {
	if a == nil || a.client == nil {
		return dto.Tier1Outcome{}, errors.New("tier1_adapter: client is nil")
	}
	start := time.Now()
	resp, err := a.client.Predict(ctx, tier1.PredictRequest{
		Subject:      req.Subject,
		Body:         req.Body,
		SenderDomain: req.Signals.SenderDomain,
		MessageID:    req.MessageID,
	})
	if err != nil {
		return dto.Tier1Outcome{}, err
	}
	// Clamp score to the documented [0, 100] range. Encoder builds
	// occasionally emit slightly out-of-range values during model
	// rollouts; we don't want callers (the categoriser, the score
	// aggregator) to have to defend against that.
	score := resp.Score
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	// Defensive copy of ReasonCodes so a downstream mutation of
	// res.Tier1.ReasonCodes cannot reach back into the HTTP-decoded
	// slice the encoder client owns. The batch path takes a similar
	// copy at batch.go:327 — the per-message path now matches so an
	// identical Tier 1 response produces identical reason codes on
	// both subjects, instead of the per-message path silently
	// dropping them as it did pre-fix.
	var reasonCodes []string
	if len(resp.ReasonCodes) > 0 {
		reasonCodes = append([]string(nil), resp.ReasonCodes...)
	}
	return dto.Tier1Outcome{
		Score:       score,
		Confidence:  resp.Confidence,
		Language:    resp.Language,
		ModelName:   resp.ModelTag,
		LatencyMs:   time.Since(start).Milliseconds(),
		ReasonCodes: reasonCodes,
	}, nil
}
