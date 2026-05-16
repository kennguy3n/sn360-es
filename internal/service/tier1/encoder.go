package tier1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PredictRequest is the per-message inference payload. The encoder
// receives the normalised body (already stripped of quotes/signatures)
// alongside the subject; we send the sender domain as a low-cost hint
// the model can choose to ignore.
type PredictRequest struct {
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	SenderDomain string `json:"sender_domain,omitempty"`
	// MessageID is an opaque identifier we echo back in the response so
	// callers can map results to inputs in the batched path. It MUST be
	// PII-free (use pseudonymised IDs).
	MessageID string `json:"message_id,omitempty"`
}

// PredictResponse is the per-message inference output.
type PredictResponse struct {
	MessageID string `json:"message_id,omitempty"`
	// Score is the calibrated risk score in [0, 100].
	Score int `json:"score"`
	// Confidence is in [0, 1].
	Confidence float64 `json:"confidence"`
	// Language is the ISO 639-1 detected language code (e.g. "en", "vi").
	Language string `json:"language,omitempty"`
	// ModelTag is the encoder's self-reported build tag, used to
	// invalidate caches across releases.
	ModelTag string `json:"model_tag,omitempty"`
	// ReasonCodes are short signals the encoder surfaces ("URGENT_TONE",
	// "WIRE_REQUEST", ...). Optional.
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

// BatchRequest is the payload sent to /predict/batch.
type BatchRequest struct {
	Items []PredictRequest `json:"items"`
}

// BatchResponse is the payload received from /predict/batch.
type BatchResponse struct {
	Items []PredictResponse `json:"items"`
}

// Client is the HTTP client for the Tier 1 encoder inference service.
// It is safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client
}

// New constructs a Client from cfg. It validates cfg and reuses a single
// underlying http.Client with sane timeouts.
func New(cfg Config) (*Client, error) {
	v, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg: v,
		http: &http.Client{
			Timeout: v.BatchTimeout, // outer cap; per-request ctx tightens further
		},
	}, nil
}

// Health pings the encoder readiness endpoint.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+c.cfg.HealthPath, nil)
	if err != nil {
		return err
	}
	c.addAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("tier1: health %d", resp.StatusCode)
	}
	return nil
}

// Predict scores a single message.
func (c *Client) Predict(ctx context.Context, in PredictRequest) (PredictResponse, error) {
	if strings.TrimSpace(in.Body) == "" && strings.TrimSpace(in.Subject) == "" {
		return PredictResponse{}, errors.New("tier1: empty input")
	}
	out, err := c.doSingle(ctx, in)
	if err != nil {
		return PredictResponse{}, err
	}
	return out, nil
}

// PredictBatch scores up to MaxBatchSize messages in a single request.
// When batch is empty, the call is a no-op.
func (c *Client) PredictBatch(ctx context.Context, items []PredictRequest) ([]PredictResponse, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > c.cfg.MaxBatchSize {
		return nil, fmt.Errorf("tier1: batch size %d exceeds max %d", len(items), c.cfg.MaxBatchSize)
	}
	body, err := json.Marshal(BatchRequest{Items: items})
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, c.cfg.BatchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, c.cfg.URL+c.cfg.BatchPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.addAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// Batched endpoint unavailable; fall back to individual calls so
		// callers see graceful degradation rather than blanket failure.
		return c.fallbackIndividual(ctx, items)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return c.fallbackIndividual(ctx, items)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("tier1: batch status %d", resp.StatusCode)
	}
	var out BatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("tier1: decode batch: %w", err)
	}
	if len(out.Items) != len(items) {
		return nil, fmt.Errorf("tier1: expected %d responses, got %d", len(items), len(out.Items))
	}
	// Preserve caller-supplied MessageID even if encoder dropped it.
	for i := range out.Items {
		if out.Items[i].MessageID == "" {
			out.Items[i].MessageID = items[i].MessageID
		}
	}
	return out.Items, nil
}

// doSingle handles one POST to /predict.
func (c *Client) doSingle(ctx context.Context, in PredictRequest) (PredictResponse, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return PredictResponse{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, c.cfg.URL+c.cfg.PredictPath, bytes.NewReader(body))
	if err != nil {
		return PredictResponse{}, err
	}
	c.addAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return PredictResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return PredictResponse{}, fmt.Errorf("tier1: predict status %d", resp.StatusCode)
	}
	var out PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return PredictResponse{}, fmt.Errorf("tier1: decode predict: %w", err)
	}
	if out.MessageID == "" {
		out.MessageID = in.MessageID
	}
	return out, nil
}

// fallbackIndividual maps a batch into N single-shot calls. Used when
// the encoder doesn't expose a batch endpoint or returns 404/405.
func (c *Client) fallbackIndividual(ctx context.Context, items []PredictRequest) ([]PredictResponse, error) {
	out := make([]PredictResponse, len(items))
	for i, in := range items {
		r, err := c.doSingle(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("tier1: fallback item %d: %w", i, err)
		}
		out[i] = r
	}
	return out, nil
}

func (c *Client) addAuth(req *http.Request) {
	if c.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
}

// Score is a convenience wrapper that runs Predict and applies the
// threshold logic against thresholds. Returns the verdict, raw score,
// and the full response (so callers can stash confidence/language).
func (c *Client) Score(ctx context.Context, in PredictRequest, thresholds Thresholds) (Verdict, int, PredictResponse, error) {
	resp, err := c.Predict(ctx, in)
	if err != nil {
		return "", 0, PredictResponse{}, err
	}
	score := resp.Score
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return thresholds.Decision(score), score, resp, nil
}

// MaxBatchSize returns the configured maximum batch size; exported so
// the batch orchestrator can size its NATS Fetch requests accordingly.
func (c *Client) MaxBatchSize() int { return c.cfg.MaxBatchSize }

// PredictTimeout returns the configured single-shot timeout.
func (c *Client) PredictTimeout() time.Duration { return c.cfg.Timeout }
