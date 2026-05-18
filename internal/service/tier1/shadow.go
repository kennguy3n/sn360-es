package tier1

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ShadowConfig configures the shadow/canary deployment mode.
type ShadowConfig struct {
	// ShadowURL is the base URL of the shadow encoder endpoint.
	ShadowURL string
	// ShadowAuthToken is the auth token for the shadow endpoint.
	ShadowAuthToken string
	// Enabled controls whether shadow scoring runs.
	Enabled bool
	// SampleRate is the fraction of requests to send to shadow (0.0-1.0).
	// Defaults to 1.0 (all requests).
	SampleRate float64
	// Logger for shadow comparison output.
	Logger *slog.Logger
}

// ShadowResult captures the comparison between production and shadow
// encoder outputs.
type ShadowResult struct {
	ProductionScore int
	ShadowScore     int
	Agreement       bool
	ProductionVerdict Verdict
	ShadowVerdict     Verdict
	Latency         time.Duration
}

// ShadowMetrics tracks agreement statistics between production and
// shadow models.
type ShadowMetrics struct {
	Total     int64
	Agreed    int64
	Diverged  int64
	ShadowErrors int64
}

// ShadowClient wraps a production encoder client and a shadow encoder
// client. Every request goes to production; shadow requests run in
// parallel and their results are logged but never used for scoring.
type ShadowClient struct {
	production *Client
	shadow     *Client
	cfg        ShadowConfig
	log        *slog.Logger
	metrics    shadowMetricsAtomic
	counter    uint64 // for sampling
}

type shadowMetricsAtomic struct {
	total        atomic.Int64
	agreed       atomic.Int64
	diverged     atomic.Int64
	shadowErrors atomic.Int64
}

// NewShadowClient constructs a shadow-enabled client.
func NewShadowClient(production *Client, cfg ShadowConfig) (*ShadowClient, error) {
	if production == nil {
		return nil, ErrNilProduction
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SampleRate <= 0 || cfg.SampleRate > 1 {
		cfg.SampleRate = 1.0
	}

	var shadow *Client
	if cfg.Enabled && cfg.ShadowURL != "" {
		var err error
		shadow, err = New(Config{
			URL:       cfg.ShadowURL,
			AuthToken: cfg.ShadowAuthToken,
		})
		if err != nil {
			cfg.Logger.Warn("tier1: shadow client init failed; shadow mode disabled",
				slog.Any("error", err))
			cfg.Enabled = false
		}
	}

	return &ShadowClient{
		production: production,
		shadow:     shadow,
		cfg:        cfg,
		log:        cfg.Logger,
	}, nil
}

// Predict sends the request to production and (if shadow is enabled)
// also to the shadow encoder in parallel. Only the production result
// is returned.
func (sc *ShadowClient) Predict(ctx context.Context, in PredictRequest, thresholds Thresholds) (Verdict, int, PredictResponse, error) {
	// Always run production.
	verdict, score, resp, err := sc.production.Score(ctx, in, thresholds)
	if err != nil {
		return verdict, score, resp, err
	}

	// Fire shadow in background if enabled and within sample rate.
	// Use context.WithoutCancel so the shadow call isn't cancelled
	// when the production request's context completes.
	if sc.cfg.Enabled && sc.shadow != nil && sc.shouldSample() {
		go sc.runShadow(context.WithoutCancel(ctx), in, thresholds, score, verdict)
	}

	return verdict, score, resp, nil
}

func (sc *ShadowClient) shouldSample() bool {
	if sc.cfg.SampleRate >= 1.0 {
		return true
	}
	n := atomic.AddUint64(&sc.counter, 1)
	return float64(n%100)/100.0 < sc.cfg.SampleRate
}

func (sc *ShadowClient) runShadow(ctx context.Context, in PredictRequest, thresholds Thresholds, prodScore int, prodVerdict Verdict) {
	sc.metrics.total.Add(1)

	start := time.Now()
	shadowVerdict, shadowScore, _, err := sc.shadow.Score(ctx, in, thresholds)
	latency := time.Since(start)

	if err != nil {
		sc.metrics.shadowErrors.Add(1)
		sc.log.WarnContext(ctx, "tier1: shadow predict failed",
			slog.Any("error", err),
			slog.String("message_id", in.MessageID))
		return
	}

	agreed := prodVerdict == shadowVerdict
	if agreed {
		sc.metrics.agreed.Add(1)
	} else {
		sc.metrics.diverged.Add(1)
	}

	sc.log.InfoContext(ctx, "tier1: shadow comparison",
		slog.String("message_id", in.MessageID),
		slog.Int("prod_score", prodScore),
		slog.Int("shadow_score", shadowScore),
		slog.String("prod_verdict", string(prodVerdict)),
		slog.String("shadow_verdict", string(shadowVerdict)),
		slog.Bool("agreed", agreed),
		slog.Duration("shadow_latency", latency))
}

// Metrics returns a snapshot of shadow agreement statistics.
func (sc *ShadowClient) Metrics() ShadowMetrics {
	return ShadowMetrics{
		Total:        sc.metrics.total.Load(),
		Agreed:       sc.metrics.agreed.Load(),
		Diverged:     sc.metrics.diverged.Load(),
		ShadowErrors: sc.metrics.shadowErrors.Load(),
	}
}

// ProductionClient returns the underlying production client for
// callers that need direct access (e.g., batch operations).
func (sc *ShadowClient) ProductionClient() *Client {
	return sc.production
}

// PredictBatch delegates to the production client. Shadow is only
// run for single predictions to avoid doubling batch load.
func (sc *ShadowClient) PredictBatch(ctx context.Context, items []PredictRequest) ([]PredictResponse, error) {
	return sc.production.PredictBatch(ctx, items)
}

var (
	// mu guards nothing but exists as a compile-time reference.
	_ sync.Mutex
)

// ErrNilProduction is returned when the production client is nil.
var ErrNilProduction = errors.New("tier1: production client is required")
