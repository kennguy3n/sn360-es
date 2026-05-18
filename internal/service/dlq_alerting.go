package service

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// DLQAlertConfig wires the DLQ alerting service.
type DLQAlertConfig struct {
	Logger *slog.Logger
	Clock  func() time.Time
	// Threshold is the number of DLQ events per tenant per hour
	// that triggers an alert. Defaults to 10.
	Threshold int
	// WebhookURL is the URL to POST alert payloads to. When empty,
	// alerts are logged only.
	WebhookURL string
	// HTTPClient for webhook calls. Defaults to http.DefaultClient.
	HTTPClient *http.Client
	// AlertCooldown is the minimum time between alerts for the same
	// tenant. Defaults to 1 hour.
	AlertCooldown time.Duration
}

// DLQAlert is the payload sent when a tenant exceeds the DLQ threshold.
type DLQAlert struct {
	TenantID  string    `json:"tenant_id"`
	Count     int       `json:"count"`
	Threshold int       `json:"threshold"`
	Window    string    `json:"window"`
	AlertedAt time.Time `json:"alerted_at"`
}

// DLQAlertService monitors per-tenant DLQ counts and fires alerts
// when the threshold is exceeded.
type DLQAlertService struct {
	cfg        DLQAlertConfig
	log        *slog.Logger
	now        func() time.Time
	mu         sync.Mutex
	counts     map[string]*tenantDLQCounter
	lastAlert  map[string]time.Time
	alertSem   chan struct{} // bounds concurrent webhook goroutines
}

type tenantDLQCounter struct {
	count     int
	windowEnd time.Time
}

// NewDLQAlertService constructs the service.
func NewDLQAlertService(cfg DLQAlertConfig) *DLQAlertService {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 10
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.AlertCooldown <= 0 {
		cfg.AlertCooldown = time.Hour
	}
	return &DLQAlertService{
		cfg:       cfg,
		log:       cfg.Logger,
		now:       cfg.Clock,
		counts:    make(map[string]*tenantDLQCounter),
		lastAlert: make(map[string]time.Time),
		alertSem:  make(chan struct{}, 16), // cap concurrent webhook goroutines
	}
}

// RecordDLQ increments the DLQ counter for a tenant and fires an
// alert if the threshold is exceeded.
func (s *DLQAlertService) RecordDLQ(ctx context.Context, tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	counter, ok := s.counts[tenantID]
	if !ok || now.After(counter.windowEnd) {
		s.counts[tenantID] = &tenantDLQCounter{
			count:     1,
			windowEnd: now.Add(time.Hour),
		}
		return
	}
	counter.count++

	if counter.count >= s.cfg.Threshold {
		last, alertedRecently := s.lastAlert[tenantID]
		if alertedRecently && now.Sub(last) < s.cfg.AlertCooldown {
			return
		}
		s.lastAlert[tenantID] = now
		alert := DLQAlert{
			TenantID:  tenantID,
			Count:     counter.count,
			Threshold: s.cfg.Threshold,
			Window:    "1h",
			AlertedAt: now,
		}
		go func() {
			select {
			case s.alertSem <- struct{}{}:
				defer func() { <-s.alertSem }()
				s.fireAlert(context.WithoutCancel(ctx), alert)
			default:
				s.log.Warn("dlq_alert: webhook backpressure, dropping alert",
					slog.String("tenant", alert.TenantID))
			}
		}()
	}
}

func (s *DLQAlertService) fireAlert(ctx context.Context, alert DLQAlert) {
	s.log.WarnContext(ctx, "dlq_alert: threshold exceeded",
		slog.String("tenant", alert.TenantID),
		slog.Int("count", alert.Count),
		slog.Int("threshold", alert.Threshold))

	if s.cfg.WebhookURL == "" {
		return
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		s.log.WarnContext(ctx, "dlq_alert: webhook request failed", slog.Any("error", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		s.log.WarnContext(ctx, "dlq_alert: webhook call failed", slog.Any("error", err))
		return
	}
	resp.Body.Close()
}

// Stats returns the current DLQ counts per tenant.
func (s *DLQAlertService) Stats() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counts))
	for tid, c := range s.counts {
		out[tid] = c.count
	}
	return out
}
