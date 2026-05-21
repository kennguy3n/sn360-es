package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// IngestionMode controls how the service acquires messages.
type IngestionMode string

const (
	ModePoll   IngestionMode = "poll"
	ModePush   IngestionMode = "push"
	ModeHybrid IngestionMode = "hybrid"
)

// PushReceiver is the provider-specific contract for registering
// webhook/push subscriptions and receiving push notifications.
type PushReceiver interface {
	// Kind returns a stable identifier ("gmail" / "outlook").
	Kind() string
	// Subscribe registers push notification delivery with the
	// provider. For Gmail this is a Pub/Sub watch; for Outlook it
	// creates a Graph Change Notification subscription.
	Subscribe(ctx context.Context, tenantID string, callbackURL string) (subscriptionID string, expiresAt time.Time, err error)
	// Renew refreshes an existing subscription before it expires.
	Renew(ctx context.Context, tenantID, subscriptionID string, callbackURL string) (expiresAt time.Time, err error)
	// HandleNotification processes an incoming push notification
	// payload and returns the raw messages to evaluate.
	HandleNotification(ctx context.Context, tenantID string, payload json.RawMessage) ([]RawEmail, error)
}

// PushConfig wires the push ingestion subsystem.
type PushConfig struct {
	Receivers  []PushReceiver
	Publisher  events.EventService
	Logger     *slog.Logger
	Normalizer Normalizer
	// CallbackBaseURL is the externally-reachable URL that providers
	// will POST push notifications to. The handler appends
	// /{provider}/{tenant} as a path suffix.
	CallbackBaseURL string
	// RenewalBuffer is how far before expiry to renew subscriptions.
	// Defaults to 1 hour.
	RenewalBuffer time.Duration
	// Subject is the JetStream subject for emitted events.
	Subject string
	// TenantIDs are the tenants to subscribe to. When empty,
	// subscriptions are created for all known tenants.
	TenantIDs []string
}

// PushSubscription tracks a live push subscription.
type PushSubscription struct {
	Provider       string
	TenantID       string
	SubscriptionID string
	ExpiresAt      time.Time
	CallbackURL    string
}

// PushManager manages push notification subscriptions and processes
// incoming notifications. It is the push counterpart to the Poller.
type PushManager struct {
	cfg  PushConfig
	mu   sync.RWMutex
	subs map[string]*PushSubscription // keyed by provider:tenant
	log  *slog.Logger
}

// NewPushManager creates a PushManager and validates the config.
func NewPushManager(cfg PushConfig) (*PushManager, error) {
	if len(cfg.Receivers) == 0 {
		return nil, errors.New("push: at least one PushReceiver is required")
	}
	if cfg.Publisher == nil {
		return nil, errors.New("push: publisher is required")
	}
	if cfg.CallbackBaseURL == "" {
		return nil, errors.New("push: callback_base_url is required")
	}
	if cfg.Normalizer == nil {
		cfg.Normalizer = NewDefaultNormalizer()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RenewalBuffer <= 0 {
		cfg.RenewalBuffer = 1 * time.Hour
	}
	if cfg.Subject == "" {
		cfg.Subject = "es.evaluate.request"
	}
	return &PushManager{
		cfg:  cfg,
		subs: make(map[string]*PushSubscription),
		log:  cfg.Logger,
	}, nil
}

// SetupSubscriptions registers push subscriptions for all configured
// tenants and receivers. Should be called at startup.
func (m *PushManager) SetupSubscriptions(ctx context.Context) error {
	tenants := m.cfg.TenantIDs
	if len(tenants) == 0 {
		tenants = []string{""}
	}

	var errs []error
	for _, recv := range m.cfg.Receivers {
		for _, tenant := range tenants {
			callbackURL := fmt.Sprintf("%s/v1/push/%s/%s", m.cfg.CallbackBaseURL, recv.Kind(), tenant)
			subID, expiresAt, err := recv.Subscribe(ctx, tenant, callbackURL)
			if err != nil {
				m.log.Warn("push: subscribe failed",
					slog.String("provider", recv.Kind()),
					slog.String("tenant", tenant),
					slog.Any("error", err))
				errs = append(errs, err)
				continue
			}
			key := recv.Kind() + ":" + tenant
			m.mu.Lock()
			m.subs[key] = &PushSubscription{
				Provider:       recv.Kind(),
				TenantID:       tenant,
				SubscriptionID: subID,
				ExpiresAt:      expiresAt,
				CallbackURL:    callbackURL,
			}
			m.mu.Unlock()
			m.log.Info("push: subscription registered",
				slog.String("provider", recv.Kind()),
				slog.String("tenant", tenant),
				slog.String("subscription_id", subID),
				slog.Time("expires_at", expiresAt))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("push: %d subscription(s) failed", len(errs))
	}
	return nil
}

// RenewLoop runs the subscription renewal loop until context is
// cancelled. Checks every minute for subscriptions nearing expiry.
func (m *PushManager) RenewLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.renewExpiring(ctx)
		}
	}
}

func (m *PushManager) renewExpiring(ctx context.Context) {
	m.mu.RLock()
	now := time.Now()
	var toRenew []*PushSubscription
	for _, s := range m.subs {
		if s.ExpiresAt.Sub(now) < m.cfg.RenewalBuffer {
			toRenew = append(toRenew, s)
		}
	}
	m.mu.RUnlock()

	for _, s := range toRenew {
		recv := m.findReceiver(s.Provider)
		if recv == nil {
			continue
		}
		newExpiry, err := recv.Renew(ctx, s.TenantID, s.SubscriptionID, s.CallbackURL)
		if err != nil {
			m.log.Warn("push: renew failed",
				slog.String("provider", s.Provider),
				slog.String("tenant", s.TenantID),
				slog.Any("error", err))
			continue
		}
		m.mu.Lock()
		s.ExpiresAt = newExpiry
		m.mu.Unlock()
		m.log.Info("push: subscription renewed",
			slog.String("provider", s.Provider),
			slog.String("tenant", s.TenantID),
			slog.Time("new_expiry", newExpiry))
	}
}

func (m *PushManager) findReceiver(kind string) PushReceiver {
	for _, r := range m.cfg.Receivers {
		if r.Kind() == kind {
			return r
		}
	}
	return nil
}

// HandleNotification processes an incoming push notification from a
// provider. It normalizes the raw emails and publishes evaluate
// requests.
func (m *PushManager) HandleNotification(ctx context.Context, provider, tenantID string, payload json.RawMessage) error {
	recv := m.findReceiver(provider)
	if recv == nil {
		return fmt.Errorf("push: unknown provider %q", provider)
	}

	emails, err := recv.HandleNotification(ctx, tenantID, payload)
	if err != nil {
		return fmt.Errorf("push: handle notification: %w", err)
	}

	for _, raw := range emails {
		req, err := m.cfg.Normalizer.Normalize(ctx, raw)
		if err != nil {
			m.log.Warn("push: normalize failed",
				slog.String("provider", provider),
				slog.String("tenant", tenantID),
				slog.Any("error", err))
			continue
		}
		blob, err := json.Marshal(req)
		if err != nil {
			m.log.Warn("push: marshal failed", slog.Any("error", err))
			continue
		}
		if perr := m.cfg.Publisher.Publish(ctx, m.cfg.Subject, blob,
			events.WithTenantID(req.TenantID),
			events.WithCorrelationID(req.CorrelationID),
			events.WithEventType("evaluate.request"),
		); perr != nil {
			m.log.Warn("push: publish failed",
				slog.String("message_id", req.MessageID),
				slog.Any("error", perr))
		}
	}
	return nil
}

// Subscriptions returns a snapshot of active subscriptions.
func (m *PushManager) Subscriptions() []PushSubscription {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PushSubscription, 0, len(m.subs))
	for _, s := range m.subs {
		out = append(out, *s)
	}
	return out
}

// HybridPollerConfig extends PollerConfig with push settings.
type HybridPollerConfig struct {
	PollerConfig
	PushReceivers   []PushReceiver
	CallbackBaseURL string
	Mode            IngestionMode
}

// NewHybridIngestion creates an ingestion system based on the
// configured mode. Returns both a Poller (may be nil in push-only
// mode) and a PushManager (may be nil in poll-only mode).
func NewHybridIngestion(cfg HybridPollerConfig) (*Poller, *PushManager, error) {
	var poller *Poller
	var push *PushManager
	var err error

	switch cfg.Mode {
	case ModePoll, "":
		poller, err = New(cfg.PollerConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("poll ingestion: %w", err)
		}
	case ModePush:
		push, err = NewPushManager(PushConfig{
			Receivers:       cfg.PushReceivers,
			Publisher:       cfg.Publisher,
			Logger:          cfg.Logger,
			Normalizer:      cfg.Normalizer,
			CallbackBaseURL: cfg.CallbackBaseURL,
			Subject:         cfg.Subject,
			TenantIDs:       cfg.TenantIDs,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("push ingestion: %w", err)
		}
	case ModeHybrid:
		poller, err = New(cfg.PollerConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("hybrid poll: %w", err)
		}
		push, err = NewPushManager(PushConfig{
			Receivers:       cfg.PushReceivers,
			Publisher:       cfg.Publisher,
			Logger:          cfg.Logger,
			Normalizer:      cfg.Normalizer,
			CallbackBaseURL: cfg.CallbackBaseURL,
			Subject:         cfg.Subject,
			TenantIDs:       cfg.TenantIDs,
		})
		if err != nil {
			return poller, nil, fmt.Errorf("hybrid push: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("unknown ingestion mode: %q", cfg.Mode)
	}
	return poller, push, nil
}

// HandlePushNotification is a convenience entry point for the HTTP
// handler to dispatch notifications. It must validate that the
// provider and tenant are known before calling HandleNotification.
func HandlePushNotification(ctx context.Context, mgr *PushManager, provider, tenantID string, payload json.RawMessage) error {
	if mgr == nil {
		return errors.New("push: push manager not configured")
	}
	return mgr.HandleNotification(ctx, provider, tenantID, payload)
}

// EvaluateRequestFromRaw is a convenience wrapper: normalize + marshal.
func EvaluateRequestFromRaw(ctx context.Context, n Normalizer, raw RawEmail) (dto.EvaluateRequest, []byte, error) {
	req, err := n.Normalize(ctx, raw)
	if err != nil {
		return dto.EvaluateRequest{}, nil, err
	}
	blob, err := json.Marshal(req)
	if err != nil {
		return req, nil, err
	}
	return req, blob, nil
}
