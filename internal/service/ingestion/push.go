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
	// Tenants returns the tenant identifiers this receiver covers.
	// Each provider has its own namespace (Gmail uses GWS domain;
	// Outlook uses Azure AD tenant ID), so the PushManager iterates
	// receiver-by-receiver against its own Tenants() rather than
	// taking a cross-product against a global tenant list — that
	// would issue mismatched-namespace subscriptions and, on
	// Outlook, create duplicate Graph subscriptions whose
	// notifications double-publish into the event bus.
	//
	// An empty slice means "no tenants are configured for this
	// provider" and the PushManager skips it with a warning. The
	// receiver MUST NOT return a slice containing an empty string
	// — a missing tenant segment would form an invalid callback URL
	// (/v1/push/{provider}/) that the webhook handler 400-rejects,
	// breaking the Microsoft Graph validation handshake.
	Tenants() []string
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

// SetupSubscriptions runs an initial reconciliation pass: every
// (receiver, tenant) pair the receivers declare via Tenants() that
// is not already subscribed is Subscribed; any already-subscribed
// pair that is nearing expiry is Renewed. It is safe to call
// repeatedly — it is the synchronous fast-path counterpart to
// RenewLoop, which calls the same reconciliation primitive on a
// timer.
//
// SetupSubscriptions MUST NOT cross-product receivers against a
// shared tenant list — each provider has its own tenant namespace
// (Gmail GWS domain vs. Outlook Azure AD tenant ID), so subscribing
// one provider with the other's tenant ID produces invalid callback
// URLs or, worse, duplicate Graph subscriptions that double-publish
// notifications.
func (m *PushManager) SetupSubscriptions(ctx context.Context) error {
	return m.reconcile(ctx)
}

// RenewLoop runs the subscription reconciliation loop until context
// is cancelled. Checks every minute and, on each tick:
//
//   - Subscribes any (receiver, tenant) pair declared by the
//     receivers but not currently tracked in m.subs. This recovers
//     from transient SetupSubscriptions failures (e.g. a Graph 503
//     during initial boot) without requiring a process restart.
//   - Renews any tracked subscription whose ExpiresAt is within
//     RenewalBuffer of now.
//
// Without the auto-resubscribe behaviour, a one-shot SetupSubscriptions
// error would leave the tenant permanently un-subscribed until the
// pod is restarted — a failure mode that's invisible from outside
// and that an operator would only notice via missing-traffic
// alerting on the downstream queue.
func (m *PushManager) RenewLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.reconcile(ctx); err != nil {
				// Per-(provider, tenant) errors are already logged
				// at WARN inside subscribeOne / renewOne. The
				// aggregated error returned here is consumed only
				// by SetupSubscriptions' caller; in the loop we
				// just want the next tick to retry, so drop it.
				_ = err
			}
		}
	}
}

// reconcile is the closed-loop primitive shared by SetupSubscriptions
// (initial pass) and RenewLoop (periodic). Each call walks every
// (receiver, tenant) pair and either Subscribes (when missing) or
// Renews (when nearing expiry). Errors are aggregated and returned
// to the caller; individual failures are also logged at WARN so the
// timer-driven path doesn't have to inspect the return.
func (m *PushManager) reconcile(ctx context.Context) error {
	var errs []error
	for _, recv := range m.cfg.Receivers {
		tenants := recv.Tenants()
		if len(tenants) == 0 {
			m.log.Warn("push: receiver has no tenants configured; skipping",
				slog.String("provider", recv.Kind()))
			continue
		}
		for _, tenant := range tenants {
			if tenant == "" {
				m.log.Warn("push: receiver returned empty tenant; skipping",
					slog.String("provider", recv.Kind()))
				continue
			}
			key := recv.Kind() + ":" + tenant
			m.mu.RLock()
			sub, alreadySubscribed := m.subs[key]
			m.mu.RUnlock()
			if !alreadySubscribed {
				if err := m.subscribeOne(ctx, recv, tenant); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			if time.Until(sub.ExpiresAt) < m.cfg.RenewalBuffer {
				if err := m.renewOne(ctx, recv, sub); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("push: %d subscription op(s) failed", len(errs))
	}
	return nil
}

// subscribeOne registers a single (receiver, tenant) subscription
// and records it in m.subs on success. Errors are logged at WARN
// and returned so the reconciliation loop can aggregate them; a
// failed Subscribe leaves m.subs unchanged so the next reconcile
// tick will retry it automatically.
func (m *PushManager) subscribeOne(ctx context.Context, recv PushReceiver, tenant string) error {
	callbackURL := fmt.Sprintf("%s/v1/push/%s/%s", m.cfg.CallbackBaseURL, recv.Kind(), tenant)
	subID, expiresAt, err := recv.Subscribe(ctx, tenant, callbackURL)
	if err != nil {
		m.log.Warn("push: subscribe failed; will retry on next reconcile tick",
			slog.String("provider", recv.Kind()),
			slog.String("tenant", tenant),
			slog.Any("error", err))
		return err
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
	return nil
}

// renewOne refreshes a single subscription's ExpiresAt. Failures
// are logged but not removed from m.subs — the subscription remains
// tracked so it can be retried on the next tick (and HandleNotification
// continues to dispatch through the receiver). If the provider has
// hard-revoked the subscription, the next Renew will surface the
// 404; an operator-driven path would need to evict from m.subs to
// force a Subscribe on the following tick.
func (m *PushManager) renewOne(ctx context.Context, recv PushReceiver, sub *PushSubscription) error {
	newExpiry, err := recv.Renew(ctx, sub.TenantID, sub.SubscriptionID, sub.CallbackURL)
	if err != nil {
		m.log.Warn("push: renew failed; will retry on next reconcile tick",
			slog.String("provider", sub.Provider),
			slog.String("tenant", sub.TenantID),
			slog.Any("error", err))
		return err
	}
	m.mu.Lock()
	sub.ExpiresAt = newExpiry
	m.mu.Unlock()
	m.log.Info("push: subscription renewed",
		slog.String("provider", sub.Provider),
		slog.String("tenant", sub.TenantID),
		slog.Time("new_expiry", newExpiry))
	return nil
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
