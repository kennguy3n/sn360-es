// Package bridge implements the WS-5A.1 NATS event bridge between
// sn360-es (email security) and the sn360-security-platform SOC. It
// publishes HighRisk+/Blocked verdict events, quarantine actions, and
// escalation ticket transitions onto the platform's JetStream stream
// so the platform's correlation, playbook, soc-triage, and
// alert-forwarder pipelines see email events on the same
// `sn360.events.>` namespace they already consume.
//
// The bridge is deliberately a routing concern, not a schema
// translator. It re-uses the platform's existing event envelope (the
// same shape `services/alert-forwarder/internal/indexer.ParseAlert`
// already accepts) so the platform side needs zero new code to index
// these events — `agent.labels.sn360.tenant_id` carries the tenant,
// `rule.id` and `rule.level` are populated from the verdict, the
// domain payload sits under `data.*`. Per-tenant pseudonymisation
// continues to happen platform-side in
// `services/alert-forwarder/internal/indexer.HMACPseudonymizer`; the
// bridge never publishes raw recipient or sender addresses — only
// stable SHA-256(tenant_id || ":" || email) fingerprints so the
// correlation engine can correlate messages from the same actor
// without seeing the actor's address.
//
// Activation is gated on PLATFORM_NATS_ENABLED so a standalone
// sn360-es deployment that is not paired with sn360-security-platform
// keeps its existing behaviour (no bridge publishes, no extra
// dependency on a second NATS cluster).
package bridge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// SubjectPrefix is the JetStream subject namespace the platform's
// alert-forwarder eventsrc subscribes to (default filter
// `sn360.events.>`). The per-event suffix is
// `email.<tenant_id>.<kind>` so each event lands on
// `sn360.events.email.<tenant_id>.<kind>`.
const SubjectPrefix = "sn360.events.email"

// Subject kinds the bridge publishes on. Kept exported so handlers
// and tests can refer to them by name.
const (
	KindPhishing   = "phishing"
	KindBEC        = "bec"
	KindMalware    = "malware"
	KindQuarantine = "quarantine"
	KindEscalation = "escalation"
)

// Escalation actions surfaced under `data.action`.
const (
	EscalationActionCreated  = "created"
	EscalationActionResolved = "resolved"
)

// Quarantine actions surfaced under `data.action`.
const (
	QuarantineActionApplied  = "applied"
	QuarantineActionReleased = "released"
)

// Default platform-side JetStream stream the alert-forwarder binds
// its consumer to. Documented in
// `services/alert-forwarder/internal/eventsrc.New`. The bridge does
// NOT create or modify the stream — that lifecycle belongs to the
// platform.
const defaultPlatformStream = "sn360-events"

// PlatformPublisher publishes terminal email-security events onto the
// sn360-security-platform NATS bus. The interface keeps the call
// sites simple and lets tests substitute a recording implementation
// without spinning up an embedded NATS server.
type PlatformPublisher interface {
	// PublishEvaluation publishes a terminal verdict (Blocked or
	// HighRisk only). For Trusted/Caution/Warning/Info results the
	// implementation silently no-ops so callers do not need a tier
	// gate at every site.
	PublishEvaluation(ctx context.Context, res *dto.EvaluateResult) error

	// PublishQuarantine publishes a quarantine apply/release event.
	PublishQuarantine(ctx context.Context, evt QuarantineEvent) error

	// PublishEscalation publishes an escalation ticket transition.
	// action is one of EscalationActionCreated / EscalationActionResolved.
	PublishEscalation(ctx context.Context, action string, ticket *dto.EscalationTicket) error

	// Close releases the underlying NATS connection. Safe to call on
	// a disabled publisher.
	Close() error
}

// QuarantineEvent is the bridge's view of a quarantine action. The
// caller assembles it from the original evaluation result so the
// bridge does not need to crack open the action service's internal
// types.
type QuarantineEvent struct {
	TenantID      string
	MessageID     string
	CorrelationID string
	Action        string // QuarantineActionApplied / QuarantineActionReleased
	Tier          constant.Tier
	Primary       constant.Category
	Score         int
	Recipient     string // raw; hashed before publish
	RequestedBy   string // optional, e.g. for release events
}

// Config carries the wiring inputs for the bridge. Constructed from
// `internal/config.Platform` in the application composition root.
type Config struct {
	// Enabled gates the bridge. When false, New returns a disabled
	// (no-op) publisher so call sites do not need to nil-check.
	Enabled bool

	// URLs is a comma-separated list of NATS server URLs for the
	// platform cluster. Required when Enabled.
	URLs string

	// CredsFile is an optional path to a NATS user credentials file
	// (.creds) issued by the platform's account JWT.
	CredsFile string

	// Token is an optional plain auth token (lower-priority than
	// CredsFile and TLS client certs).
	Token string

	// Name is the connection name advertised to the platform NATS
	// for observability. Defaults to "sn360-es-bridge".
	Name string

	// Source is embedded in `data.source` so the platform can
	// distinguish events that originated in sn360-es from events
	// produced by other sources on the same subject namespace.
	// Defaults to "sn360-es".
	Source string

	// ClusterID identifies which sn360-es deployment produced the
	// event. Embedded in `cluster_id` and
	// `agent.labels.sn360.cluster_id`. Defaults to Source.
	ClusterID string

	// TLS — mutually-exclusive with creds in NATS' usual sense, but
	// both may be set when the server requires TLS *and* JWT auth.
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
	TLSInsecure bool // dev-only

	// Reconnect / publish timing knobs. Reasonable defaults are
	// applied when zero.
	ReconnectWait  time.Duration
	MaxReconnects  int
	PublishTimeout time.Duration
	PublishRetries int

	// Stream is the platform JetStream stream the bridge publishes
	// against. Defaults to "sn360-events". The bridge does not
	// create the stream; the platform owns that lifecycle.
	Stream string
}

// withDefaults fills in unset fields. Called by New so callers can
// pass a partially-populated Config.
func (c Config) withDefaults() Config {
	if c.Name == "" {
		c.Name = "sn360-es-bridge"
	}
	if c.Source == "" {
		c.Source = "sn360-es"
	}
	if c.ClusterID == "" {
		c.ClusterID = c.Source
	}
	if c.ReconnectWait <= 0 {
		c.ReconnectWait = 2 * time.Second
	}
	if c.MaxReconnects == 0 {
		// The zero-value (unset) maps to -1 ("retry forever"),
		// which is the safer default for a fire-and-forget
		// bridge — a long-lived network blip should not silently
		// give up forwarding SOC events.
		//
		// We deliberately do not preserve an explicit 0 because
		// Go's zero-value semantics make it impossible to
		// distinguish "unset" from "explicit 0" without a
		// pointer field, and "unset" is by far the common case.
		//
		// There is intentionally no MaxReconnects value that
		// means "no reconnect" — the NATS Go client treats every
		// MaxReconnect < 0 as infinite (the reconnect loop only
		// breaks when MaxReconnect >= 0 && i >= MaxReconnect; see
		// nats-io/nats.go@v1.52.0 conn.go), so -1, -2, and -999
		// all produce the same behaviour as the default. An
		// operator who genuinely wants the bridge to give up
		// after the first disconnect must wire nats.NoReconnect()
		// at the call site (intentionally not exposed as config
		// because there is no realistic operational reason to
		// silently stop forwarding SOC events on the first blip).
		c.MaxReconnects = -1
	}
	if c.PublishTimeout <= 0 {
		c.PublishTimeout = 3 * time.Second
	}
	if c.PublishRetries <= 0 {
		c.PublishRetries = 3
	}
	if c.Stream == "" {
		c.Stream = defaultPlatformStream
	}
	return c
}

// New constructs a PlatformPublisher. When cfg.Enabled is false or
// cfg.URLs is empty, it returns a disabled (no-op) publisher and a
// nil error so the caller can wire it unconditionally.
//
// The returned publisher owns its NATS connection; the caller MUST
// Close it during shutdown.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (PlatformPublisher, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if !cfg.Enabled {
		logger.Info("sn360-es: platform NATS bridge disabled (PLATFORM_NATS_ENABLED=false)")
		return Disabled(), nil
	}
	if strings.TrimSpace(cfg.URLs) == "" {
		logger.Warn("sn360-es: platform NATS bridge enabled but PLATFORM_NATS_URLS is empty; running in disabled mode")
		return Disabled(), nil
	}
	cfg = cfg.withDefaults()

	opts, err := natsOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("bridge: build nats options: %w", err)
	}
	opts = append(opts,
		// RetryOnFailedConnect makes nats.Connect return
		// successfully even when the platform NATS cluster is
		// unreachable at boot: the client schedules background
		// reconnect attempts (governed by ReconnectWait /
		// MaxReconnects) and queues nothing locally — Publish
		// calls in the meantime surface ErrConnectionClosed /
		// ErrNoServers and are absorbed by the bridge's
		// log-and-continue policy. This decouples sn360-es boot
		// from platform-NATS availability so a transient platform
		// outage cannot prevent the core email-security pipeline
		// from starting — operators who want the bridge to
		// fail-closed on misconfiguration still get that from the
		// production validation in internal/config/validate.go,
		// which rejects ENABLED=true + URLS="" before this point.
		nats.RetryOnFailedConnect(true),
		nats.DisconnectErrHandler(func(_ *nats.Conn, derr error) {
			logger.Warn("sn360-es: platform NATS disconnected", slog.Any("error", derr))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("sn360-es: platform NATS reconnected", slog.String("url", nc.ConnectedUrl()))
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			logger.Info("sn360-es: platform NATS connection closed")
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, perr error) {
			logger.Warn("sn360-es: platform NATS async error", slog.Any("error", perr))
		}),
	)

	nc, err := nats.Connect(cfg.URLs, opts...)
	if err != nil {
		// With RetryOnFailedConnect, an error here means the
		// options themselves are invalid (bad TLS cert, malformed
		// URL, etc.) — not a transient network failure. Those are
		// real configuration bugs and should fail boot.
		return nil, fmt.Errorf("bridge: connect platform nats %q: %w", cfg.URLs, err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bridge: platform jetstream context: %w", err)
	}

	// Eager liveness probe so a wrong URL / bad creds surfaces at
	// boot rather than on the first verdict. AccountInfo failures
	// are logged but non-fatal: the alert-forwarder consumer may
	// have read-only access in some deployments, and Publish will
	// surface real wire failures with full context.
	if cfg.PublishTimeout > 0 {
		probeCtx, cancel := context.WithTimeout(ctx, cfg.PublishTimeout)
		if _, perr := js.AccountInfo(probeCtx); perr != nil {
			logger.Warn("sn360-es: platform NATS AccountInfo probe failed (continuing)",
				slog.Any("error", perr))
		}
		cancel()
	}

	logger.Info("sn360-es: platform NATS bridge connected",
		slog.String("url", nc.ConnectedUrl()),
		slog.String("name", cfg.Name),
		slog.String("source", cfg.Source),
		slog.String("cluster_id", cfg.ClusterID),
		slog.String("stream", cfg.Stream))

	return &natsPlatformPublisher{
		cfg:    cfg,
		logger: logger,
		nc:     nc,
		js:     js,
	}, nil
}

func natsOptions(cfg Config) ([]nats.Option, error) {
	opts := []nats.Option{
		nats.Name(cfg.Name),
		nats.ReconnectWait(cfg.ReconnectWait),
		nats.MaxReconnects(cfg.MaxReconnects),
	}
	if cfg.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.CredsFile))
	}
	if cfg.Token != "" {
		opts = append(opts, nats.Token(cfg.Token))
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}
	return opts, nil
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.TLSCAFile == "" && cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" && !cfg.TLSInsecure {
		return nil, nil
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.TLSInsecure} //nolint:gosec // dev-only
	if cfg.TLSCAFile != "" {
		caBytes, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("bridge: read TLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("bridge: TLS CA %s has no valid certs", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("bridge: load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

// natsPlatformPublisher is the production PlatformPublisher backed by
// a NATS JetStream connection to the platform cluster.
type natsPlatformPublisher struct {
	cfg    Config
	logger *slog.Logger

	mu sync.Mutex
	nc *nats.Conn
	js jetstream.JetStream
}

// PublishEvaluation implements PlatformPublisher.
func (p *natsPlatformPublisher) PublishEvaluation(ctx context.Context, res *dto.EvaluateResult) error {
	if res == nil {
		return nil
	}
	if res.TenantID == "" || res.MessageID == "" {
		return nil
	}
	// Gate: only publish terminal verdicts. The platform's
	// correlation engine is interested in HighRisk+ — Caution /
	// Warning / Info / Trusted produce too much noise and would
	// re-introduce the per-message-per-tenant cost the cost model
	// explicitly avoids.
	if !isTerminalTier(res.Tier) {
		return nil
	}
	kind := kindForVerdict(res)
	subj := p.subject(res.TenantID, kind)

	payload := EvaluationPayload{
		Source:           p.cfg.Source,
		EventType:        "email.verdict." + kind,
		Action:           "verdict",
		MessageID:        res.MessageID,
		CorrelationID:    res.CorrelationID,
		Tier:             string(res.Tier),
		Primary:          string(res.Primary),
		Secondary:        categoriesAsStrings(res.Secondary),
		Score:            res.Score,
		ReasonCodes:      res.ReasonCodes,
		EvaluatedAt:      timeOrNow(res.EvaluatedAt),
		Degraded:         res.Degraded,
		DegradedServices: res.DegradedServices,
		RecipientHash:    hashIdentifier(res.TenantID, res.Recipient),
		// SenderHash is intentionally left empty here: the
		// sender is not propagated onto dto.EvaluateResult by
		// design (raw addresses are deliberately not carried
		// past the originating EvaluateRequest, see
		// dto/evaluate.go). Downstream correlation can join on
		// MessageID / CorrelationID instead.
	}
	if res.LinkScore != nil {
		v := *res.LinkScore
		payload.LinkScore = &v
	}
	if res.AttachmentScore != nil {
		v := *res.AttachmentScore
		payload.AttachmentScore = &v
	}
	env := buildEnvelope(p.cfg, res.TenantID, ruleIDForVerdict(res, kind), ruleLevelForTier(res.Tier),
		ruleDescriptionForVerdict(kind, res.Tier), payload)
	eventClass := "email.verdict." + kind
	env.enrichForEngine(
		res.TenantID,
		subj,
		uuid.NewString(),
		eventClass,
		severityForTier(res.Tier),
		engineFieldsForVerdict(payload),
	)
	return p.publish(ctx, subj, res.MessageID, res.CorrelationID, res.TenantID, eventClass, env)
}

// PublishQuarantine implements PlatformPublisher.
func (p *natsPlatformPublisher) PublishQuarantine(ctx context.Context, evt QuarantineEvent) error {
	if evt.TenantID == "" || evt.MessageID == "" {
		return nil
	}
	action := evt.Action
	if action == "" {
		action = QuarantineActionApplied
	}
	subj := p.subject(evt.TenantID, KindQuarantine)
	payload := QuarantinePayload{
		Source:        p.cfg.Source,
		EventType:     "email.quarantine." + action,
		Action:        action,
		MessageID:     evt.MessageID,
		CorrelationID: evt.CorrelationID,
		Tier:          string(evt.Tier),
		Primary:       string(evt.Primary),
		Score:         evt.Score,
		RecipientHash: hashIdentifier(evt.TenantID, evt.Recipient),
		RequestedBy:   evt.RequestedBy,
		At:            time.Now().UTC(),
	}
	level := ruleLevelForTier(evt.Tier)
	if level == 0 {
		level = 10
	}
	desc := fmt.Sprintf("sn360-es: quarantine %s", action)
	env := buildEnvelope(p.cfg, evt.TenantID, ruleIDForQuarantine(action), level, desc, payload)
	eventClass := "email.quarantine." + action
	env.enrichForEngine(
		evt.TenantID,
		subj,
		uuid.NewString(),
		eventClass,
		severityForTier(evt.Tier),
		engineFieldsForQuarantine(payload),
	)
	return p.publish(ctx, subj, evt.MessageID, evt.CorrelationID, evt.TenantID, eventClass, env)
}

// PublishEscalation implements PlatformPublisher.
func (p *natsPlatformPublisher) PublishEscalation(ctx context.Context, action string, ticket *dto.EscalationTicket) error {
	if ticket == nil {
		return nil
	}
	if ticket.TenantID == "" || ticket.TicketID == "" {
		return nil
	}
	if action == "" {
		action = EscalationActionCreated
	}
	subj := p.subject(ticket.TenantID, KindEscalation)
	payload := EscalationPayload{
		Source:        p.cfg.Source,
		EventType:     "email.escalation." + action,
		Action:        action,
		TicketID:      ticket.TicketID,
		Reason:        string(ticket.Reason),
		CreatedAt:     ticket.CreatedAt,
		Outcome:       string(ticket.Outcome),
		ResolvedAt:    nilIfZero(ticket.ResolvedAt),
		ResolverHash:  ticket.ResolverHash,
		MessageID:     ticket.Incident.PseudoMessageID,
		Tier:          ticket.Incident.Tier,
		Category:      ticket.Incident.Category,
		Score:         ticket.Incident.Score,
		AffectedUsers: ticket.Incident.AffectedUserCount,
		DetectedAt:    ticket.Incident.DetectedAt,
		Indicators:    ticket.Incident.Indicators,
		AISummary:     ticket.Incident.AISummary,
	}
	desc := fmt.Sprintf("sn360-es: escalation %s", action)
	level := 12
	env := buildEnvelope(p.cfg, ticket.TenantID, ruleIDForEscalation(action), level, desc, payload)
	eventClass := "email.escalation." + action
	env.enrichForEngine(
		ticket.TenantID,
		subj,
		uuid.NewString(),
		eventClass,
		severityForLevel(level),
		engineFieldsForEscalation(payload),
	)
	return p.publish(ctx, subj, ticket.TicketID, "", ticket.TenantID, eventClass, env)
}

// Close releases the NATS connection. Idempotent.
func (p *natsPlatformPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nc == nil {
		return nil
	}
	if err := p.nc.Drain(); err != nil && !errors.Is(err, nats.ErrConnectionClosed) {
		p.logger.Warn("sn360-es: platform NATS drain failed", slog.Any("error", err))
	}
	p.nc.Close()
	p.nc = nil
	p.js = nil
	return nil
}

// publish marshals env, attaches headers, and PublishMsg's with
// per-call timeout + retry. Errors are logged but only returned to
// the caller for top-level visibility; the bridge MUST NOT block
// downstream email actions on a platform outage — that is why callers
// invoke Publish* fire-and-forget after the local action has
// succeeded, and the implementation also caps Publish at a few
// retries before giving up.
func (p *natsPlatformPublisher) publish(ctx context.Context, subject, msgID, correlationID, tenantID, eventType string, env Envelope) error {
	p.mu.Lock()
	js := p.js
	p.mu.Unlock()
	if js == nil {
		return errors.New("bridge: jetstream not connected")
	}

	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("bridge: marshal envelope: %w", err)
	}

	// Dedup ID: <tenant>:<msg-or-uuid>:<subject>. Using the
	// per-message ID where present means a re-delivery of the same
	// es.evaluate.result that lands on a different sn360-es replica
	// still dedups platform-side (the platform stream's dedup
	// window observes Nats-Msg-Id).
	dedupID := msgID
	if dedupID == "" {
		dedupID = uuid.NewString()
	}
	dedupID = tenantID + ":" + dedupID + ":" + subject

	msg := &nats.Msg{
		Subject: subject,
		Data:    data,
		Header:  nats.Header{},
	}
	msg.Header.Set(jetstream.MsgIDHeader, dedupID)
	msg.Header.Set("message-id", dedupID)
	msg.Header.Set("tenant-id", tenantID)
	if correlationID != "" {
		msg.Header.Set("correlation-id", correlationID)
	}
	msg.Header.Set("event-type", eventType)
	msg.Header.Set("source", p.cfg.Source)
	msg.Header.Set("enqueued-at", time.Now().UTC().Format(time.RFC3339Nano))

	delay := 100 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= p.cfg.PublishRetries; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, p.cfg.PublishTimeout)
		_, perr := js.PublishMsg(callCtx, msg, jetstream.WithMsgID(dedupID))
		cancel()
		if perr == nil {
			return nil
		}
		lastErr = perr
		// Context completion (cancellation or deadline) propagates
		// immediately — no point retrying a parent context that
		// is already gone. Without DeadlineExceeded here, an
		// expired parent would burn through one wasted PublishMsg
		// per remaining attempt (the derived callCtx fires
		// immediately) before the delay-select catches it, which
		// is harmless but wasteful.
		if errors.Is(perr, context.Canceled) || errors.Is(perr, context.DeadlineExceeded) {
			// Only treat the derived deadline as a publish-retry
			// exit when the *parent* ctx is also done — a per-call
			// timeout that fires while the parent is still healthy
			// is a transient wire failure worth retrying.
			if errors.Is(perr, context.DeadlineExceeded) && ctx.Err() == nil {
				// fall through to retry path below
			} else {
				return perr
			}
		}
		// jetstream.ErrNoStreamResponse means there is no stream
		// matching the subject on the target server. That is a
		// hard configuration error and retrying won't fix it.
		if errors.Is(perr, jetstream.ErrNoStreamResponse) {
			p.logger.Warn("sn360-es: platform NATS publish failed — no stream matches subject",
				slog.String("subject", subject),
				slog.String("stream_expected", p.cfg.Stream),
				slog.Any("error", perr))
			return perr
		}
		if attempt < p.cfg.PublishRetries {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			delay *= 2
		}
	}
	p.logger.Warn("sn360-es: platform NATS publish failed after retries",
		slog.String("subject", subject),
		slog.Int("attempts", p.cfg.PublishRetries),
		slog.Any("error", lastErr))
	return fmt.Errorf("bridge: publish %s: %w", subject, lastErr)
}

func (p *natsPlatformPublisher) subject(tenantID, kind string) string {
	return SubjectPrefix + "." + tenantID + "." + kind
}

// --- subject / rule mapping ------------------------------------------------

// isTerminalTier reports whether the bridge should forward a verdict
// for this tier. Only Blocked and HighRisk cross the bridge; lower
// tiers are too noisy and not interesting to the SOC.
func isTerminalTier(t constant.Tier) bool {
	return t == constant.TierBlocked || t == constant.TierHighRisk
}

// kindForVerdict picks the subject suffix from the primary category.
// Malware bucket triggers on attachment-bearing categories or a high
// attachment score even when the primary is not explicitly attachment-
// based, since the platform's malware correlation rule looks at the
// `.malware` subject regardless of the upstream taxonomy.
func kindForVerdict(res *dto.EvaluateResult) string {
	if res == nil {
		return KindPhishing
	}
	switch res.Primary {
	case constant.CategoryBECImpersonation,
		constant.CategoryAccountTakeoverSuspected,
		constant.CategoryVendorCompromise,
		constant.CategoryInvoiceFraud:
		return KindBEC
	case constant.CategorySuspiciousAttachment:
		return KindMalware
	}
	if res.AttachmentScore != nil && *res.AttachmentScore >= 70 {
		return KindMalware
	}
	// Default bucket — covers LIKELY_PHISHING,
	// CREDENTIAL_HARVESTING, LOOKALIKE_DOMAIN, SUSPICIOUS_URL,
	// QR_PHISHING, SCAM_FRAUD, AUTH_FAILED, FIRST_CONTACT_EXTERNAL,
	// and any unknown category that still made it past the
	// terminal-tier gate.
	return KindPhishing
}

// ruleIDForVerdict reserves the 7800–7899 rule-ID range for sn360-es
// bridge events. The numbering convention is:
//
//	7800 phishing+Blocked   7801 phishing+HighRisk
//	7810 bec+Blocked        7811 bec+HighRisk
//	7820 malware+Blocked    7821 malware+HighRisk
//
// Falls back to the kind base ID when the tier is unknown.
func ruleIDForVerdict(res *dto.EvaluateResult, kind string) string {
	base := 7800
	switch kind {
	case KindBEC:
		base = 7810
	case KindMalware:
		base = 7820
	}
	if res != nil && res.Tier == constant.TierHighRisk {
		base++
	}
	return fmt.Sprintf("%d", base)
}

func ruleIDForQuarantine(action string) string {
	switch action {
	case QuarantineActionReleased:
		return "7831"
	default:
		return "7830"
	}
}

func ruleIDForEscalation(action string) string {
	switch action {
	case EscalationActionResolved:
		return "7841"
	default:
		return "7840"
	}
}

// ruleLevelForTier maps verdict tier to a Wazuh-style rule level
// (0-15). The platform's index-policy buckets observe this for ISM
// retention so the values must be high enough to land in the
// `enterprise` policy when set, but low enough that an evaluator
// regression cannot accidentally trip a level-15 page-on-call rule.
func ruleLevelForTier(t constant.Tier) int {
	switch t {
	case constant.TierBlocked:
		return 12
	case constant.TierHighRisk:
		return 8
	default:
		return 0
	}
}

func ruleDescriptionForVerdict(kind string, tier constant.Tier) string {
	return fmt.Sprintf("sn360-es: %s verdict (%s)", kind, tier)
}

// severityForTier maps a verdict tier to the correlation-engine
// severity vocabulary (info|low|medium|high|critical). The
// correlation-engine validator rejects any rule whose `severity`
// is outside that set (see dac.validSeverities), and the engine's
// composite-risk scoring weights rule severity vs. event severity
// — so mismatched values would push every match into the
// medium-bucket regardless of upstream tier.
func severityForTier(t constant.Tier) string {
	switch t {
	case constant.TierBlocked:
		return "critical"
	case constant.TierHighRisk:
		return "high"
	default:
		return "medium"
	}
}

// severityForLevel is the fall-back when a tier-bearing field is
// unavailable (escalation events). It mirrors the bridge's
// ruleLevelForTier mapping in reverse.
func severityForLevel(level int) string {
	switch {
	case level >= 12:
		return "critical"
	case level >= 8:
		return "high"
	case level >= 3:
		return "medium"
	case level > 0:
		return "low"
	default:
		return "info"
	}
}

// engineFieldsForVerdict flattens a VerdictPayload into the
// `fields` map the correlation-engine reads. The keys mirror what
// the engine's bundled rules expect to join on; adding a new
// rule that joins on `link_score` would require the corresponding
// entry to be present here.
func engineFieldsForVerdict(p EvaluationPayload) map[string]any {
	fields := map[string]any{
		"message_id":     p.MessageID,
		"correlation_id": p.CorrelationID,
		"tier":           p.Tier,
		"primary":        p.Primary,
		"score":          p.Score,
		"action":         p.Action,
		"event_type":     p.EventType,
		"recipient_hash": p.RecipientHash,
		"sender_hash":    p.SenderHash,
		"degraded":       p.Degraded,
		"source":         p.Source,
	}
	if p.LinkScore != nil {
		fields["link_score"] = *p.LinkScore
	}
	if p.AttachmentScore != nil {
		fields["attachment_score"] = *p.AttachmentScore
	}
	if len(p.Secondary) > 0 {
		fields["secondary"] = p.Secondary
	}
	if len(p.ReasonCodes) > 0 {
		fields["reason_codes"] = p.ReasonCodes
	}
	return fields
}

// engineFieldsForQuarantine flattens a QuarantinePayload into the
// engine `fields` map.
func engineFieldsForQuarantine(p QuarantinePayload) map[string]any {
	return map[string]any{
		"message_id":     p.MessageID,
		"correlation_id": p.CorrelationID,
		"tier":           p.Tier,
		"primary":        p.Primary,
		"score":          p.Score,
		"action":         p.Action,
		"event_type":     p.EventType,
		"recipient_hash": p.RecipientHash,
		"requested_by":   p.RequestedBy,
		"source":         p.Source,
	}
}

// engineFieldsForEscalation flattens an EscalationPayload into the
// engine `fields` map. ticket-id is exposed under the dual name
// `ticket_id` (the canonical platform field) and `message_id`
// (preserves the existing rule corpus that joins email events on
// message_id) when the underlying incident message id is empty;
// most escalation events carry both.
func engineFieldsForEscalation(p EscalationPayload) map[string]any {
	fields := map[string]any{
		"ticket_id":      p.TicketID,
		"message_id":     p.MessageID,
		"tier":           p.Tier,
		"category":       p.Category,
		"score":          p.Score,
		"action":         p.Action,
		"event_type":     p.EventType,
		"reason":         p.Reason,
		"outcome":        p.Outcome,
		"resolver_hash":  p.ResolverHash,
		"affected_users": p.AffectedUsers,
		"source":         p.Source,
	}
	if len(p.Indicators) > 0 {
		fields["indicators"] = p.Indicators
	}
	return fields
}

func categoriesAsStrings(in []constant.Category) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, c := range in {
		out[i] = string(c)
	}
	return out
}

func timeOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

func nilIfZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// hashIdentifier returns a stable SHA-256 fingerprint of the email
// scoped to the tenant. Returns "" if either input is empty. The
// platform's correlation engine uses these hashes to link messages
// from the same actor without ever seeing the raw address.
func hashIdentifier(tenantID, email string) string {
	if tenantID == "" || email == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{':'})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(h.Sum(nil))
}

// --- envelope -------------------------------------------------------------

// Envelope is the platform-side event shape. It is a deliberate
// hybrid: the Wazuh-shaped keys (`@timestamp`, `rule`, `agent`,
// `data`, `cluster_id`) keep the wire byte-for-byte compatible
// with `services/alert-forwarder/internal/indexer.ParseAlert`, and
// the additional top-level keys (`tenant_id`, `subject`,
// `event_id`, `event_class`, `severity`, `timestamp`, `fields`)
// mirror the correlation-engine's `Event` struct
// (services/correlation-engine/internal/engine/engine.go) so the
// SAME JSON document deserialises into BOTH consumers without an
// intermediate translator service:
//
//   - alert-forwarder reads `@timestamp`, `cluster_id`, `rule`,
//     `agent.labels.sn360.tenant_id`, `data` (and ignores the
//     engine-shape keys it doesn't reference).
//   - correlation-engine json.Unmarshals into engine.Event and
//     reads `tenant_id`, `subject`, `event_id`, `event_class`,
//     `severity`, `timestamp`, `fields` (and ignores the Wazuh
//     keys it doesn't reference).
//
// The `fields` block is the load-bearing addition: the engine's
// `joinValueFor` extracts join-key values from ev.Fields, so any
// rule that joins on `recipient_hash` / `sender_hash` /
// `message_id` / `correlation_id` must see those keys promoted out
// of `data` and into a flat `fields` map. Without that promotion
// every join_value would be the empty string and every multi-
// source rule would either match nothing or merge unrelated events
// into one huge pending bucket.
type Envelope struct {
	// Wazuh-envelope keys (alert-forwarder).
	Timestamp time.Time `json:"@timestamp"`
	ClusterID string    `json:"cluster_id,omitempty"`
	Rule      Rule      `json:"rule"`
	Agent     Agent     `json:"agent"`
	Data      any       `json:"data,omitempty"`

	// engine.Event keys (correlation-engine). All `omitempty` so
	// the envelope JSON remains compatible with any legacy
	// consumer that only reads the Wazuh keys.
	TenantID        string         `json:"tenant_id,omitempty"`
	Subject         string         `json:"subject,omitempty"`
	EventID         string         `json:"event_id,omitempty"`
	EventClass      string         `json:"event_class,omitempty"`
	Severity        string         `json:"severity,omitempty"`
	EngineTimestamp time.Time      `json:"timestamp,omitempty"`
	Fields          map[string]any `json:"fields,omitempty"`
}

// enrichForEngine populates the correlation-engine Event-shape
// fields on an already-built envelope. Idempotent. Callers pass
// the values they want to expose to multi-source rules in the
// `fields` map; common entries are recipient_hash, sender_hash,
// message_id, correlation_id, tier, primary, score, reason_codes.
// Empty entries are dropped so the wire stays compact and so a
// rule joining on e.g. sender_hash does NOT match every event
// where the value happens to be the empty string.
func (e *Envelope) enrichForEngine(tenantID, subject, eventID, eventClass, severity string, fields map[string]any) {
	e.TenantID = tenantID
	e.Subject = subject
	e.EventID = eventID
	e.EventClass = eventClass
	e.Severity = severity
	e.EngineTimestamp = e.Timestamp
	if len(fields) == 0 {
		return
	}
	clean := make(map[string]any, len(fields))
	for k, v := range fields {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		clean[k] = v
	}
	if len(clean) > 0 {
		e.Fields = clean
	}
}

// Rule mirrors Wazuh's rule block. Only the fields the platform's
// indexer template explicitly maps are surfaced; the rest are left
// to OpenSearch's dynamic mapping.
type Rule struct {
	ID          string `json:"id"`
	Level       int    `json:"level"`
	Description string `json:"description,omitempty"`
}

// Agent mirrors Wazuh's agent block. `labels.sn360.tenant_id` is
// the field the alert-forwarder reads to route alerts to the
// per-tenant index, so the bridge must always populate it.
type Agent struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Labels Labels `json:"labels"`
}

// Labels is the agent labels block. Only the sn360 sub-block matters
// to the bridge.
type Labels struct {
	SN360 SN360Labels `json:"sn360"`
}

// SN360Labels carries the per-tenant routing metadata.
type SN360Labels struct {
	TenantID  string `json:"tenant_id"`
	ClusterID string `json:"cluster_id,omitempty"`
}

// EvaluationPayload is the `data` block for verdict events.
type EvaluationPayload struct {
	Source           string    `json:"source"`
	EventType        string    `json:"event_type"`
	Action           string    `json:"action"`
	MessageID        string    `json:"message_id"`
	CorrelationID    string    `json:"correlation_id,omitempty"`
	Tier             string    `json:"tier"`
	Primary          string    `json:"primary,omitempty"`
	Secondary        []string  `json:"secondary,omitempty"`
	Score            int       `json:"score"`
	LinkScore        *int      `json:"link_score,omitempty"`
	AttachmentScore  *int      `json:"attachment_score,omitempty"`
	ReasonCodes      []string  `json:"reason_codes,omitempty"`
	EvaluatedAt      time.Time `json:"evaluated_at"`
	Degraded         bool      `json:"degraded,omitempty"`
	DegradedServices []string  `json:"degraded_services,omitempty"`
	RecipientHash    string    `json:"recipient_hash,omitempty"`
	SenderHash       string    `json:"sender_hash,omitempty"`
}

// QuarantinePayload is the `data` block for quarantine events.
type QuarantinePayload struct {
	Source        string    `json:"source"`
	EventType     string    `json:"event_type"`
	Action        string    `json:"action"`
	MessageID     string    `json:"message_id"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Tier          string    `json:"tier,omitempty"`
	Primary       string    `json:"primary,omitempty"`
	Score         int       `json:"score,omitempty"`
	RecipientHash string    `json:"recipient_hash,omitempty"`
	RequestedBy   string    `json:"requested_by,omitempty"`
	At            time.Time `json:"at"`
}

// EscalationPayload is the `data` block for escalation events.
type EscalationPayload struct {
	Source        string     `json:"source"`
	EventType     string     `json:"event_type"`
	Action        string     `json:"action"`
	TicketID      string     `json:"ticket_id"`
	Reason        string     `json:"reason,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	Outcome       string     `json:"outcome,omitempty"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
	ResolverHash  string     `json:"resolver_hash,omitempty"`
	MessageID     string     `json:"message_id,omitempty"`
	Tier          string     `json:"tier,omitempty"`
	Category      string     `json:"category,omitempty"`
	Score         float64    `json:"score,omitempty"`
	AffectedUsers int        `json:"affected_users,omitempty"`
	DetectedAt    time.Time  `json:"detected_at,omitempty"`
	Indicators    []string   `json:"indicators,omitempty"`
	AISummary     string     `json:"ai_summary,omitempty"`
}

// buildEnvelope wraps the per-event payload in the platform's
// alert-shaped envelope, hard-coding the routing labels so the
// alert-forwarder can pick them up without translation.
func buildEnvelope(cfg Config, tenantID, ruleID string, ruleLevel int, ruleDesc string, payload any) Envelope {
	return Envelope{
		Timestamp: time.Now().UTC(),
		ClusterID: cfg.ClusterID,
		Rule: Rule{
			ID:          ruleID,
			Level:       ruleLevel,
			Description: ruleDesc,
		},
		Agent: Agent{
			ID:   cfg.Source,
			Name: cfg.Source,
			Labels: Labels{
				SN360: SN360Labels{
					TenantID:  tenantID,
					ClusterID: cfg.ClusterID,
				},
			},
		},
		Data: payload,
	}
}

// --- disabled (no-op) implementation --------------------------------------

// Disabled returns a PlatformPublisher whose methods all no-op. Used
// when the bridge is gated off via PLATFORM_NATS_ENABLED=false (the
// default for standalone deployments) so call sites can call
// publisher.Publish* without nil-checks.
func Disabled() PlatformPublisher {
	return disabledPublisher{}
}

type disabledPublisher struct{}

func (disabledPublisher) PublishEvaluation(context.Context, *dto.EvaluateResult) error { return nil }
func (disabledPublisher) PublishQuarantine(context.Context, QuarantineEvent) error     { return nil }
func (disabledPublisher) PublishEscalation(context.Context, string, *dto.EscalationTicket) error {
	return nil
}
func (disabledPublisher) Close() error { return nil }
