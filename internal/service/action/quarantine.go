package action

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// QuarantineLabelName is the canonical hidden Gmail label / Outlook
// folder name used for Blocked-tier messages. It mirrors the format
// used by the LabelApplier so audit traces look consistent.
const QuarantineLabelName = "SN360 / Blocked"

// QuarantineStubBody is the placeholder body injected when a message
// is quarantined. The recipient sees this stub instead of the
// original content and can tap the banner's "Why?" action to learn
// more or request a release via the AI Support Agent.
const QuarantineStubBody = "This message was blocked by SN360. Tap Why? for details."

// QuarantineProvider is the per-mailbox surface the quarantine
// service drives. Implementations live under
// `pkg/email_provider/*` and translate the abstract requests into
// Gmail labels.modify / Outlook moveMessage calls.
type QuarantineProvider interface {
	Kind() LabelProviderKind
	// EnsureQuarantineLabel creates the hidden quarantine label or
	// folder in the user's mailbox if it does not exist and returns
	// its provider-side ID. The label MUST be hidden from the user
	// (Gmail messageListVisibility=hide / Outlook category color
	// "none").
	EnsureQuarantineLabel(ctx context.Context, email string) (id string, err error)
	// MoveToQuarantine attaches the quarantine label to messageID
	// and applies the body stub. Implementations should also remove
	// any prior INBOX / Focused-Inbox markers so the message
	// disappears from the user's primary view.
	MoveToQuarantine(ctx context.Context, email, messageID, quarantineLabelID, stubBody string) error
	// RestoreFromQuarantine removes the quarantine label, restores
	// the message into the inbox, and replaces the stub body with
	// the original (or, when the caller passes the empty string, a
	// short release receipt).
	RestoreFromQuarantine(ctx context.Context, email, messageID, quarantineLabelID, restoredBody string) error
}

// QuarantineStore persists the encrypted reference to a quarantined
// message so the release flow can locate it later. Only the
// provider-side message ID is stored — not the original content.
//
// The interface is the minimal slice of pkg/storage/redis.Client the
// quarantine service needs, so tests can use an in-memory fake.
type QuarantineStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, bool, error)
	Del(ctx context.Context, keys ...string) error
	// GetDel atomically reads and removes the key. Returns
	// (value, true, nil) when the key existed, ("", false, nil) when
	// it was already absent, and ("", false, err) on transport
	// failures. Used by ClaimReference to fence concurrent release
	// flows so a split-brain Redis lock cannot cause two restorers
	// to mutate the same provider message.
	GetDel(ctx context.Context, key string) (string, bool, error)
}

// QuarantineEncryptor encrypts and decrypts the persisted message
// reference. `pkg/privacy.Encryptor` satisfies the interface.
type QuarantineEncryptor interface {
	Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, tenantID string, ciphertext []byte) ([]byte, error)
}

// QuarantineRecord is the canonical payload persisted under the
// pseudonymised message key. It carries provider/email/message-id so
// the release flow can locate the message later without contacting
// the management plane.
type QuarantineRecord struct {
	Provider     LabelProviderKind `json:"provider"`
	Email        string            `json:"email"`
	MessageID    string            `json:"message_id"`
	Tenant       string            `json:"tenant"`
	LabelID      string            `json:"label_id"`
	OriginalTier constant.Tier     `json:"original_tier"`
	Primary      constant.Category `json:"primary"`
	QuarantineAt time.Time         `json:"quarantined_at"`
}

// QuarantinePublisher is the minimal contract the quarantine service
// needs from the event bus. The concrete events.EventService
// satisfies it; tests can plug a fake in.
type QuarantinePublisher interface {
	Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error
}

// QuarantineConfig wires the quarantine service's dependencies and
// tunables.
type QuarantineConfig struct {
	Logger    *slog.Logger
	Providers []QuarantineProvider
	Store     QuarantineStore
	Encryptor QuarantineEncryptor
	Publisher QuarantinePublisher
	// TTL is the lifetime of the encrypted reference in the store.
	// Defaults to 30 days when zero.
	TTL time.Duration
	// AppliedSubject is the NATS subject used for "quarantine
	// applied" events. Defaults to "es.action.quarantine.applied".
	AppliedSubject string
}

// QuarantineService moves Blocked-tier messages into a hidden
// provider folder, replaces the body with a stub, and persists an
// encrypted reference so the release flow can re-evaluate and
// restore them later.
type QuarantineService struct {
	logger    *slog.Logger
	providers map[LabelProviderKind]QuarantineProvider
	store     QuarantineStore
	encryptor QuarantineEncryptor
	publisher QuarantinePublisher
	ttl       time.Duration
	subject   string
}

// NewQuarantineService constructs a QuarantineService. store and
// encryptor are required; publishers and providers may be empty for
// tests that exercise the local behaviour only.
func NewQuarantineService(cfg QuarantineConfig) (*QuarantineService, error) {
	if cfg.Store == nil {
		return nil, errors.New("quarantine: store is required")
	}
	if cfg.Encryptor == nil {
		return nil, errors.New("quarantine: encryptor is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	provMap := make(map[LabelProviderKind]QuarantineProvider, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if p == nil {
			continue
		}
		provMap[p.Kind()] = p
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	subject := cfg.AppliedSubject
	if subject == "" {
		subject = "es.action.quarantine.applied"
	}
	return &QuarantineService{
		logger:    logger,
		providers: provMap,
		store:     cfg.Store,
		encryptor: cfg.Encryptor,
		publisher: cfg.Publisher,
		ttl:       ttl,
		subject:   subject,
	}, nil
}

// QuarantineRequest carries the inputs for a single quarantine pass.
// PseudonymizedMessage is the privacy-safe key used to look up the
// record on release.
type QuarantineRequest struct {
	Tenant               string
	PseudonymizedMessage string
	Provider             LabelProviderKind
	Email                string
	MessageID            string
	Tier                 constant.Tier
	Primary              constant.Category
}

// Quarantine moves a message into the hidden quarantine label and
// persists an encrypted reference. The request must be for a Blocked-
// tier message; other tiers return an error so callers cannot
// accidentally quarantine soft-warning mail.
func (s *QuarantineService) Quarantine(ctx context.Context, req QuarantineRequest) (QuarantineRecord, error) {
	if req.Tenant == "" || req.Email == "" || req.MessageID == "" {
		return QuarantineRecord{}, errors.New("quarantine: tenant, email and message_id are required")
	}
	if req.PseudonymizedMessage == "" {
		return QuarantineRecord{}, errors.New("quarantine: pseudonymized message id is required")
	}
	if !req.Tier.IsBlocking() {
		return QuarantineRecord{}, fmt.Errorf("quarantine: tier %q is not blocking", req.Tier)
	}
	prov, ok := s.providers[req.Provider]
	if !ok {
		return QuarantineRecord{}, fmt.Errorf("quarantine: no provider registered for %q", req.Provider)
	}

	labelID, err := prov.EnsureQuarantineLabel(ctx, req.Email)
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine: ensure label: %w", err)
	}
	if err := prov.MoveToQuarantine(ctx, req.Email, req.MessageID, labelID, QuarantineStubBody); err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine: move: %w", err)
	}

	rec := QuarantineRecord{
		Provider:     req.Provider,
		Email:        req.Email,
		MessageID:    req.MessageID,
		Tenant:       req.Tenant,
		LabelID:      labelID,
		OriginalTier: req.Tier,
		Primary:      req.Primary,
		QuarantineAt: time.Now().UTC(),
	}
	if err := s.persist(ctx, req.Tenant, req.PseudonymizedMessage, rec); err != nil {
		return rec, fmt.Errorf("quarantine: persist: %w", err)
	}
	if s.publisher != nil {
		payload, err := json.Marshal(struct {
			TenantID             string            `json:"tenant_id"`
			PseudonymizedMessage string            `json:"pseudonymized_message_id"`
			Provider             LabelProviderKind `json:"provider"`
			Tier                 constant.Tier     `json:"tier"`
			Primary              constant.Category `json:"primary"`
			QuarantineAt         time.Time         `json:"quarantined_at"`
		}{
			TenantID:             req.Tenant,
			PseudonymizedMessage: req.PseudonymizedMessage,
			Provider:             req.Provider,
			Tier:                 req.Tier,
			Primary:              req.Primary,
			QuarantineAt:         rec.QuarantineAt,
		})
		if err != nil {
			s.logger.WarnContext(ctx, "quarantine: marshal applied event", slog.Any("error", err))
		} else if err := s.publisher.Publish(ctx, s.subject, payload,
			events.WithEventType("action.quarantine.applied"),
			events.WithTenantID(req.Tenant),
			events.WithMessageID(req.PseudonymizedMessage),
		); err != nil {
			// Publishing is best-effort; the quarantine itself is
			// already applied to the mailbox, so we degrade.
			s.logger.WarnContext(ctx, "quarantine: publish applied event", slog.Any("error", err))
		}
	}
	s.logger.InfoContext(ctx, "action.quarantine applied",
		slog.String("tenant_id", req.Tenant),
		slog.String("provider", string(req.Provider)),
		slog.String("tier", string(req.Tier)),
		slog.String("primary", string(req.Primary)),
	)
	return rec, nil
}

// LookupReference retrieves the QuarantineRecord previously stored
// for the (tenant, pseudonymizedMessage) tuple. Returns false when no
// record exists.
func (s *QuarantineService) LookupReference(ctx context.Context, tenant, pseudoMessage string) (QuarantineRecord, bool, error) {
	encHex, ok, err := s.store.Get(ctx, QuarantineKey(tenant, pseudoMessage))
	if err != nil {
		return QuarantineRecord{}, false, fmt.Errorf("quarantine: store get: %w", err)
	}
	if !ok {
		return QuarantineRecord{}, false, nil
	}
	enc, err := hex.DecodeString(encHex)
	if err != nil {
		return QuarantineRecord{}, false, fmt.Errorf("quarantine: hex decode: %w", err)
	}
	plain, err := s.encryptor.Decrypt(ctx, tenant, enc)
	if err != nil {
		return QuarantineRecord{}, false, fmt.Errorf("quarantine: decrypt: %w", err)
	}
	var rec QuarantineRecord
	if err := json.Unmarshal(plain, &rec); err != nil {
		return QuarantineRecord{}, false, fmt.Errorf("quarantine: unmarshal: %w", err)
	}
	return rec, true, nil
}

// Provider returns the registered provider for kind. Used by the
// release flow to restore messages.
func (s *QuarantineService) Provider(kind LabelProviderKind) (QuarantineProvider, bool) {
	p, ok := s.providers[kind]
	return p, ok
}

// ClearReference removes the stored record. Called after a release
// completes so the encrypted blob no longer sits in Redis.
func (s *QuarantineService) ClearReference(ctx context.Context, tenant, pseudoMessage string) error {
	if err := s.store.Del(ctx, QuarantineKey(tenant, pseudoMessage)); err != nil {
		return fmt.Errorf("quarantine: store del: %w", err)
	}
	return nil
}

// ClaimReference atomically reads-and-deletes the stored reference.
//
// This is the application-layer fencing primitive that defends the
// release flow against split-brain Redis locks (see
// pkg/storage/redis/lock.go's package doc). Two concurrent release
// flows that both passed the Reevaluate gate race to ClaimReference:
// only one wins (claimed=true), the loser sees claimed=false and
// short-circuits without calling RestoreFromQuarantine — so a
// safety-critical phishing email cannot be unblocked twice from a
// single quarantine event even if the surrounding lock fails to
// arbitrate.
//
// On success the encrypted blob is gone from Redis. If the caller
// fails AFTER claiming (typically: provider RestoreFromQuarantine
// errors) it must call RestoreReference to re-persist the record so
// a subsequent release attempt can retry.
//
// Failure handling between GETDEL and the successful unmarshal of
// rec is symmetric with the post-claim provider-failure path: if
// decode / decrypt / unmarshal fails AFTER the atomic GETDEL has
// already removed the key, we re-`Set` the original encrypted hex
// back into the store so the data is not lost on what is otherwise
// expected to be a transient or near-impossible error (LookupReference
// just successfully decoded the same blob). The re-persist is
// best-effort — if it itself fails we surface the original decode
// error joined with the re-persist error so an operator sees both.
func (s *QuarantineService) ClaimReference(ctx context.Context, tenant, pseudoMessage string) (QuarantineRecord, bool, error) {
	key := QuarantineKey(tenant, pseudoMessage)
	encHex, ok, err := s.store.GetDel(ctx, key)
	if err != nil {
		return QuarantineRecord{}, false, fmt.Errorf("quarantine: store getdel: %w", err)
	}
	if !ok {
		return QuarantineRecord{}, false, nil
	}
	// repersist writes the raw encrypted hex back under key with
	// the same TTL the original blob had. Used to restore the
	// store to its pre-GETDEL state when a downstream step on the
	// hot path (decode/decrypt/unmarshal) fails — i.e. when we
	// hold a value we can't interpret but have already removed
	// from Redis. Without this, a one-off decrypt blip would
	// permanently strand the reference.
	repersist := func(decodeErr error, op string) (QuarantineRecord, bool, error) {
		setCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if perr := s.store.Set(setCtx, key, encHex, s.ttl); perr != nil {
			return QuarantineRecord{}, false, fmt.Errorf("quarantine: %s: %w (repersist also failed: %v)", op, decodeErr, perr)
		}
		return QuarantineRecord{}, false, fmt.Errorf("quarantine: %s: %w", op, decodeErr)
	}
	enc, err := hex.DecodeString(encHex)
	if err != nil {
		return repersist(err, "hex decode")
	}
	plain, err := s.encryptor.Decrypt(ctx, tenant, enc)
	if err != nil {
		return repersist(err, "decrypt")
	}
	var rec QuarantineRecord
	if err := json.Unmarshal(plain, &rec); err != nil {
		return repersist(err, "unmarshal")
	}
	return rec, true, nil
}

// RestoreReference re-persists a claimed record. Used by the release
// flow when the post-claim provider call fails so a later attempt
// can retry. Re-persistence reuses the encrypt-and-set path so the
// payload round-trips through the encryptor exactly as the original
// quarantine did.
func (s *QuarantineService) RestoreReference(ctx context.Context, tenant, pseudoMessage string, rec QuarantineRecord) error {
	return s.persist(ctx, tenant, pseudoMessage, rec)
}

// persist encrypts rec and stores it under QuarantineKey.
func (s *QuarantineService) persist(ctx context.Context, tenant, pseudoMessage string, rec QuarantineRecord) error {
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	enc, err := s.encryptor.Encrypt(ctx, tenant, payload)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err := s.store.Set(ctx, QuarantineKey(tenant, pseudoMessage), hex.EncodeToString(enc), s.ttl); err != nil {
		return fmt.Errorf("store set: %w", err)
	}
	return nil
}

// QuarantineKey returns the canonical Redis key for the stored
// reference. Format: `quarantine:{tenant}:{pseudoMessage}`. Exposed
// so the release flow can compose the key without a service round-
// trip.
func QuarantineKey(tenant, pseudoMessage string) string {
	return "quarantine:" + tenant + ":" + pseudoMessage
}
