package action

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// fakeQStore is an in-memory implementation of QuarantineStore.
type fakeQStore struct {
	mu   sync.Mutex
	data map[string]string
	ttls map[string]time.Duration
}

func newFakeQStore() *fakeQStore {
	return &fakeQStore{data: map[string]string{}, ttls: map[string]time.Duration{}}
}

func (s *fakeQStore) Set(_ context.Context, k, v string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[k] = v
	s.ttls[k] = ttl
	return nil
}

func (s *fakeQStore) Get(_ context.Context, k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[k]
	return v, ok, nil
}

func (s *fakeQStore) Del(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		delete(s.data, k)
		delete(s.ttls, k)
	}
	return nil
}

func (s *fakeQStore) GetDel(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return "", false, nil
	}
	delete(s.data, key)
	delete(s.ttls, key)
	return v, true, nil
}

// fakeQEncryptor xors with a 1-byte key derived from tenant id. Not
// secure — only used to exercise encrypt/decrypt round-trips in
// tests deterministically.
type fakeQEncryptor struct{}

func (fakeQEncryptor) Encrypt(_ context.Context, tenant string, plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	k := byte(0xa5)
	if len(tenant) > 0 {
		k ^= tenant[0]
	}
	for i, b := range plaintext {
		out[i] = b ^ k
	}
	return out, nil
}

func (e fakeQEncryptor) Decrypt(ctx context.Context, tenant string, ciphertext []byte) ([]byte, error) {
	return e.Encrypt(ctx, tenant, ciphertext)
}

// fakeQProvider records every call so tests can assert the protocol.
type fakeQProvider struct {
	mu           sync.Mutex
	kind         LabelProviderKind
	labelID      string
	ensureCalls  []string
	moveCalls    []moveCall
	restoreCalls []restoreCall
	ensureErr    error
	moveErr      error
	restoreErr   error
}

type moveCall struct {
	email     string
	messageID string
	labelID   string
	body      string
}

type restoreCall struct {
	email     string
	messageID string
	labelID   string
	body      string
}

func newFakeQProvider(kind LabelProviderKind, labelID string) *fakeQProvider {
	return &fakeQProvider{kind: kind, labelID: labelID}
}

func (p *fakeQProvider) Kind() LabelProviderKind { return p.kind }

func (p *fakeQProvider) EnsureQuarantineLabel(_ context.Context, email string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensureCalls = append(p.ensureCalls, email)
	if p.ensureErr != nil {
		return "", p.ensureErr
	}
	return p.labelID, nil
}

func (p *fakeQProvider) MoveToQuarantine(_ context.Context, email, messageID, labelID, body string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.moveCalls = append(p.moveCalls, moveCall{email, messageID, labelID, body})
	return p.moveErr
}

func (p *fakeQProvider) RestoreFromQuarantine(_ context.Context, email, messageID, labelID, body string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.restoreCalls = append(p.restoreCalls, restoreCall{email, messageID, labelID, body})
	return p.restoreErr
}

// recordingPublisher captures every published event.
type recordingPublisher struct {
	mu     sync.Mutex
	events []recordedEvent
	err    error
}

type recordedEvent struct {
	subject string
	data    []byte
}

func (p *recordingPublisher) Publish(_ context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, recordedEvent{subject: subject, data: append([]byte(nil), data...)})
	return p.err
}

func (p *recordingPublisher) lastSubject() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.events) == 0 {
		return ""
	}
	return p.events[len(p.events)-1].subject
}

func newQuarantineForTest(t *testing.T, prov *fakeQProvider, pub *recordingPublisher) (*QuarantineService, *fakeQStore) {
	t.Helper()
	store := newFakeQStore()
	svc, err := NewQuarantineService(QuarantineConfig{
		Providers: []QuarantineProvider{prov},
		Store:     store,
		Encryptor: fakeQEncryptor{},
		Publisher: pub,
	})
	if err != nil {
		t.Fatalf("NewQuarantineService: %v", err)
	}
	return svc, store
}

func TestQuarantine_AppliesAndPersists(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_42")
	pub := &recordingPublisher{}
	svc, store := newQuarantineForTest(t, prov, pub)

	req := QuarantineRequest{
		Tenant:               "acme",
		PseudonymizedMessage: "msg-abc",
		Provider:             LabelProviderGmail,
		Email:                "user@acme.com",
		MessageID:            "raw-1",
		Tier:                 constant.TierBlocked,
		Primary:              constant.CategoryLikelyPhishing,
	}
	rec, err := svc.Quarantine(ctx, req)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if rec.LabelID != "Label_42" {
		t.Fatalf("LabelID: got %q want Label_42", rec.LabelID)
	}
	if rec.OriginalTier != constant.TierBlocked {
		t.Fatalf("OriginalTier: got %q", rec.OriginalTier)
	}
	if len(prov.moveCalls) != 1 {
		t.Fatalf("expected 1 move call, got %d", len(prov.moveCalls))
	}
	if prov.moveCalls[0].body != QuarantineStubBody {
		t.Fatalf("stub body mismatch: %q", prov.moveCalls[0].body)
	}

	// Stored value must round-trip via decryption.
	raw, ok, err := store.Get(ctx, QuarantineKey("acme", "msg-abc"))
	if err != nil || !ok {
		t.Fatalf("store get: ok=%v err=%v", ok, err)
	}
	enc, _ := hex.DecodeString(raw)
	plain, err := (fakeQEncryptor{}).Decrypt(ctx, "acme", enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var back QuarantineRecord
	if err := json.Unmarshal(plain, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.MessageID != "raw-1" {
		t.Fatalf("decoded record: %+v", back)
	}

	// Lookup should succeed via the service.
	got, found, err := svc.LookupReference(ctx, "acme", "msg-abc")
	if err != nil || !found {
		t.Fatalf("LookupReference: found=%v err=%v", found, err)
	}
	if got.MessageID != "raw-1" {
		t.Fatalf("LookupReference returned %+v", got)
	}

	// And a quarantine.applied event was emitted.
	if got := pub.lastSubject(); got != "es.action.quarantine.applied" {
		t.Fatalf("event subject: got %q", got)
	}
}

func TestQuarantine_RejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_42")
	svc, _ := newQuarantineForTest(t, prov, &recordingPublisher{})

	cases := []struct {
		name string
		req  QuarantineRequest
	}{
		{"missing tenant", QuarantineRequest{
			PseudonymizedMessage: "m",
			Provider:             LabelProviderGmail,
			Email:                "u@e.com",
			MessageID:            "raw",
			Tier:                 constant.TierBlocked,
		}},
		{"missing pseudonym", QuarantineRequest{
			Tenant:    "t",
			Provider:  LabelProviderGmail,
			Email:     "u@e.com",
			MessageID: "raw",
			Tier:      constant.TierBlocked,
		}},
		{"non-blocking tier", QuarantineRequest{
			Tenant:               "t",
			PseudonymizedMessage: "m",
			Provider:             LabelProviderGmail,
			Email:                "u@e.com",
			MessageID:            "raw",
			Tier:                 constant.TierWarning,
		}},
		{"unknown provider", QuarantineRequest{
			Tenant:               "t",
			PseudonymizedMessage: "m",
			Provider:             LabelProviderKind("imap"),
			Email:                "u@e.com",
			MessageID:            "raw",
			Tier:                 constant.TierBlocked,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Quarantine(ctx, tc.req); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestQuarantine_LookupMissingReturnsFalse(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_42")
	svc, _ := newQuarantineForTest(t, prov, &recordingPublisher{})
	_, found, err := svc.LookupReference(ctx, "acme", "missing")
	if err != nil {
		t.Fatalf("LookupReference err: %v", err)
	}
	if found {
		t.Fatal("expected not-found")
	}
}

func TestQuarantine_ProviderEnsureFailureSurfacesError(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "")
	prov.ensureErr = errors.New("ensure failed")
	svc, _ := newQuarantineForTest(t, prov, &recordingPublisher{})
	_, err := svc.Quarantine(ctx, QuarantineRequest{
		Tenant:               "t",
		PseudonymizedMessage: "m",
		Provider:             LabelProviderGmail,
		Email:                "u@e.com",
		MessageID:            "raw",
		Tier:                 constant.TierBlocked,
	})
	if err == nil {
		t.Fatal("expected error from ensure")
	}
}

// failingDecryptor is a QuarantineEncryptor whose Decrypt always
// returns an error. Used to exercise the ClaimReference re-persist
// symmetry on decrypt failure without needing to corrupt the store
// out-of-band.
type failingDecryptor struct{}

func (failingDecryptor) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (failingDecryptor) Decrypt(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errors.New("decrypt: simulated KMS failure")
}

// TestQuarantine_ClaimReferenceRepersistsOnHexFailure asserts that
// when ClaimReference's hex.DecodeString fails AFTER the atomic
// GETDEL has already removed the key, the raw encHex is written
// back to the store so the reference is not stranded. This is the
// symmetry guarantee with the post-claim provider-fail recovery
// path (which calls RestoreReference) — both error categories
// leave the store in the same pre-claim state so a retry can
// succeed.
func TestQuarantine_ClaimReferenceRepersistsOnHexFailure(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_42")
	svc, store := newQuarantineForTest(t, prov, &recordingPublisher{})

	// Write a non-hex value directly into the store so the hex
	// decode inside ClaimReference fails. The pre-condition is
	// that the key exists — the actual content shape is irrelevant
	// because we expect Claim to abort before decryption.
	key := QuarantineKey("acme", "garbled")
	const corrupt = "zzzz-not-hex-zzzz"
	if err := store.Set(ctx, key, corrupt, time.Hour); err != nil {
		t.Fatalf("store.Set: %v", err)
	}

	_, claimed, err := svc.ClaimReference(ctx, "acme", "garbled")
	if err == nil {
		t.Fatal("ClaimReference: expected error, got nil")
	}
	if claimed {
		t.Fatal("ClaimReference: expected claimed=false, got true")
	}

	// Symmetry guarantee: the encrypted blob must still be
	// readable from the store after the failed claim, with the
	// exact value we wrote.
	got, found, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("post-claim store.Get: %v", err)
	}
	if !found {
		t.Fatal("post-claim store.Get: key was not re-persisted after decode failure")
	}
	if got != corrupt {
		t.Fatalf("post-claim store.Get: got %q, want %q (re-persist must preserve original blob byte-for-byte)", got, corrupt)
	}
}

// TestQuarantine_ClaimReferenceRepersistsOnDecryptFailure asserts
// the same symmetry guarantee for the decrypt failure branch — the
// most plausible production failure (transient KMS outage,
// rotated-out key, etc.) must not strand a quarantined message.
func TestQuarantine_ClaimReferenceRepersistsOnDecryptFailure(t *testing.T) {
	ctx := context.Background()
	prov := newFakeQProvider(LabelProviderGmail, "Label_42")
	store := newFakeQStore()
	svc, err := NewQuarantineService(QuarantineConfig{
		Providers: []QuarantineProvider{prov},
		Store:     store,
		Encryptor: failingDecryptor{},
		Publisher: &recordingPublisher{},
	})
	if err != nil {
		t.Fatalf("NewQuarantineService: %v", err)
	}

	// Pre-populate the store with a hex-valid blob so Claim
	// proceeds past hex decode and fails inside Decrypt.
	key := QuarantineKey("acme", "msg-decrypt")
	const blobHex = "deadbeef"
	if err := store.Set(ctx, key, blobHex, time.Hour); err != nil {
		t.Fatalf("store.Set: %v", err)
	}

	_, claimed, err := svc.ClaimReference(ctx, "acme", "msg-decrypt")
	if err == nil {
		t.Fatal("ClaimReference: expected error, got nil")
	}
	if claimed {
		t.Fatal("ClaimReference: expected claimed=false, got true")
	}

	got, found, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("post-claim store.Get: %v", err)
	}
	if !found {
		t.Fatal("post-claim store.Get: key was not re-persisted after decrypt failure")
	}
	if got != blobHex {
		t.Fatalf("post-claim store.Get: got %q, want %q", got, blobHex)
	}
}
