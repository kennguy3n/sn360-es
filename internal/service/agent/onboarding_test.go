package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// stubDirectory is a deterministic DirectoryClient.
type stubDirectory struct {
	users  []DiscoveredUser
	groups []DiscoveredGroup
	usrErr error
	grpErr error
}

func (s stubDirectory) ListUsers(_ context.Context, _ string) ([]DiscoveredUser, error) {
	return s.users, s.usrErr
}

func (s stubDirectory) ListGroups(_ context.Context, _ string) ([]DiscoveredGroup, error) {
	return s.groups, s.grpErr
}

// recordingLabels records EnsureTierLabels calls.
type recordingLabels struct {
	mu       sync.Mutex
	calls    []string
	fail     map[string]error
}

func newRecordingLabels() *recordingLabels {
	return &recordingLabels{fail: map[string]error{}}
}

func (r *recordingLabels) EnsureTierLabels(_ context.Context, _ string, mailbox string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, mailbox)
	return r.fail[mailbox]
}

// recordingPub captures every (subject, payload) the agent publishes.
type recordingPub struct {
	mu       sync.Mutex
	subjects []string
	data     [][]byte
}

func (p *recordingPub) Publish(_ context.Context, subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	p.data = append(p.data, append([]byte(nil), data...))
	return nil
}

// recordingAudit records every audit entry written.
type recordingAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *recordingAudit) Record(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

// recordingConfig records weight/threshold updates.
type recordingConfig struct {
	mu         sync.Mutex
	weights    []ScoreWeights
	thresholds []Thresholds
}

func (c *recordingConfig) UpdateWeights(_ context.Context, _ string, w ScoreWeights) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.weights = append(c.weights, w)
	return nil
}

func (c *recordingConfig) UpdateThresholds(_ context.Context, _ string, t Thresholds) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.thresholds = append(c.thresholds, t)
	return nil
}

// stubVendorScanner returns a canned candidate slice.
type stubVendorScanner struct {
	candidates []VendorCandidate
	err        error
}

func (s stubVendorScanner) ScanRecentSenders(_ context.Context, _ string, _ time.Time) ([]VendorCandidate, error) {
	return s.candidates, s.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewOnboardingAgent_RequiresDirectoryAndLabels(t *testing.T) {
	labels := newRecordingLabels()
	if _, err := NewOnboardingAgent(OnboardingConfig{Labels: labels, Logger: discardLogger()}); err == nil {
		t.Fatal("expected error when Directory is nil")
	}
	if _, err := NewOnboardingAgent(OnboardingConfig{Directory: stubDirectory{}, Logger: discardLogger()}); err == nil {
		t.Fatal("expected error when Labels is nil")
	}
}

func TestNewOnboardingAgent_AppliesDefaults(t *testing.T) {
	a, err := NewOnboardingAgent(OnboardingConfig{
		Directory: stubDirectory{},
		Labels:    newRecordingLabels(),
		Logger:    discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewOnboardingAgent: %v", err)
	}
	if a.cfg.VendorScanWindow != 30*24*time.Hour {
		t.Fatalf("VendorScanWindow default: %v", a.cfg.VendorScanWindow)
	}
	if a.cfg.MinVendorConfidence != 0.6 {
		t.Fatalf("MinVendorConfidence default: %v", a.cfg.MinVendorConfidence)
	}
	if a.cfg.DefaultWeights.AI != 0.8 || a.cfg.DefaultWeights.Rspamd != 0.2 {
		t.Fatalf("DefaultWeights: %+v", a.cfg.DefaultWeights)
	}
	if a.cfg.DefaultThresholds.BannerBlocked != 85 {
		t.Fatalf("DefaultThresholds.BannerBlocked: %d", a.cfg.DefaultThresholds.BannerBlocked)
	}
}

func TestOnboardingAgent_Onboard_FullFlow(t *testing.T) {
	dir := stubDirectory{
		users: []DiscoveredUser{
			{ID: "u1", Email: "ceo@acme.com", DisplayName: "Alice", JobTitle: "CEO"},
			{ID: "u2", Email: "ap@acme.com", DisplayName: "Bob", JobTitle: "AP Specialist"},
			{ID: "u3", Email: "marketing@acme.com", DisplayName: "Carol", JobTitle: "Marketing"},
			{ID: "u4", Email: "suspended@acme.com", IsSuspended: true},
			{ID: "u5", Email: "", DisplayName: "no-email"},
		},
		groups: []DiscoveredGroup{
			{ID: "g1", Name: "C-suite"},
		},
	}
	labels := newRecordingLabels()
	pub := &recordingPub{}
	audit := &recordingAudit{}
	cfg := &recordingConfig{}
	scanner := stubVendorScanner{
		candidates: []VendorCandidate{
			{Domain: "vendor-a.com", Confidence: 0.9, SeenCount: 25},
			{Domain: "low-conf.com", Confidence: 0.3, SeenCount: 1},
		},
	}
	a, err := NewOnboardingAgent(OnboardingConfig{
		Directory:     dir,
		VendorScanner: scanner,
		Labels:        labels,
		Events:        pub,
		Audit:         audit,
		Config:        cfg,
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewOnboardingAgent: %v", err)
	}
	res, err := a.Onboard(context.Background(), TenantContext{
		TenantID: "acme",
		Provider: ProviderGoogle,
	})
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}
	if res.UsersDiscovered != 5 {
		t.Fatalf("UsersDiscovered: %d", res.UsersDiscovered)
	}
	if res.GroupsDiscovered != 1 {
		t.Fatalf("GroupsDiscovered: %d", res.GroupsDiscovered)
	}
	// Only the 3 non-suspended, non-empty mailboxes get labels.
	if res.LabelsApplied != 3 {
		t.Fatalf("LabelsApplied: %d", res.LabelsApplied)
	}
	if len(labels.calls) != 3 {
		t.Fatalf("labels.calls: %v", labels.calls)
	}
	// Only the high-confidence vendor seeds.
	if res.VendorsSeeded != 1 {
		t.Fatalf("VendorsSeeded: %d", res.VendorsSeeded)
	}
	// One audit row for completion.
	if len(audit.entries) != 1 || audit.entries[0].Action != "onboarding.completed" {
		t.Fatalf("audit: %+v", audit.entries)
	}
	// Config seeded once each.
	if len(cfg.weights) != 1 || len(cfg.thresholds) != 1 {
		t.Fatalf("config seed: w=%d t=%d", len(cfg.weights), len(cfg.thresholds))
	}
	// Events: 3 user.created + 1 vendor.seeded.
	var userEvents, vendorEvents int
	for _, s := range pub.subjects {
		switch s {
		case "es.onboarding.user.created":
			userEvents++
		case "es.onboarding.vendor.seeded":
			vendorEvents++
		}
	}
	if userEvents != 3 || vendorEvents != 1 {
		t.Fatalf("events: user=%d vendor=%d (all=%v)", userEvents, vendorEvents, pub.subjects)
	}
}

func TestOnboardingAgent_Onboard_RejectsInvalidContext(t *testing.T) {
	a, _ := NewOnboardingAgent(OnboardingConfig{
		Directory: stubDirectory{},
		Labels:    newRecordingLabels(),
		Logger:    discardLogger(),
	})
	if _, err := a.Onboard(context.Background(), TenantContext{}); err == nil {
		t.Fatal("expected error for empty context")
	}
}

func TestOnboardingAgent_Onboard_PropagatesDirectoryErrors(t *testing.T) {
	a, _ := NewOnboardingAgent(OnboardingConfig{
		Directory: stubDirectory{usrErr: errors.New("boom")},
		Labels:    newRecordingLabels(),
		Logger:    discardLogger(),
	})
	if _, err := a.Onboard(context.Background(), TenantContext{TenantID: "acme", Provider: ProviderGoogle}); err == nil {
		t.Fatal("expected error from ListUsers failure")
	}
}

func TestOnboardingAgent_Onboard_ContinuesPastLabelFailure(t *testing.T) {
	labels := newRecordingLabels()
	labels.fail["bad@acme.com"] = errors.New("label failure")
	a, _ := NewOnboardingAgent(OnboardingConfig{
		Directory: stubDirectory{
			users: []DiscoveredUser{
				{ID: "u1", Email: "good@acme.com"},
				{ID: "u2", Email: "bad@acme.com"},
			},
		},
		Labels: labels,
		Logger: discardLogger(),
	})
	res, err := a.Onboard(context.Background(), TenantContext{TenantID: "acme", Provider: ProviderGoogle})
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}
	// Only the good mailbox should be counted as applied.
	if res.LabelsApplied != 1 {
		t.Fatalf("LabelsApplied: %d", res.LabelsApplied)
	}
	// Both mailboxes attempted.
	if len(labels.calls) != 2 {
		t.Fatalf("labels.calls: %v", labels.calls)
	}
}

func TestClassifyUserSensitivity(t *testing.T) {
	// Groups that, when matched on a user, propagate keywords into
	// the haystack the classifier scans.
	groups := map[string]DiscoveredGroup{
		"chief": {ID: "chief", Name: "Chief Executive Officers"},
		"hr":    {ID: "hr", Name: "Human Resources Team"},
	}
	cases := []struct {
		name string
		user DiscoveredUser
		want Sensitivity
	}{
		{"CFO title", DiscoveredUser{JobTitle: "CFO"}, SensitivityMax},
		{"founder via display name", DiscoveredUser{DisplayName: "Jane (Founder)"}, SensitivityMax},
		{"chief executive via group", DiscoveredUser{GroupIDs: []string{"chief"}}, SensitivityMax},
		{"finance dept", DiscoveredUser{Department: "Finance"}, SensitivityHigh},
		{"controller", DiscoveredUser{JobTitle: "Controller"}, SensitivityHigh},
		{"human resources via group", DiscoveredUser{GroupIDs: []string{"hr"}}, SensitivityHigh},
		{"legal department", DiscoveredUser{Department: "Legal"}, SensitivityHigh},
		{"exec assistant", DiscoveredUser{JobTitle: "Executive Assistant"}, SensitivityElevated},
		{"procurement", DiscoveredUser{JobTitle: "Procurement Lead"}, SensitivityElevated},
		{"marketing default", DiscoveredUser{JobTitle: "Marketing"}, SensitivityDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyUserSensitivity(tc.user, groups); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestSensitivity_StringLabels(t *testing.T) {
	cases := map[Sensitivity]string{
		SensitivityDefault:  "default",
		SensitivityElevated: "elevated",
		SensitivityHigh:     "high",
		SensitivityMax:      "max",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Fatalf("%d: got %q want %q", s, got, want)
		}
	}
}
