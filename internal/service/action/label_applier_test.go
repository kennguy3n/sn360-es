package action

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// --- Fakes ----------------------------------------------------------------

type memCache struct {
	mu   sync.Mutex
	data map[string]string
	get  func(key string) (string, error)
	set  func(key, value string) error
}

func newMemCache() *memCache {
	return &memCache{data: map[string]string{}}
}

func (c *memCache) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.get != nil {
		return c.get(key)
	}
	if v, ok := c.data[key]; ok {
		return v, nil
	}
	return "", nil
}

func (c *memCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set != nil {
		return c.set(key, value)
	}
	c.data[key] = value
	return nil
}

type providerCall struct {
	op      string // "ensure" | "apply" | "remove"
	email   string
	msg     string
	labelID string
	name    string
	color   LabelColor
}

type fakeLabelProvider struct {
	mu       sync.Mutex
	kind     LabelProviderKind
	ensure   func(email, name string, color LabelColor) (string, error)
	apply    func(email, msg, labelID string) error
	remove   func(email, msg, labelID string) error
	calls    []providerCall
	nextID   int
	ensureBy map[string]string // label name -> id, populated by default ensure
}

func newFakeProvider(kind LabelProviderKind) *fakeLabelProvider {
	return &fakeLabelProvider{kind: kind, ensureBy: map[string]string{}}
}

func (f *fakeLabelProvider) Kind() LabelProviderKind { return f.kind }

func (f *fakeLabelProvider) EnsureLabel(_ context.Context, email, name string, color LabelColor) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, providerCall{op: "ensure", email: email, name: name, color: color})
	if f.ensure != nil {
		return f.ensure(email, name, color)
	}
	if id, ok := f.ensureBy[name]; ok {
		return id, nil
	}
	f.nextID++
	id := name + "-id"
	f.ensureBy[name] = id
	return id, nil
}

func (f *fakeLabelProvider) ApplyLabel(_ context.Context, email, msg, labelID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, providerCall{op: "apply", email: email, msg: msg, labelID: labelID})
	if f.apply != nil {
		return f.apply(email, msg, labelID)
	}
	return nil
}

func (f *fakeLabelProvider) RemoveLabel(_ context.Context, email, msg, labelID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, providerCall{op: "remove", email: email, msg: msg, labelID: labelID})
	if f.remove != nil {
		return f.remove(email, msg, labelID)
	}
	return nil
}

func (f *fakeLabelProvider) callsByOp(op string) []providerCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []providerCall
	for _, c := range f.calls {
		if c.op == op {
			out = append(out, c)
		}
	}
	return out
}

// --- Tests ----------------------------------------------------------------

func TestNewLabelApplier_NilProviderEntriesSkipped(t *testing.T) {
	a := NewLabelApplier(nil, newMemCache(), nil)
	if a == nil {
		t.Fatal("NewLabelApplier returned nil")
	}
	if len(a.providers) != 0 {
		t.Fatalf("nil providers should be skipped: %+v", a.providers)
	}
	if a.logger == nil {
		t.Fatal("default logger not set")
	}
}

func TestApply_RejectsMissingFields(t *testing.T) {
	a := NewLabelApplier(nil, newMemCache(), newFakeProvider(LabelProviderGmail))
	cases := []struct {
		name string
		req  LabelApplyRequest
	}{
		{"empty tenant", LabelApplyRequest{Provider: LabelProviderGmail, Email: "u@x", MessageID: "m", NewTier: constant.TierWarning}},
		{"empty email", LabelApplyRequest{Tenant: "t", Provider: LabelProviderGmail, MessageID: "m", NewTier: constant.TierWarning}},
		{"empty msg", LabelApplyRequest{Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", NewTier: constant.TierWarning}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := a.Apply(context.Background(), c.req); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestApply_RejectsInvalidTier(t *testing.T) {
	a := NewLabelApplier(nil, newMemCache(), newFakeProvider(LabelProviderGmail))
	_, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: "Mango",
	})
	if err == nil {
		t.Fatal("expected error for invalid tier")
	}
}

func TestApply_UnknownProvider(t *testing.T) {
	a := NewLabelApplier(nil, newMemCache(), newFakeProvider(LabelProviderGmail))
	_, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderOutlook, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning,
	})
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestApply_HappyPath_AllTiers_BothProviders(t *testing.T) {
	for _, kind := range []LabelProviderKind{LabelProviderGmail, LabelProviderOutlook} {
		for _, tier := range constant.AllTiers {
			t.Run(string(kind)+"/"+string(tier), func(t *testing.T) {
				cache := newMemCache()
				prov := newFakeProvider(kind)
				a := NewLabelApplier(nil, cache, prov)
				res, err := a.Apply(context.Background(), LabelApplyRequest{
					Tenant: "tenant-1", Provider: kind, Email: "u@x.example",
					MessageID: "msg-1", NewTier: tier,
				})
				if err != nil {
					t.Fatalf("Apply: %v", err)
				}
				wantLabel := tier.LabelName()
				if res.AppliedLabel != wantLabel {
					t.Fatalf("AppliedLabel: got %q want %q", res.AppliedLabel, wantLabel)
				}
				if res.AppliedLabelID == "" {
					t.Fatal("AppliedLabelID is empty")
				}
				// Exactly one ensure + one apply for the tier label, no remove (cache empty).
				if got := len(prov.callsByOp("ensure")); got != 1 {
					t.Fatalf("ensure calls: got %d want 1 (%+v)", got, prov.calls)
				}
				if got := len(prov.callsByOp("apply")); got != 1 {
					t.Fatalf("apply calls: got %d want 1", got)
				}
				if got := len(prov.callsByOp("remove")); got != 0 {
					t.Fatalf("remove calls: got %d want 0", got)
				}
			})
		}
	}
}

func TestApply_PassesProviderTierColor(t *testing.T) {
	prov := newFakeProvider(LabelProviderGmail)
	a := NewLabelApplier(nil, newMemCache(), prov)
	_, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierBlocked,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := ColorFor(constant.TierBlocked)
	ensures := prov.callsByOp("ensure")
	if len(ensures) == 0 || ensures[0].color != want {
		t.Fatalf("ensure color: %+v want %+v", ensures, want)
	}
}

func TestApply_RemovesPreviousTierLabels(t *testing.T) {
	cache := newMemCache()
	// Pre-populate the cache with two stale tier labels (Caution + HighRisk).
	_ = cache.Set(context.Background(),
		cacheKey(LabelProviderGmail, "t", "u@x", constant.TierCaution), "stale-caution", 0)
	_ = cache.Set(context.Background(),
		cacheKey(LabelProviderGmail, "t", "u@x", constant.TierHighRisk), "stale-high", 0)
	prov := newFakeProvider(LabelProviderGmail)
	a := NewLabelApplier(nil, cache, prov)

	res, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res.RemovedLabelIDs) != 2 {
		t.Fatalf("RemovedLabelIDs: %+v", res.RemovedLabelIDs)
	}
	removes := prov.callsByOp("remove")
	if len(removes) != 2 {
		t.Fatalf("remove calls: %+v", removes)
	}
	// Removal must skip the tier we're applying.
	for _, c := range removes {
		if c.labelID == res.AppliedLabelID {
			t.Fatalf("removed the newly-applied tier label")
		}
	}
}

func TestApply_RemovePreviousLabelErrorIsNonFatal(t *testing.T) {
	cache := newMemCache()
	_ = cache.Set(context.Background(),
		cacheKey(LabelProviderGmail, "t", "u@x", constant.TierCaution), "stale", 0)
	prov := newFakeProvider(LabelProviderGmail)
	prov.remove = func(_, _, _ string) error { return errors.New("remove down") }
	a := NewLabelApplier(nil, cache, prov)

	res, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning,
	})
	if err != nil {
		t.Fatalf("remove error should not fail Apply: %v", err)
	}
	if len(res.RemovedLabelIDs) != 0 {
		t.Fatalf("failed removes should not be recorded: %+v", res.RemovedLabelIDs)
	}
}

func TestApply_AppliesSubCategoryForNonBenignCategory(t *testing.T) {
	prov := newFakeProvider(LabelProviderGmail)
	a := NewLabelApplier(nil, newMemCache(), prov)
	res, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning, PrimaryCategory: constant.CategoryLookalikeDomain,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.SubCategoryID == "" {
		t.Fatal("expected sub-category ID to be populated")
	}
	// Sub-label name is derived from the tier label + short category.
	wantSub := constant.TierWarning.LabelName() + " / Lookalike Domain"
	found := false
	for _, c := range prov.callsByOp("ensure") {
		if c.name == wantSub {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("sub-label not ensured: %+v", prov.calls)
	}
}

func TestApply_SkipsSubLabelForBenignCategory(t *testing.T) {
	prov := newFakeProvider(LabelProviderGmail)
	a := NewLabelApplier(nil, newMemCache(), prov)
	res, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierInformational, PrimaryCategory: constant.CategoryNewsletter,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.SubCategoryID != "" {
		t.Fatalf("benign category should not produce sub-label: %q", res.SubCategoryID)
	}
	// Only one ensure for the tier label, no sub-label ensure.
	if got := len(prov.callsByOp("ensure")); got != 1 {
		t.Fatalf("ensure calls: %d want 1", got)
	}
}

func TestApply_SubLabelEnsureErrorIsNonFatal(t *testing.T) {
	prov := newFakeProvider(LabelProviderGmail)
	// Make ensure fail only for the sub-label.
	prov.ensure = func(_, name string, _ LabelColor) (string, error) {
		if name == constant.TierWarning.LabelName() {
			return "tier-id", nil
		}
		return "", errors.New("ensure sub fail")
	}
	a := NewLabelApplier(nil, newMemCache(), prov)
	res, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning, PrimaryCategory: constant.CategoryLikelyPhishing,
	})
	if err != nil {
		t.Fatalf("sub-label error should not fail Apply: %v", err)
	}
	if res.SubCategoryID != "" {
		t.Fatalf("failed sub-label should not populate SubCategoryID: %q", res.SubCategoryID)
	}
}

func TestApply_SubLabelApplyErrorIsNonFatal(t *testing.T) {
	prov := newFakeProvider(LabelProviderGmail)
	prov.apply = func(_, _, labelID string) error {
		// Tier label apply succeeds, sub-label apply fails.
		if labelID == constant.TierWarning.LabelName()+"-id" {
			return nil
		}
		return errors.New("apply sub fail")
	}
	a := NewLabelApplier(nil, newMemCache(), prov)
	res, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning, PrimaryCategory: constant.CategoryLikelyPhishing,
	})
	if err != nil {
		t.Fatalf("sub-label apply error should not fail Apply: %v", err)
	}
	if res.SubCategoryID != "" {
		t.Fatalf("SubCategoryID should not be set when apply fails: %q", res.SubCategoryID)
	}
}

func TestApply_EnsureTierLabelErrorFails(t *testing.T) {
	prov := newFakeProvider(LabelProviderGmail)
	prov.ensure = func(_, _ string, _ LabelColor) (string, error) {
		return "", errors.New("network down")
	}
	a := NewLabelApplier(nil, newMemCache(), prov)
	if _, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning,
	}); err == nil {
		t.Fatal("expected error from ensure")
	}
}

func TestApply_ApplyTierLabelErrorFails(t *testing.T) {
	prov := newFakeProvider(LabelProviderGmail)
	prov.apply = func(_, _, _ string) error { return errors.New("apply down") }
	a := NewLabelApplier(nil, newMemCache(), prov)
	if _, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning,
	}); err == nil {
		t.Fatal("expected apply error")
	}
}

func TestApply_CachesEnsuredLabelIDAcrossCalls(t *testing.T) {
	cache := newMemCache()
	prov := newFakeProvider(LabelProviderGmail)
	a := NewLabelApplier(nil, cache, prov)

	for i := 0; i < 3; i++ {
		if _, err := a.Apply(context.Background(), LabelApplyRequest{
			Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
			NewTier: constant.TierWarning,
		}); err != nil {
			t.Fatalf("Apply #%d: %v", i, err)
		}
	}
	if got := len(prov.callsByOp("ensure")); got != 1 {
		t.Fatalf("ensure called %d times across 3 Apply()s; cache should hit", got)
	}
	if got := len(prov.callsByOp("apply")); got != 3 {
		t.Fatalf("apply calls: %d want 3", got)
	}
}

func TestApply_CacheSetErrorDoesNotFail(t *testing.T) {
	cache := newMemCache()
	cache.set = func(_, _ string) error { return errors.New("redis down") }
	prov := newFakeProvider(LabelProviderGmail)
	a := NewLabelApplier(nil, cache, prov)
	if _, err := a.Apply(context.Background(), LabelApplyRequest{
		Tenant: "t", Provider: LabelProviderGmail, Email: "u@x", MessageID: "m",
		NewTier: constant.TierWarning,
	}); err != nil {
		t.Fatalf("cache set error should not propagate: %v", err)
	}
}

func TestCategoryShortName(t *testing.T) {
	cases := map[constant.Category]string{
		constant.CategoryLikelyPhishing:           "Phishing",
		constant.CategoryBECImpersonation:         "Impersonation",
		constant.CategoryLookalikeDomain:          "Lookalike Domain",
		constant.CategorySuspiciousURL:            "Url",
		constant.CategoryFirstContactExternal:     "External",
		constant.CategoryAccountTakeoverSuspected: "Account Takeover Suspected",
		constant.CategoryVendorCompromise:         "Vendor Compromise",
	}
	for in, want := range cases {
		t.Run(string(in), func(t *testing.T) {
			if got := categoryShortName(in); got != want {
				t.Fatalf("categoryShortName(%q)=%q want %q", in, got, want)
			}
		})
	}
}

func TestCacheKeyFormat(t *testing.T) {
	k := cacheKey(LabelProviderGmail, "tenant-1", "alice@example.com", constant.TierWarning)
	want := "gmail:tenant-1:alice@example.com:label:Warning"
	if k != want {
		t.Fatalf("cacheKey=%q want=%q", k, want)
	}
	kn := cacheKeyNamed(LabelProviderOutlook, "tenant-1", "alice@example.com", "SN360 / Warning / Phishing")
	wantN := "outlook:tenant-1:alice@example.com:labelname:SN360 / Warning / Phishing"
	if kn != wantN {
		t.Fatalf("cacheKeyNamed=%q want=%q", kn, wantN)
	}
}
