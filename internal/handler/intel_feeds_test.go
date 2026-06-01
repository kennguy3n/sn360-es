package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/pkg/intel"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// adminCtx seeds the request context with an admin_api claim.
// Tests that exercise unauthorized paths call this with an empty
// scope.
func adminCtx(ctx context.Context, scope string) context.Context {
	return middleware.ContextWithClaims(ctx, &privacy.ActionClaims{
		TenantID: "tenant-1",
		Scope:    scope,
	})
}

type fakeRefresher struct {
	called string
	upsert int
	err    error
}

func (f *fakeRefresher) PollFeed(_ context.Context, id string) (int, error) {
	f.called = id
	return f.upsert, f.err
}

func newTestHandler(refresher IntelFeedRefresher) (*IntelFeedsHandler, *repository.MemoryIntelStore) {
	store := repository.NewMemoryIntelStore()
	h := NewIntelFeedsHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), store, refresher)
	return h, store
}

func TestIntelFeeds_CreateAndList(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(nil)

	body := `{"name":"urlhaus-recent","provider":"urlhaus","url":"https://urlhaus.haus.fail/downloads/csv_recent/"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/intel/feeds", bytes.NewReader([]byte(body)))
	req = req.WithContext(adminCtx(req.Context(), privacy.ScopeAdminAPI))
	rec := httptest.NewRecorder()
	h.ServeFeeds(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/intel/feeds", nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	listRec := httptest.NewRecorder()
	h.ServeFeeds(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: status %d body %s", listRec.Code, listRec.Body.String())
	}
	var got feedListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if len(got.Feeds) != 1 || got.Feeds[0].Name != "urlhaus-recent" {
		t.Errorf("unexpected feed list: %+v", got)
	}
}

func TestIntelFeeds_CreateConflict(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(nil)
	body := `{"name":"dup","provider":"csv","url":"https://example.com/x.csv"}`
	for i, want := range []int{http.StatusCreated, http.StatusConflict} {
		req := httptest.NewRequest(http.MethodPost, "/v1/intel/feeds", bytes.NewReader([]byte(body)))
		req = req.WithContext(adminCtx(req.Context(), privacy.ScopeAdminAPI))
		rec := httptest.NewRecorder()
		h.ServeFeeds(rec, req)
		if rec.Code != want {
			t.Fatalf("iteration %d: status %d; want %d (body=%s)", i, rec.Code, want, rec.Body.String())
		}
	}
}

func TestIntelFeeds_CreateValidation(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(nil)
	cases := []struct {
		body   string
		status int
	}{
		{``, http.StatusBadRequest},                                       // empty body
		{`{`, http.StatusBadRequest},                                      // invalid JSON
		{`{"name":"a","provider":"csv","url":""}`, http.StatusBadRequest}, // missing url
		{`{"name":"a","provider":"","url":"https://e/x"}`, http.StatusBadRequest},
		{`{"name":"a","provider":"csv","url":"https://e/x","foo":1}`, http.StatusBadRequest}, // unknown field
		// fetch_interval_sec must be >= 60 when supplied (OpenAPI
		// minimum). Zero/omitted falls through to the 15-minute
		// default. A 30s value would let the worker re-poll on
		// every tick and get the deployment rate-limited.
		{`{"name":"a","provider":"csv","url":"https://e/x","fetch_interval_sec":30}`, http.StatusBadRequest},
		{`{"name":"a","provider":"csv","url":"https://e/x","fetch_interval_sec":-5}`, http.StatusBadRequest},
		{`{"name":"a","provider":"csv","url":"https://e/x","fetch_interval_sec":1}`, http.StatusBadRequest},
	}
	for i, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/v1/intel/feeds", bytes.NewReader([]byte(c.body)))
		req = req.WithContext(adminCtx(req.Context(), privacy.ScopeAdminAPI))
		rec := httptest.NewRecorder()
		h.ServeFeeds(rec, req)
		if rec.Code != c.status {
			t.Errorf("case %d: status %d; want %d (body=%s)", i, rec.Code, c.status, rec.Body.String())
		}
	}
}

// TestIntelFeeds_PatchValidation exercises the
// fetch_interval_sec >= 60 guard on the PATCH path. Without this
// validator a PATCH {"fetch_interval_sec": 0} would pin nextDue at
// exactly LastFetchedAt and the worker would hammer the upstream
// provider once per tick.
func TestIntelFeeds_PatchValidation(t *testing.T) {
	t.Parallel()
	h, store := newTestHandler(nil)
	feed, err := store.CreateFeed(context.Background(), intel.Feed{
		Name: "csv-a", Provider: "csv", URL: "https://e/x.csv",
		FetchInterval: 10 * time.Minute, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	cases := []struct {
		name   string
		body   string
		status int
	}{
		{"zero", `{"fetch_interval_sec":0}`, http.StatusBadRequest},
		{"negative", `{"fetch_interval_sec":-1}`, http.StatusBadRequest},
		{"below_minimum", `{"fetch_interval_sec":30}`, http.StatusBadRequest},
		{"exact_minimum_ok", `{"fetch_interval_sec":60}`, http.StatusOK},
		{"large_ok", `{"fetch_interval_sec":86400}`, http.StatusOK},
		// URL guards: PgIntelStore would have rejected the empty
		// string via the CHECK (length(url) > 0) constraint on
		// intel_feeds (returning a 500) and stored the whitespace-
		// only one; MemoryIntelStore would accept either silently.
		// The handler trims+validates so both backends produce the
		// same 400 in this case.
		{"url_empty", `{"url":""}`, http.StatusBadRequest},
		{"url_whitespace_only", `{"url":"   "}`, http.StatusBadRequest},
		{"url_valid", `{"url":"https://example.com/new.csv"}`, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch,
				"/v1/intel/feeds/"+feed.ID,
				bytes.NewReader([]byte(c.body)))
			req = req.WithContext(adminCtx(req.Context(), privacy.ScopeAdminAPI))
			rec := httptest.NewRecorder()
			h.ServeFeeds(rec, req)
			if rec.Code != c.status {
				t.Errorf("status %d; want %d (body=%s)",
					rec.Code, c.status, rec.Body.String())
			}
		})
	}
}

func TestIntelFeeds_PatchAndDelete(t *testing.T) {
	t.Parallel()
	h, store := newTestHandler(nil)
	feed, err := store.CreateFeed(context.Background(), intel.Feed{
		Name: "csv-a", Provider: "csv", URL: "https://e/x.csv",
		FetchInterval: 10 * time.Minute, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// PATCH disable
	patchBody := `{"enabled":false,"fetch_interval_sec":600}`
	patchReq := httptest.NewRequest(http.MethodPatch, "/v1/intel/feeds/"+feed.ID, bytes.NewReader([]byte(patchBody)))
	patchReq = patchReq.WithContext(adminCtx(patchReq.Context(), privacy.ScopeAdminAPI))
	patchRec := httptest.NewRecorder()
	h.ServeFeeds(patchRec, patchReq)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("patch: status %d body %s", patchRec.Code, patchRec.Body.String())
	}
	var patched feedAPI
	if err := json.Unmarshal(patchRec.Body.Bytes(), &patched); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if patched.Enabled || patched.FetchIntervalSec != 600 {
		t.Errorf("patch result wrong: %+v", patched)
	}

	// DELETE
	delReq := httptest.NewRequest(http.MethodDelete, "/v1/intel/feeds/"+feed.ID, nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	delRec := httptest.NewRecorder()
	h.ServeFeeds(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d", delRec.Code)
	}

	// DELETE again -> 404
	delAgain := httptest.NewRequest(http.MethodDelete, "/v1/intel/feeds/"+feed.ID, nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	delAgainRec := httptest.NewRecorder()
	h.ServeFeeds(delAgainRec, delAgain)
	if delAgainRec.Code != http.StatusNotFound {
		t.Errorf("delete-again: status %d; want 404", delAgainRec.Code)
	}
}

func TestIntelFeeds_RefreshDispatches(t *testing.T) {
	t.Parallel()
	refresher := &fakeRefresher{upsert: 7}
	h, store := newTestHandler(refresher)
	feed, err := store.CreateFeed(context.Background(), intel.Feed{
		Name: "u", Provider: "urlhaus", URL: "https://e/x",
		FetchInterval: 10 * time.Minute, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/intel/feeds/"+feed.ID+"/refresh", nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	rec := httptest.NewRecorder()
	h.ServeFeeds(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: status %d body %s", rec.Code, rec.Body.String())
	}
	if refresher.called != feed.ID {
		t.Errorf("refresher.PollFeed not invoked with %q (got %q)", feed.ID, refresher.called)
	}
	var resp refreshResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.IndicatorsUpserted != 7 {
		t.Errorf("upserted = %d; want 7", resp.IndicatorsUpserted)
	}
}

func TestIntelFeeds_RefreshUnavailable(t *testing.T) {
	t.Parallel()
	h, store := newTestHandler(nil)
	feed, _ := store.CreateFeed(context.Background(), intel.Feed{
		Name: "u2", Provider: "csv", URL: "https://e/x",
		FetchInterval: 10 * time.Minute, Enabled: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/intel/feeds/"+feed.ID+"/refresh", nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	rec := httptest.NewRecorder()
	h.ServeFeeds(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d; want 501 (refresher nil)", rec.Code)
	}
}

func TestIntelFeeds_RefreshUpstreamError(t *testing.T) {
	t.Parallel()
	refresher := &fakeRefresher{err: errors.New("upstream 500")}
	h, store := newTestHandler(refresher)
	feed, _ := store.CreateFeed(context.Background(), intel.Feed{
		Name: "u3", Provider: "csv", URL: "https://e/x",
		FetchInterval: 10 * time.Minute, Enabled: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/intel/feeds/"+feed.ID+"/refresh", nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	rec := httptest.NewRecorder()
	h.ServeFeeds(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d; want 502", rec.Code)
	}
}

func TestIntelFeeds_Indicators(t *testing.T) {
	t.Parallel()
	h, store := newTestHandler(nil)
	feed, _ := store.CreateFeed(context.Background(), intel.Feed{
		Name: "f1", Provider: "csv", URL: "https://e/x.csv",
		FetchInterval: 5 * time.Minute, Enabled: true,
	})
	hash, _ := intel.HashIndicator(intel.IndicatorDomain, "evil.example")
	if _, err := store.UpsertIndicators(context.Background(), feed.ID, []intel.Indicator{
		{Indicator: "evil.example", Type: intel.IndicatorDomain, Hash: hash, Severity: 80},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/intel/indicators?indicator=evil.example", nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	rec := httptest.NewRecorder()
	h.ServeIndicators(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var resp indicatorLookupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Matches) == 0 || resp.Matches[0].Severity != 80 {
		t.Errorf("unexpected match payload: %+v", resp)
	}
}

func TestIntelFeeds_ForbiddenWithoutScope(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(nil)
	// Wrong scope -> 403
	req := httptest.NewRequest(http.MethodGet, "/v1/intel/feeds", nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeBannerAction))
	rec := httptest.NewRecorder()
	h.ServeFeeds(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong scope: status = %d; want 403", rec.Code)
	}
	// No claims -> 401
	noClaims := httptest.NewRequest(http.MethodGet, "/v1/intel/feeds", nil)
	noClaimsRec := httptest.NewRecorder()
	h.ServeFeeds(noClaimsRec, noClaims)
	if noClaimsRec.Code != http.StatusUnauthorized {
		t.Errorf("no claims: status = %d; want 401", noClaimsRec.Code)
	}
}

func TestIntelFeeds_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(nil)
	req := httptest.NewRequest(http.MethodPut, "/v1/intel/feeds", nil).
		WithContext(adminCtx(context.Background(), privacy.ScopeAdminAPI))
	rec := httptest.NewRecorder()
	h.ServeFeeds(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got == "" {
		t.Error("Allow header missing")
	}
}
