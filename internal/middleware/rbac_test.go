package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// withClaims is the test-only helper that mirrors what JWTAuth does
// in production: stamp a verified ActionClaims onto the request
// context so RBAC has a principal to authorise. Keeping this
// separate from any real JWT issuance lets the RBAC tests focus on
// the role-decision surface without re-testing token signing. Uses
// the public ContextWithClaims helper so the test path matches the
// trust contract exposed to external callers.
func withClaims(req *http.Request, role string) *http.Request {
	claims := &privacy.ActionClaims{TenantID: "t1", Role: role}
	return req.WithContext(ContextWithClaims(req.Context(), claims))
}

// readReason decodes the {"error","reason"} body the gate emits on
// rejection. Used by every negative test below.
func readReason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return body["reason"]
}

// TestRequireRole_MatrixAcceptsAndRejects pins the full 4×4 matrix:
// each of the four canonical roles tried against each of three
// representative allow-lists, plus the empty-claims and
// unknown-role cases. Without this, an off-by-one in the role
// lookup map would silently allow a viewer to hit
// RequireRole(admin, operator) — and that is the exact misconfig
// the gate exists to prevent.
func TestRequireRole_MatrixAcceptsAndRejects(t *testing.T) {
	type row struct {
		name         string
		allowedRoles []string
		principal    string // role on JWT
		wantStatus   int
		wantReason   string // "" when accepted
	}
	rows := []row{
		// admin allow-list (write actions)
		{"admin allows admin", []string{privacy.RoleAdmin}, privacy.RoleAdmin, http.StatusOK, ""},
		{"admin denies operator", []string{privacy.RoleAdmin}, privacy.RoleOperator, http.StatusForbidden, "forbidden_role"},
		{"admin denies viewer", []string{privacy.RoleAdmin}, privacy.RoleViewer, http.StatusForbidden, "forbidden_role"},
		{"admin denies end_user", []string{privacy.RoleAdmin}, privacy.RoleEndUser, http.StatusForbidden, "forbidden_role"},
		// admin+operator allow-list (operator-equivalent write actions)
		{"admin+op allows admin", []string{privacy.RoleAdmin, privacy.RoleOperator}, privacy.RoleAdmin, http.StatusOK, ""},
		{"admin+op allows operator", []string{privacy.RoleAdmin, privacy.RoleOperator}, privacy.RoleOperator, http.StatusOK, ""},
		{"admin+op denies viewer", []string{privacy.RoleAdmin, privacy.RoleOperator}, privacy.RoleViewer, http.StatusForbidden, "forbidden_role"},
		{"admin+op denies end_user", []string{privacy.RoleAdmin, privacy.RoleOperator}, privacy.RoleEndUser, http.StatusForbidden, "forbidden_role"},
		// admin+operator+viewer (read actions)
		{"reader allows admin", []string{privacy.RoleAdmin, privacy.RoleOperator, privacy.RoleViewer}, privacy.RoleAdmin, http.StatusOK, ""},
		{"reader allows operator", []string{privacy.RoleAdmin, privacy.RoleOperator, privacy.RoleViewer}, privacy.RoleOperator, http.StatusOK, ""},
		{"reader allows viewer", []string{privacy.RoleAdmin, privacy.RoleOperator, privacy.RoleViewer}, privacy.RoleViewer, http.StatusOK, ""},
		{"reader denies end_user", []string{privacy.RoleAdmin, privacy.RoleOperator, privacy.RoleViewer}, privacy.RoleEndUser, http.StatusForbidden, "forbidden_role"},
		// edge: unknown / empty role on a valid-looking token
		{"reader denies empty role", []string{privacy.RoleAdmin, privacy.RoleOperator, privacy.RoleViewer}, "", http.StatusForbidden, "forbidden_role"},
		{"reader denies unknown role", []string{privacy.RoleAdmin, privacy.RoleOperator, privacy.RoleViewer}, "root", http.StatusForbidden, "forbidden_role"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			mw := RequireRole(tc.allowedRoles...)(next)
			req := withClaims(httptest.NewRequest(http.MethodGet, "/v1/test", nil), tc.principal)
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status: got %d want %d body=%q", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantReason != "" && readReason(t, rec) != tc.wantReason {
				t.Fatalf("reason: got %q want %q", readReason(t, rec), tc.wantReason)
			}
		})
	}
}

// TestRequireRole_NoClaimsIs401 pins the JWT-not-ran path. If a
// request hits the RBAC gate without verified claims (misordered
// middleware, broken wiring) the gate must refuse it. 401 is the
// correct shape because the failure is "no principal" rather than
// "wrong principal".
func TestRequireRole_NoClaimsIs401(t *testing.T) {
	mw := RequireRole(privacy.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d (expected 401)", rec.Code)
	}
	if readReason(t, rec) != "missing_role_claim" {
		t.Fatalf("reason=%q", readReason(t, rec))
	}
}

// TestRequireRole_PanicsOnUnknownRoleAtWrapTime asserts the boot-time
// guard: a typo'd role string in the call-site (e.g.
// RequireRole("adim")) must panic when the middleware constructor
// runs, not silently 403 every request later. The panic message must
// name the role so the operator can grep for it.
func TestRequireRole_PanicsOnUnknownRoleAtWrapTime(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on unknown role")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "adim") {
			t.Fatalf("panic message must name the bad role: %v", r)
		}
	}()
	_ = RequireRole("adim")
}

// TestRequireRole_SkipPathsBypass pins the skip-paths behaviour. The
// gate must wave through anything that matches an exact path or a
// trailing-slash prefix, even when no claims are present — this is
// the "health probes never role-gate" invariant.
func TestRequireRole_SkipPathsBypass(t *testing.T) {
	mw := RequireRoleWith(
		RequireRoleConfig{SkipPaths: []string{"/healthz", "/docs/"}},
		privacy.RoleAdmin,
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, path := range []string{"/healthz", "/docs/", "/docs/swagger.css"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("path=%s code=%d (expected skip)", path, rec.Code)
		}
	}
	// Non-skipped path with no claims still 401s.
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-skipped: code=%d", rec.Code)
	}
}

// TestRequireRoleByMethod_DispatchesPerMethod pins the per-method
// allow-list shape used by mixed-verb routes like `/v1/vendors`.
// GET maps to a reader list (admin, operator, viewer), POST maps to
// a writer list (admin, operator). The test walks every method ×
// role combination so a regression that accidentally OR's the
// per-method maps together would surface immediately.
func TestRequireRoleByMethod_DispatchesPerMethod(t *testing.T) {
	mw := RequireRoleByMethod(map[string][]string{
		http.MethodGet:  {privacy.RoleAdmin, privacy.RoleOperator, privacy.RoleViewer},
		http.MethodPost: {privacy.RoleAdmin, privacy.RoleOperator},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	type row struct {
		method     string
		role       string
		wantStatus int
	}
	rows := []row{
		// GET (read) — viewer allowed
		{http.MethodGet, privacy.RoleAdmin, http.StatusOK},
		{http.MethodGet, privacy.RoleOperator, http.StatusOK},
		{http.MethodGet, privacy.RoleViewer, http.StatusOK},
		{http.MethodGet, privacy.RoleEndUser, http.StatusForbidden},
		// POST (write) — viewer denied
		{http.MethodPost, privacy.RoleAdmin, http.StatusOK},
		{http.MethodPost, privacy.RoleOperator, http.StatusOK},
		{http.MethodPost, privacy.RoleViewer, http.StatusForbidden},
		{http.MethodPost, privacy.RoleEndUser, http.StatusForbidden},
		// DELETE not in table at all — 403 (method_not_in_role_table)
		{http.MethodDelete, privacy.RoleAdmin, http.StatusForbidden},
	}
	for _, tc := range rows {
		req := withClaims(httptest.NewRequest(tc.method, "/v1/vendors", nil), tc.role)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s %s: code=%d want=%d body=%q", tc.method, tc.role, rec.Code, tc.wantStatus, rec.Body.String())
		}
	}
}

// TestRequireRoleByMethod_MethodNotInTable surfaces the "method
// missing from the RBAC table" failure with a specific reason code
// so an operator can distinguish it from an ordinary forbidden_role
// in a 403 storm.
func TestRequireRoleByMethod_MethodNotInTable(t *testing.T) {
	mw := RequireRoleByMethod(map[string][]string{
		http.MethodGet: {privacy.RoleAdmin},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := withClaims(httptest.NewRequest(http.MethodPatch, "/v1/test", nil), privacy.RoleAdmin)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
	if readReason(t, rec) != "method_not_in_role_table" {
		t.Fatalf("reason=%q", readReason(t, rec))
	}
}

// TestRequireRoleByMethod_AuthBeforeMethodTable pins the 401-vs-403
// ordering contract added in response to PR #51 Devin Review
// finding 0001. An unauthenticated request that ALSO uses a method
// not in the role table must surface as 401 (missing_role_claim),
// not 403 (method_not_in_role_table) — because the latter would
// leak the shape of the RBAC table (specifically, which methods
// the route DOES enforce) to a caller we can't even identify.
// Authenticated callers continue to see method_not_in_role_table
// because at that point the leak is irrelevant: they're already
// past the auth gate, and the distinct reason code helps operators
// debug 403 storms.
func TestRequireRoleByMethod_AuthBeforeMethodTable(t *testing.T) {
	mw := RequireRoleByMethod(map[string][]string{
		http.MethodGet: {privacy.RoleAdmin},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Unauthenticated + method-not-in-table → 401, not 403.
	req := httptest.NewRequest(http.MethodPatch, "/v1/test", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth + bad method: code=%d (expected 401)", rec.Code)
	}
	if got := readReason(t, rec); got != "missing_role_claim" {
		t.Fatalf("unauth + bad method: reason=%q (expected missing_role_claim)", got)
	}
	// Authenticated + method-not-in-table → 403
	// method_not_in_role_table (unchanged contract).
	req = withClaims(httptest.NewRequest(http.MethodPatch, "/v1/test", nil), privacy.RoleAdmin)
	rec = httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auth + bad method: code=%d (expected 403)", rec.Code)
	}
	if got := readReason(t, rec); got != "method_not_in_role_table" {
		t.Fatalf("auth + bad method: reason=%q (expected method_not_in_role_table)", got)
	}
}
