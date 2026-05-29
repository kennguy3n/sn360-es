package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// writeTemp wraps the boilerplate of dropping a file into t.TempDir.
func writeTemp(t *testing.T, name, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestLoadSpecPaths(t *testing.T) {
	body := `openapi: 3.0.0
info: {title: x, version: 0}
paths:
  /v1/foo:
    get: {responses: {"200": {description: ok}}}
  /v1/bar/{id}:
    get: {responses: {"200": {description: ok}}}
`
	got, err := loadSpecPaths(writeTemp(t, "spec.yaml", body))
	if err != nil {
		t.Fatalf("loadSpecPaths: %v", err)
	}
	want := []string{"/v1/bar/{id}", "/v1/foo"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

func TestLoadGoRoutes(t *testing.T) {
	body := `package main
import "net/http"
func wire(mux *http.ServeMux) {
	mux.HandleFunc("/v1/foo", func(http.ResponseWriter, *http.Request) {})
	mux.Handle("/v1/bar/", http.NotFoundHandler())
}
`
	got, err := loadGoRoutes(writeTemp(t, "routes.go", body))
	if err != nil {
		t.Fatalf("loadGoRoutes: %v", err)
	}
	want := []string{"/v1/bar/", "/v1/foo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

func TestLoadGoRoutes_IgnoresNonLiteralPath(t *testing.T) {
	body := `package main
import "net/http"
const route = "/v1/dyn"
func wire(mux *http.ServeMux) {
	mux.HandleFunc(route, nil)
	mux.HandleFunc("/v1/literal", nil)
}
`
	got, err := loadGoRoutes(writeTemp(t, "r.go", body))
	if err != nil {
		t.Fatalf("loadGoRoutes: %v", err)
	}
	want := []string{"/v1/literal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got=%v want=%v (const-named routes deliberately skipped)", got, want)
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/v1/foo", "/v1/foo"},
		{"/v1/foo/", "/v1/foo/"},
		{"/v1/foo/{id}", "/v1/foo/"},
		{"/v1/foo/{id}/x", "/v1/foo/"},
		{"/v1/{tenant}/foo", "/v1/"},
	}
	for _, c := range cases {
		if got := normalize(c.in); got != c.want {
			t.Errorf("normalize(%q)=%q; want %q", c.in, got, c.want)
		}
	}
}

func TestDiff_ExactMatchVsPrefixMatch(t *testing.T) {
	a := map[string]struct{}{"/": {}, "/v1/foo": {}, "/healthz": {}}
	b := map[string]struct{}{"/v1/foo": {}}
	// "/" goes via allowOnlyInGoExact -- prefix matching it would
	// allow-list every route under "/", which would defeat the gate.
	got := diff(a, b, []string{"/healthz"}, map[string]struct{}{"/": {}})
	if len(got) != 0 {
		t.Errorf("diff=%v; want empty (/ exact-allowed, /healthz prefix-allowed)", got)
	}
}

func TestDiff_ExactAllowDoesNotShadowDescendant(t *testing.T) {
	// Regression: an earlier prototype used a single prefix-list
	// containing "/" which (correctly under HasPrefix) matched
	// EVERY route, silently passing the gate. The split between
	// prefix and exact allow-lists exists precisely to prevent this.
	a := map[string]struct{}{"/v1/secret": {}}
	b := map[string]struct{}{}
	got := diff(a, b, nil, map[string]struct{}{"/": {}})
	want := []string{"/v1/secret"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diff=%v; want %v (exact / must NOT mask /v1/secret)", got, want)
	}
}

// TestLoadGoRoutes_StripsGo122MethodPrefix locks in the Go 1.22+
// method-pattern support. The stdlib ServeMux accepts patterns like
// `GET /v1/foo`; the gate must strip the method+space prefix so the
// remaining path matches the OpenAPI form. Without this, every
// method-pattern route would falsely appear "missing from spec".
func TestLoadGoRoutes_StripsGo122MethodPrefix(t *testing.T) {
	body := `package main
import "net/http"
func wire(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/users", nil)
	mux.HandleFunc("POST /v1/users", nil)
	mux.HandleFunc("DELETE /v1/users/{id}", nil)
	mux.HandleFunc("PATCH /v1/users/{id}", nil)
	mux.Handle("OPTIONS /v1/users", nil)
}
`
	got, err := loadGoRoutes(writeTemp(t, "r.go", body))
	if err != nil {
		t.Fatalf("loadGoRoutes: %v", err)
	}
	// Methods are stripped; multiple methods on the same path
	// produce duplicate entries — that is fine because loadGoRoutes
	// is the raw extractor and normalizeSet de-duplicates downstream.
	want := []string{
		"/v1/users", "/v1/users", "/v1/users",
		"/v1/users/{id}", "/v1/users/{id}",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got=%v want=%v", got, want)
	}
}

// TestStripMethodPrefix exhaustively pins the method-prefix
// stripping behaviour: every recognised stdlib HTTP method is
// stripped, an unrecognised pseudo-method is left alone, and a path
// that happens to contain a space without a method prefix is also
// left alone.
func TestStripMethodPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"GET /v1/foo", "/v1/foo"},
		{"HEAD /v1/foo", "/v1/foo"},
		{"POST /v1/foo", "/v1/foo"},
		{"PUT /v1/foo", "/v1/foo"},
		{"PATCH /v1/foo", "/v1/foo"},
		{"DELETE /v1/foo", "/v1/foo"},
		{"OPTIONS /v1/foo", "/v1/foo"},
		{"CONNECT /v1/foo", "/v1/foo"},
		{"TRACE /v1/foo", "/v1/foo"},
		{"/v1/foo", "/v1/foo"},             // no prefix; unchanged
		{"PURGE /v1/foo", "PURGE /v1/foo"}, // non-stdlib method; unchanged
		{"/v1/foo bar", "/v1/foo bar"},     // path contains space; unchanged
	}
	for _, c := range cases {
		if got := stripMethodPrefix(c.in); got != c.want {
			t.Errorf("stripMethodPrefix(%q)=%q; want %q", c.in, got, c.want)
		}
	}
}

// TestDiff_AllowOnlyInSpecExactMatch locks in the exact-match
// semantics of allowOnlyInSpec (the parameter passed as `allowExact`
// when checking the spec->go direction). Adding `/v1/foo` must NOT
// allow-list `/v1/foobar`.
func TestDiff_AllowOnlyInSpecExactMatch(t *testing.T) {
	a := map[string]struct{}{"/v1/foo": {}, "/v1/foobar": {}}
	b := map[string]struct{}{}
	got := diff(a, b, nil, map[string]struct{}{"/v1/foo": {}})
	want := []string{"/v1/foobar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diff=%v; want %v (allowOnlyInSpec must be exact-match, not prefix)", got, want)
	}
}

// TestAllowOnlyInGoPrefixes_SubtreeEntriesEndInSlash locks in the
// rule that subtree allow-list entries MUST end in `/` so a bare
// prefix like `/v1/push` cannot accidentally allow-list an
// unrelated future route like `/v1/pushback`. Exact-route entries
// (`/healthz`, `/metrics`, `/openapi.yaml`) are exempt because
// they're registered as exact routes in routes.go, not as
// subtrees.
func TestAllowOnlyInGoPrefixes_SubtreeEntriesEndInSlash(t *testing.T) {
	// Entries that legitimately match exact routes (file-style
	// endpoints). Any other entry MUST end in `/`.
	exactExempt := map[string]struct{}{
		"/healthz":      {},
		"/readyz":       {},
		"/metrics":      {},
		"/docs":         {}, // routes.go registers both /docs and /docs/
		"/openapi.yaml": {},
	}
	for _, p := range allowOnlyInGoPrefixes {
		if _, ok := exactExempt[p]; ok {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			t.Errorf("allowOnlyInGoPrefixes contains bare prefix %q; subtree entries must end in `/` to avoid over-matching (see ANALYSIS_0002, round 2)", p)
		}
	}
}

// TestLoadGoRoutes_UnquoteHandlesBacktickStrings verifies the
// switch to strconv.Unquote correctly handles both quoted-string
// forms (double-quoted and back-ticked) for route literals, where
// the previous manual-stripping implementation had no escape-
// sequence support. Routes in this codebase don't currently use
// escapes, but the test pins the contract for future maintainers.
func TestLoadGoRoutes_UnquoteHandlesBacktickStrings(t *testing.T) {
	tmp := t.TempDir() + "/routes.go"
	src := "package main\n" +
		"import \"net/http\"\n" +
		"func wire(mux *http.ServeMux) {\n" +
		"\tmux.Handle(\"/v1/double\", nil)\n" +
		"\tmux.Handle(`/v1/backtick`, nil)\n" +
		"}\n"
	if err := os.WriteFile(tmp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadGoRoutes(tmp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/v1/backtick", "/v1/double"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("loadGoRoutes=%v; want %v", got, want)
	}
}
