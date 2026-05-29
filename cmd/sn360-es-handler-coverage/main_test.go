package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
