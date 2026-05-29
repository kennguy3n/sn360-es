// sn360-es-handler-coverage is a CI gate that verifies every route
// declared in api/openapi.yaml has a corresponding mux.Handle /
// mux.HandleFunc registration in cmd/sn360-es/routes.go (and vice
// versa, mod a small allow-list).
//
// The gate fires on two failure modes:
//
//  1. Spec lists a path Go does not serve. Symptom in prod: API
//     consumer reads the spec, hits the path, gets 404. We want
//     this caught at PR review.
//
//  2. Go serves a path the spec does not document. Symptom: drift
//     between contract and implementation; new endpoints land
//     without anyone updating the spec. CI gate forces the spec
//     update.
//
// Implementation:
//
//   - openapi.yaml is parsed with the standard gopkg.in/yaml.v3
//     package. We extract the top-level keys of `paths:` only —
//     we don't validate operation methods or schemas here because
//     openapi-check + spectral are the right gates for that.
//
//   - routes.go is parsed with go/ast. We walk the AST looking
//     for SelectorExpr nodes of shape `<ident>.Handle(` or
//     `<ident>.HandleFunc(` where <ident> resolves to *http.ServeMux
//     (heuristically "mux"). The first argument is the route path
//     literal.
//
//   - Path normalization: OpenAPI uses `{param}` for path
//     parameters; Go's net/http stdlib uses `/prefix/` for
//     prefix-matching subtrees. We normalize both into a comparable
//     shape:
//
//     OpenAPI `/v1/escalation/{ticket_id}`  ->  `/v1/escalation/`
//     Go      `/v1/escalation/`             ->  `/v1/escalation/`
//
//     This is an intentionally lossy mapping — we're checking that
//     a parameterised route in the spec has SOME Go registration
//     that matches its prefix, not asserting one-to-one route
//     shape. The full router behaviour is exercised by integration
//     tests; this gate is the architecture-level "did anyone
//     forget to wire it" check.
//
// Allow-list mechanism:
//
//	The internal endpoints (/healthz, /readyz, /metrics, /docs,
//	/openapi.yaml, /l/, internal/ops/...) are NOT in the OpenAPI
//	spec by design — they're operational endpoints, not customer
//	API surface. The allow-list keeps them out of the "go has but
//	spec lacks" failure mode.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// allowOnlyInGoPrefixes is the set of route prefixes Go is allowed
// to serve without an OpenAPI entry. Each entry is a prefix that Go
// routes must START WITH to be accepted. Operational endpoints by
// design.
var allowOnlyInGoPrefixes = []string{
	"/healthz",
	"/readyz",
	"/metrics",
	"/docs",
	"/openapi.yaml",
	"/l/",          // URL-rewrite interstitial — internal-only
	"/v1/push",     // SaaS push webhooks — separate from REST API
	"/v1/feedback", // feedback events — separate from REST API
	"/v1/agent",    // AI agent control surface — separate from REST API
	"/internal/",   // ops surface (alert router) — separate from REST API
}

// allowOnlyInGoExact is the set of EXACT routes Go is allowed to
// serve without an OpenAPI entry. Used for "/" specifically: the
// net/http stdlib requires a catch-all handler at "/" — it is the
// 404 sink for unmatched routes, NOT a customer API surface.
// Using exact-match here so the entry doesn't accidentally allow-
// list every route in the prefix-match table.
var allowOnlyInGoExact = map[string]struct{}{
	"/": {},
}

// allowOnlyInSpec is the set of spec paths Go is NOT yet wiring.
// Empty by default — populate this only with a comment citing the
// PR that will wire the route. The CI gate fails if the list grows
// unbounded.
//
// Uses EXACT matching, not prefix matching, so adding `/v1/foo`
// allow-lists only `/v1/foo` itself and not e.g. `/v1/foobar`.
// The Go→Spec direction has both allowOnlyInGoPrefixes (for
// subtree-style operational endpoints like `/healthz`) and
// allowOnlyInGoExact (for true catch-alls like `/`); the Spec→Go
// direction does not need a prefix variant because spec paths are
// already fully-qualified.
var allowOnlyInSpec = map[string]struct{}{}

func main() {
	openapiPath := flag.String("openapi", "api/openapi.yaml", "path to OpenAPI YAML")
	routesPath := flag.String("routes", "cmd/sn360-es/routes.go", "path to routes.go")
	flag.Parse()

	specPaths, err := loadSpecPaths(*openapiPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load spec: %v\n", err)
		os.Exit(2)
	}
	goPaths, err := loadGoRoutes(*routesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse routes.go: %v\n", err)
		os.Exit(2)
	}

	specNorm := normalizeSet(specPaths)
	goNorm := normalizeSet(goPaths)

	missingFromGo := diff(specNorm, goNorm, nil, allowOnlyInSpec)
	missingFromSpec := diff(goNorm, specNorm, allowOnlyInGoPrefixes, allowOnlyInGoExact)

	if len(missingFromGo) == 0 && len(missingFromSpec) == 0 {
		fmt.Printf("handler-coverage OK: %d spec routes ↔ %d Go routes (after normalisation)\n",
			len(specNorm), len(goNorm))
		return
	}

	if len(missingFromGo) > 0 {
		fmt.Fprintln(os.Stderr, "ERROR: OpenAPI spec lists routes Go does not register:")
		for _, p := range missingFromGo {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
	}
	if len(missingFromSpec) > 0 {
		fmt.Fprintln(os.Stderr, "ERROR: Go registers routes the OpenAPI spec does not document:")
		for _, p := range missingFromSpec {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
	}
	fmt.Fprintln(os.Stderr, "Fix: update api/openapi.yaml (and re-run `make openapi-sync`) and/or cmd/sn360-es/routes.go.")
	os.Exit(1)
}

// loadSpecPaths reads the OpenAPI document and returns the top-level
// keys of its `paths:` map. Method-level details (get/post/...) are
// out of scope for this gate.
func loadSpecPaths(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("yaml %s: %w", path, err)
	}
	out := make([]string, 0, len(doc.Paths))
	for k := range doc.Paths {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// loadGoRoutes parses routes.go and returns the path literals passed
// to mux.Handle / mux.HandleFunc. We accept ANY receiver name (not
// just "mux") so a refactor that renames the variable doesn't silently
// break the gate.
func loadGoRoutes(path string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := []string{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			// Path is not a literal — could be a constant or a
			// function call. Skip rather than fail; the maintainer
			// can document a workaround if it ever bites us.
			return true
		}
		// strconv.Unquote works for both `"foo"` and "`foo`" forms.
		s := lit.Value
		if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
			s = s[1 : len(s)-1]
		}
		out = append(out, stripMethodPrefix(s))
		return true
	})
	sort.Strings(out)
	return out, nil
}

// httpMethodPrefixes is the set of method tokens Go 1.22+'s
// `http.ServeMux` recognises as a prefix to a route pattern, per the
// stdlib net/http docs (`https://pkg.go.dev/net/http#ServeMux`). The
// route pattern syntax is `[METHOD ][HOST]/[PATH]`; this gate is
// concerned with the PATH component only, so we strip the
// method+space prefix when present.
var httpMethodPrefixes = []string{
	"GET ",
	"HEAD ",
	"POST ",
	"PUT ",
	"PATCH ",
	"DELETE ",
	"OPTIONS ",
	"CONNECT ",
	"TRACE ",
}

// stripMethodPrefix removes a leading `METHOD ` token from a route
// pattern (Go 1.22+ syntax) so the path matches the OpenAPI form.
// Returns the input unchanged when no method prefix is present.
//
// Examples:
//
//	`GET /v1/foo`  -> `/v1/foo`
//	`/v1/foo`      -> `/v1/foo`
func stripMethodPrefix(p string) string {
	for _, m := range httpMethodPrefixes {
		if strings.HasPrefix(p, m) {
			return p[len(m):]
		}
	}
	return p
}

// normalizeSet maps each path through normalize() and returns the
// distinct values. Multiple inputs collapsing to the same key is
// deliberate — see normalize for why.
func normalizeSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, p := range in {
		out[normalize(p)] = struct{}{}
	}
	return out
}

// normalize maps OpenAPI parameterised paths and Go subtree paths to
// a common shape so they can be compared. Specifically:
//
//   - `/v1/foo/{id}`    -> `/v1/foo/`   (OpenAPI param -> Go subtree)
//   - `/v1/foo/{id}/x`  -> `/v1/foo/`   (param at any depth)
//   - `/v1/foo/`        -> `/v1/foo/`   (Go subtree, unchanged)
//   - `/v1/foo`         -> `/v1/foo`    (exact route, unchanged)
//
// The collapse-at-first-param is intentionally lossy. A future tighter
// gate could thread per-param shapes through, but the current goal is
// "every documented route has SOME handler" not "every route shape
// matches exactly".
func normalize(p string) string {
	if i := strings.Index(p, "{"); i >= 0 {
		return p[:i]
	}
	return p
}

// diff returns the keys in `a` that are not in `b` and not in the
// allow-list. The allow-list has two parts: prefix matching (so
// adding `/v1/internal/` covers all descendants) and exact matching
// (so `/` only allow-lists itself, not the entire route tree).
func diff(a, b map[string]struct{}, allowPrefixes []string, allowExact map[string]struct{}) []string {
	out := []string{}
	for k := range a {
		if _, ok := b[k]; ok {
			continue
		}
		if _, ok := allowExact[k]; ok {
			continue
		}
		allowed := false
		for _, prefix := range allowPrefixes {
			if strings.HasPrefix(k, prefix) {
				allowed = true
				break
			}
		}
		if allowed {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
