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
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// allowOnlyInGoPrefixes is the set of route subtrees Go is allowed
// to serve without an OpenAPI entry. Each entry MUST end in `/`,
// matching the net/http stdlib's subtree-pattern syntax — the prefix
// is matched via strings.HasPrefix, and the trailing `/` is what makes
// the match shape-correct (`/v1/push/` matches `/v1/push/foo` but not
// `/v1/pushback`). The invariant is enforced at startup by
// validateAllowList() so a future contributor can't add a bare-prefix
// entry that silently over-matches; the regression test at
// TestAllowOnlyInGoPrefixes_SubtreeEntriesEndInSlash also pins it.
//
// Exact routes (files like `/healthz`, `/metrics`, `/openapi.yaml`)
// belong in allowOnlyInGoExact, NOT here. Adding them here would mean
// `/healthz` prefix-matches a hypothetical future route like
// `/healthzCheck` and silently lets it through without an OpenAPI
// entry. That's the exact failure mode the gate exists to prevent.
//
// Entries are added ONLY when the matching route is actually
// registered in routes.go. Pre-emptive entries for "future" routes
// were intentionally not introduced: the cost of a developer adding
// a single allow-list line when they wire a new operational endpoint
// is far cheaper than the cost of accidentally allow-listing a future
// customer-facing endpoint without OpenAPI coverage.
var allowOnlyInGoPrefixes = []string{
	"/docs/",    // Swagger UI assets — operational, separate from REST API
	"/l/",       // URL-rewrite interstitial — internal-only
	"/v1/push/", // SaaS push webhooks — operational ingress, not REST API
}

// allowOnlyInGoExact is the set of EXACT routes Go is allowed to
// serve without an OpenAPI entry. These are file-style operational
// endpoints with no descendants — they MUST be in the exact map and
// NOT in allowOnlyInGoPrefixes, otherwise a HasPrefix check would
// accidentally allow-list any route whose path starts with the same
// characters (e.g. `/healthz` prefix-matching `/healthzCheck`).
//
// `/` is also here because net/http requires a catch-all handler at
// `/` to serve as the 404 sink — it is NOT a customer API surface,
// so it's allow-listed exactly (not as a prefix, which would match
// every URL ever).
var allowOnlyInGoExact = map[string]struct{}{
	"/":             {},
	"/healthz":      {},
	"/readyz":       {},
	"/metrics":      {},
	"/docs":         {}, // exact form; subtree form is in allowOnlyInGoPrefixes
	"/openapi.yaml": {},
}

// validateAllowList asserts the structural invariant: every entry in
// allowOnlyInGoPrefixes must end in `/`. Without this guard, a future
// edit that adds a bare-prefix entry (e.g. "/healthz") would silently
// over-match every route starting with the same characters. Calling
// this from main() makes the invariant a hard build-time check, not a
// doc-comment suggestion.
//
// Thin wrapper over validateAllowListPrefixes — tests should call the
// parameterised form rather than mutating the package-level global, so
// the suite remains safe under `t.Parallel()` should a future
// contributor enable it.
func validateAllowList() error {
	return validateAllowListPrefixes(allowOnlyInGoPrefixes)
}

// validateAllowListPrefixes is the testable core of validateAllowList:
// it performs the trailing-slash check on an arbitrary prefix list so
// negative-path tests can exercise the failure mode without touching
// the package-level allowOnlyInGoPrefixes global. Keeping the logic in
// a pure function means TestValidateAllowList does not have to install
// a t.Cleanup-based restoration shim, and any future `t.Parallel()`
// addition cannot race on the global.
func validateAllowListPrefixes(prefixes []string) error {
	for _, p := range prefixes {
		if !strings.HasSuffix(p, "/") {
			return fmt.Errorf(
				"allowOnlyInGoPrefixes entry %q does not end in `/`; "+
					"bare prefixes silently over-match (e.g. /healthz would match /healthzCheck); "+
					"move exact-route entries to allowOnlyInGoExact, or add a trailing `/` for true subtrees",
				p)
		}
	}
	return nil
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

	if err := validateAllowList(); err != nil {
		fmt.Fprintf(os.Stderr, "handler-coverage allow-list invariant violated: %v\n", err)
		os.Exit(2)
	}

	specPaths, err := loadSpecPaths(*openapiPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load spec: %v\n", err)
		os.Exit(2)
	}
	goPaths, skips, err := loadGoRoutesWithSkips(*routesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse routes.go: %v\n", err)
		os.Exit(2)
	}
	// Surface const-named / function-call route paths as a CI warning
	// rather than silently dropping them. The gate is intentionally
	// permissive here (resolving non-literal paths would require a
	// full type-checker pass), but a future contributor adding e.g.
	// `mux.HandleFunc(routesConst.Foo, h)` now gets visible feedback
	// in build output: either rename to a literal so the gate sees
	// the route, or add the route to the allow-lists explicitly.
	for _, s := range skips {
		fmt.Fprintf(os.Stderr, "handler-coverage WARN: non-literal route argument skipped — %s\n", s)
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
//
// Non-literal path arguments (e.g. mux.HandleFunc(someConst, h) or
// mux.HandleFunc(buildRoutePath(...), h)) are skipped because the AST
// walker cannot resolve them without a full type+const evaluator —
// pulling in golang.org/x/tools/go/packages just for this gate is not
// worth the dependency. To keep the skip from being a silent gap,
// each skipped call is written to skipsOut (when non-nil) so main()
// can surface it as a CI warning: an operator who adds a const-named
// route sees the warning in build output and either renames to a
// literal or adds the route to the allow-lists explicitly.
func loadGoRoutes(path string) ([]string, error) {
	out, _, err := loadGoRoutesWithSkips(path)
	return out, err
}

// loadGoRoutesWithSkips is the testable core of loadGoRoutes: alongside
// the resolved route literals it returns the source positions of any
// mux.Handle / mux.HandleFunc call whose first argument was NOT a
// string literal. Callers that want to surface the skips (main()) read
// the positions; callers that just want the routes (most tests) ignore
// them via the loadGoRoutes wrapper.
func loadGoRoutesWithSkips(path string) ([]string, []string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := []string{}
	skips := []string{}
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
			// function call. Skip rather than fail (resolving
			// non-literals requires a type-checker pass) but
			// record the position so main() can warn. Without
			// this warning, a const-named route would silently
			// vanish from the gate's view: routes.go would have
			// it, the gate wouldn't see it, and the "missing
			// from spec" check would never fire.
			pos := fset.Position(call.Pos())
			skips = append(skips, fmt.Sprintf("%s:%d:%d: %s.%s(<non-literal>, ...)",
				pos.Filename, pos.Line, pos.Column,
				exprString(sel.X), sel.Sel.Name))
			return true
		}
		// strconv.Unquote handles both `"foo"` and "`foo`" forms
		// AND decodes any escape sequences inside double-quoted
		// literals (e.g. `"\u00e9"` -> `é`). Route paths in this
		// codebase don't currently use escapes, but Unquote is the
		// stdlib-blessed way to recover the runtime string from a
		// `token.STRING` BasicLit — use it rather than reinventing
		// quote-stripping by hand.
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			// Malformed literal would have failed `parser.ParseFile`
			// earlier, but guard defensively rather than panic.
			return true
		}
		out = append(out, stripMethodPrefix(s))
		return true
	})
	sort.Strings(out)
	sort.Strings(skips)
	return out, skips, nil
}

// exprString returns a best-effort textual rendering of an AST
// expression for diagnostic messages. We only need enough to identify
// which mux variable / receiver the call was on, so cover the two
// common cases (bare identifier, selector) and fall back to the AST
// node's stringer for anything else.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	default:
		return fmt.Sprintf("%T", e)
	}
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
