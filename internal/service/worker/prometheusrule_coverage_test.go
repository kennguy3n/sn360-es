package worker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestPrometheusRuleWorkerCoverage is the CI gate that keeps the
// Prometheus `SN360ESWorkerCycleStalled` alert in sync with the set
// of Job implementations under internal/service/worker.
//
// Background: the alert in
// deployments/helm/sn360-es/templates/prometheusrule.yaml has to
// enumerate each worker by name in its per-worker
// `absent_over_time(...{worker="..."})` legs because PromQL's
// `absent_over_time` only fires when a metric with the given label
// set has never been emitted — i.e. it cannot generically say "any
// worker that should exist hasn't emitted". So the alert needs to
// know the canonical set of worker names. The Job.Name() values in
// this package are the source of truth.
//
// Without a gate, adding a new worker (or renaming an existing one)
// without updating the alert is a silent regression: the new worker's
// boot-failure mode wouldn't fire the alert at all. The doc comment
// in prometheusrule.yaml asks future maintainers to keep them in sync
// but doc comments are not load-bearing — this test makes the
// invariant enforceable.
//
// Implementation: walk every *.go file in this package, parse with
// go/ast, and for every method declaration of the form
// `func (j *XJob) Name() string { return "literal" }` capture the
// literal. Then read the prometheusrule.yaml template and extract the
// `{worker="..."}` literals from the SN360ESWorkerCycleStalled
// expression. Assert the two sets are equal.
//
// Notes:
//   - We deliberately scope to types whose name ends in "Job"
//     (matching the Job interface naming convention in this package)
//     so test fixtures like `fakeJob` and helpers like `PrunerFunc`
//     don't pollute the canonical set.
//   - We skip *_test.go files so test-only fake Jobs aren't picked
//     up.
//   - Reading the YAML as text (rather than parsing it via the helm
//     SDK) keeps the test dependency-free; the worker-label regex
//     is tight enough that it cannot match unintended literals.
func TestPrometheusRuleWorkerCoverage(t *testing.T) {
	wantWorkers := collectJobNamesFromWorkerPackage(t)
	gotWorkers := collectAlertWorkerLabels(t)

	sort.Strings(wantWorkers)
	sort.Strings(gotWorkers)

	if !equalStringSlices(wantWorkers, gotWorkers) {
		t.Errorf(
			"prometheusrule.yaml SN360ESWorkerCycleStalled enumeration drifted from "+
				"Job.Name() in internal/service/worker.\n"+
				"Workers in code:        %v\n"+
				"Workers in alert:       %v\n"+
				"Add or remove the per-worker absent_over_time leg in "+
				"deployments/helm/sn360-es/templates/prometheusrule.yaml.",
			wantWorkers, gotWorkers,
		)
	}
}

// collectJobNamesFromWorkerPackage parses every *.go (non-test) file
// in this package and returns the string literals returned by
// methods named "Name" on receiver types ending in "Job". This is
// the canonical worker-name set: the same set that
// `sn360_es_worker_cycle_completed_total{worker="..."}` carries at
// runtime.
func collectJobNamesFromWorkerPackage(t *testing.T) []string {
	t.Helper()
	dir := workerPackageDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read worker package dir: %v", err)
	}
	fset := token.NewFileSet()
	names := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Name.Name != "Name" {
				continue
			}
			if fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if !receiverTypeEndsInJob(fn.Recv.List[0]) {
				continue
			}
			if fn.Body == nil || len(fn.Body.List) != 1 {
				// Defensive: skip Name() implementations that
				// aren't a single `return "..."` statement so we
				// don't accidentally match a method that computes
				// the name at runtime.
				continue
			}
			ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				continue
			}
			lit, ok := ret.Results[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			names[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	return out
}

// receiverTypeEndsInJob reports whether the given Field is a method
// receiver whose pointed-to type name ends in "Job" (e.g. *CleanupJob,
// *DirectorySyncJob). This filters out helpers like PrunerFunc whose
// Name() implementation lives in this package but is NOT a worker.
func receiverTypeEndsInJob(recv *ast.Field) bool {
	switch t := recv.Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return strings.HasSuffix(id.Name, "Job")
		}
	case *ast.Ident:
		return strings.HasSuffix(t.Name, "Job")
	}
	return false
}

// workerLabelRE captures the worker name out of expressions like
// `sn360_es_worker_cycle_completed_total{worker="cleanup"}`. We tie
// the metric name into the pattern so an unrelated `{worker="..."}`
// in some other expression wouldn't be picked up.
var workerLabelRE = regexp.MustCompile(`sn360_es_worker_cycle_completed_total\{worker="([^"]+)"`)

// collectAlertWorkerLabels reads the prometheusrule.yaml Helm
// template and extracts every worker name referenced in a
// `sn360_es_worker_cycle_completed_total{worker="..."}` literal.
func collectAlertWorkerLabels(t *testing.T) []string {
	t.Helper()
	repoRoot := repoRootFromWorkerPackage(t)
	path := filepath.Join(repoRoot, "deployments", "helm", "sn360-es", "templates", "prometheusrule.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	matches := workerLabelRE.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		t.Fatalf("no worker labels found in %s — alert may have been refactored away; update this test", path)
	}
	set := map[string]struct{}{}
	for _, m := range matches {
		set[string(m[1])] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	return out
}

// workerPackageDir returns the on-disk directory of this package. We
// derive it from runtime.Caller so the test is location-independent
// (e.g. works under both `go test ./...` from repo root and
// `go test .` from inside the package directory).
func workerPackageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate worker package directory")
	}
	return filepath.Dir(thisFile)
}

func repoRootFromWorkerPackage(t *testing.T) string {
	t.Helper()
	// internal/service/worker -> ../../..
	return filepath.Join(workerPackageDir(t), "..", "..", "..")
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
