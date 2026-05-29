// Command sn360-es-tenant-lint is a static analyser that fails the build
// when a SQL string literal touches a tenant-scoped table without a
// `tenant_id` predicate.
//
// Background. SN360-ES enforces tenant isolation at the application
// layer: every CRUD operation against a tenant-scoped table must filter
// or set `tenant_id` so one tenant's rows are never visible to another.
// Postgres Row-Level Security (RLS) is on the roadmap as defence in
// depth, but historically a single missing `WHERE tenant_id=$1` has
// been enough to leak rows across tenants in similar codebases. This
// analyser catches that class of bug at lint time, before it can ship.
//
// What it checks. For every Go source file under the given root, the
// analyser:
//  1. parses the file into a go/ast.
//  2. visits every *ast.BasicLit that is a Go string and contains the
//     name of a tenant-scoped table (`users`, `vendors`, `audit_logs`,
//     etc.). The list is hard-coded against the migrations in
//     migrations/ — see `tenantScopedTables`.
//  3. classifies the SQL statement (SELECT / INSERT / UPDATE / DELETE)
//     and asserts the appropriate tenant_id predicate:
//     SELECT / UPDATE / DELETE → must include `tenant_id` in the
//     WHERE clause (or be a JOIN whose
//     left-hand parent table is itself
//     tenant-filtered).
//     INSERT                   → must list `tenant_id` in the column
//     list of an INSERT … (col_list) form.
//  4. reports each violation as a `file:line:col` diagnostic and exits
//     non-zero when any violations were found.
//
// What it does NOT check. The analyser is intentionally conservative:
//   - It does not interpret prepared-statement values, only the SQL
//     text. A query that omits `tenant_id` from its SQL but happens to
//     filter at the Go layer is still flagged — that is the point.
//   - It does not parse the SQL grammar; it uses string matching with
//     a small lexer to detect statement type and predicate presence.
//     False positives are preferred over false negatives.
//   - `group_memberships` is excluded because its tenant scoping is
//     enforced via FK to `groups(id)` / `users(id)` (both tenant-scoped),
//     not via a direct column.
//   - `tenants` and `email_classifications` are not tenant-scoped.
//
// Opt-out annotation. A small number of admin / boot-time queries
// are legitimately cross-tenant (e.g. the OAuth registry restores
// every tenant's tokens at startup; the worker fan-out enumerates
// every tenant). These call-sites must carry a comment of the form
//
//	// tenant-lint:cross-tenant — <one-line justification>
//
// on the line directly above the SQL string literal. The analyser
// suppresses violations for any literal whose preceding comment
// (anywhere in the same statement's leading // comments) matches
// `tenant-lint:cross-tenant`. The justification text is required to
// force the author to articulate why the cross-tenant access is safe.
//
// Blank lines between the annotation and the SQL literal are
// tolerated: the analyser walks forward through any number of blank
// or comment-only lines and exempts the first non-blank, non-comment
// source line it finds. This matches the way authors actually
// format code — keeping a justification comment readable above a
// query body — without forcing the annotation to be glued to the
// literal.
//
// Usage:
//
//	go run ./cmd/sn360-es-tenant-lint ./...
//	# or, with an explicit root:
//	go run ./cmd/sn360-es-tenant-lint -root . ./internal/... ./pkg/...
//
// Exit codes:
//
//	0 — clean.
//	1 — one or more violations were found (printed to stderr).
//	2 — internal error (file walk / parse failure).
//
// The analyser is intentionally a standalone command (no
// golang.org/x/tools dep) so it can be wired into CI without adding to
// the production module graph. See `make tenant-lint` for the
// canonical invocation.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// tenantScopedTables is the set of tables whose every row is scoped to
// exactly one tenant via a direct `tenant_id` column. The list is
// derived from `migrations/0001_init.up.sql` + subsequent ALTERs at
// schema HEAD. Update this list when a new tenant-scoped table is
// added in a migration.
var tenantScopedTables = map[string]struct{}{
	"users":                     {},
	"groups":                    {},
	"labels":                    {},
	"score_engine":              {},
	"vendors":                   {},
	"evaluation_results":        {},
	"communication_histories":   {},
	"campaigns":                 {},
	"simulation_results":        {},
	"escalation_tickets":        {},
	"audit_logs":                {},
	"feedback_events":           {},
	"oauth_tokens":              {},
	"sync_checkpoints":          {},
	"user_behavioral_baselines": {},
	"org_graphs":                {},
}

// tableREs holds one pre-compiled regexp per tenant-scoped table,
// populated at init time so the hot path (every SQL literal in the
// codebase) does a map lookup instead of recompiling a regexp. With 16
// tables and ~hundreds of SQL literals across the codebase, naive
// per-call regexp.MustCompile was the dominant cost of the analyser.
var tableREs = func() map[string]*regexp.Regexp {
	out := make(map[string]*regexp.Regexp, len(tenantScopedTables))
	for t := range tenantScopedTables {
		out[t] = compileTableRE(t)
	}
	return out
}()

// excludedDirs is the set of repo-relative directory prefixes the
// linter never inspects. Migrations (`migrations/`) are SQL files
// (not Go) so they are excluded automatically by the .go filter, but
// Go files that legitimately store SQL test fixtures or schema-
// introspection code can be added here.
var excludedDirs = []string{
	"cmd/sn360-es-tenant-lint/", // the linter itself contains table names in strings
	"cmd/sn360-es-migrate/",     // migration tool inspects schema by design
}

// excludedSuffixes is the set of filename suffixes the linter never
// inspects. Kept separate from excludedDirs so the check is a precise
// HasSuffix — a `strings.Contains` would mis-match any path that
// happens to embed `_test.go` as a substring (e.g. a directory named
// `foo_test.go_helper/`).
var excludedSuffixes = []string{
	"_test.go", // tests legitimately exercise edge cases
}

// statementRE matches the first SQL keyword in a candidate string.
// Anchored at the start (after optional whitespace) so it does not
// match keywords embedded in comments or inside string concatenations.
var statementRE = regexp.MustCompile(`(?is)^\s*(?:--[^\n]*\n\s*)*(SELECT|INSERT|UPDATE|DELETE|WITH|UPSERT|MERGE)\b`)

// compileTableRE returns a fresh regexp that matches `<tableName>` as a
// whole word, case-insensitive. Called once per table at init time;
// the hot path (table-scan in checkSQL) reads from the pre-compiled
// tableREs map directly.
func compileTableRE(name string) *regexp.Regexp {
	// (?i) — case-insensitive; \b — word boundary so `users` does not
	// also match `users_active`.
	return regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(name) + `\b`)
}

// tenantIDPredicateRE matches the various forms the tenant_id predicate
// can take in a WHERE/JOIN clause: equality with a placeholder, equality
// with another column (JOIN), IN (...), or `current_setting('sn360.tenant_id'...)`
// (the RLS-aware form). The regex is intentionally permissive to keep
// false positives low — false negatives are the real risk.
var tenantIDPredicateRE = regexp.MustCompile(`(?i)\btenant_id\s*(?:=|IN\b|::)`)

// insertColListRE captures the column list of an INSERT INTO <t> (...)
// form. Captures up to a balanced closing paren. The regex is
// intentionally minimal — INSERT INTO ... DEFAULT VALUES is rejected
// for tenant-scoped tables because it cannot set tenant_id.
var insertColListRE = regexp.MustCompile(`(?is)\binsert\s+into\s+([a-z_][a-z_0-9]*)\s*\(([^)]*)\)`)

// updateTableRE captures the target of an UPDATE statement and its
// optional alias. Group 1 is the table; group 2 is the alias (with
// or without `AS`). The post-table reserved-word filter in
// sqlTableReferences rejects keywords like `SET` if they were
// mis-captured as an alias.
var updateTableRE = regexp.MustCompile(`(?is)\bupdate\s+([a-z_][a-z_0-9]*)(?:\s+(?:AS\s+)?([a-z_][a-z_0-9]*))?`)

// deleteFromRE captures the target of a DELETE FROM and its optional
// alias. Same alias handling as updateTableRE.
var deleteFromRE = regexp.MustCompile(`(?is)\bdelete\s+from\s+([a-z_][a-z_0-9]*)(?:\s+(?:AS\s+)?([a-z_][a-z_0-9]*))?`)

// insertColTenantIDRE matches `tenant_id` as a column identifier inside
// an INSERT column list. Pre-compiled at package scope so the violates()
// hot path is a regexp match, not a per-call compile — same rationale
// as the other module-scope REs above.
var insertColTenantIDRE = regexp.MustCompile(`(?i)\btenant_id\b`)

// insertSelectFromRE captures the FROM clause of an INSERT...SELECT
// form, so we can detect when an INSERT INTO non-tenant-scoped target
// pulls rows from a tenant-scoped source without filtering. Used to
// close the linter's INSERT...SELECT blind spot.
var insertSelectFromRE = regexp.MustCompile(`(?is)\binsert\s+into\s+[a-z_][a-z_0-9]*(?:\s*\([^)]*\))?\s*select\b.*?\bfrom\s+([a-z_][a-z_0-9]*)\b`)

// fromJoinRE captures every (table, alias) binding in FROM and JOIN
// clauses. Group 1 is the table identifier, group 2 is the optional
// alias (with or without `AS`). Used by sqlTableReferences to build
// the alias map that the multi-table predicate check consults.
var fromJoinRE = regexp.MustCompile(`(?is)\b(?:FROM|JOIN)\s+([a-z_][a-z_0-9]*)(?:\s+(?:AS\s+)?([a-z_][a-z_0-9]*))?`)

// directBindRE matches a `<qualifier>.tenant_id` reference that
// binds the qualifier to a non-qualifier value: a parameter
// placeholder, literal, IN clause, function, or cast. These are
// the "directly scoped" qualifiers — the ones that actually pin
// rows to a tenant. Group 1 is the qualifier.
//
// A `<a>.tenant_id = <b>.tenant_id` form is intentionally NOT
// matched here — those are transitive joins, handled separately
// by transitiveJoinRE so the union-find can propagate scope from
// the directly-scoped side to the transitively-scoped side.
var directBindRE = regexp.MustCompile(
	`(?i)\b([a-z_][a-z_0-9]*)\.tenant_id\s*(?:` +
		// IN (...) — list / subquery predicate.
		`IN\b|` +
		// Postgres cast then comparison, e.g. ::text = $1.
		`::|` +
		// = <non-qualifier-RHS>: placeholder, literal, function,
		// NULL, or any character that isn't the start of another
		// identifier (the negative class catches '(' for function
		// calls and '\'' for literals at minimum).
		`=\s*(?:\$\d+|\d+|true\b|false\b|null\b|'[^']*'|current_setting\b|[^a-z_]))`)

// transitiveJoinRE matches `<a>.tenant_id = <b>.tenant_id` join
// conditions in either order. Both qualifiers are placed in the
// same scoping equivalence class so a single directly-scoped
// qualifier transitively scopes every other qualifier joined to
// it via tenant_id. Without this, the linter would flag the
// idiomatic JOIN-on-tenant_id pattern as a violation.
var transitiveJoinRE = regexp.MustCompile(
	`(?i)\b([a-z_][a-z_0-9]*)\.tenant_id\s*=\s*([a-z_][a-z_0-9]*)\.tenant_id\b`)

// sqlReservedAfterTable is the set of SQL keywords that can legally
// follow a table name in a FROM/JOIN clause. They must not be misread
// as the table's alias — e.g. `JOIN groups ON ...` makes the alias
// empty, not "on". The set covers the post-table positions for the
// PG dialect actually used by the codebase; new ones can be added as
// the codebase exercises them.
var sqlReservedAfterTable = map[string]struct{}{
	"on": {}, "where": {}, "inner": {}, "left": {}, "right": {},
	"full": {}, "join": {}, "cross": {}, "using": {}, "order": {},
	"group": {}, "having": {}, "limit": {}, "offset": {}, "returning": {},
	"set": {}, "values": {}, "select": {}, "lateral": {}, "natural": {},
	"for": {}, "into": {}, "from": {}, "with": {}, "as": {},
}

// sqlTableReferences extracts every table reference in the SQL,
// returning a map of alias -> table name. The alias is the SQL-level
// short name (e.g. `u` in `users u`); when no alias is given the map
// uses the table name itself as the key. UPDATE / DELETE / INSERT
// targets are included so an UPDATE with no FROM clause still has
// its target in the map.
//
// This is the foundation for the multi-table predicate check:
// `SELECT u.id FROM users u JOIN groups g ON u.id = g.user_id` has
// two tenant-scoped references (users via `u`, groups via `g`) and
// each needs its own `<alias>.tenant_id` predicate — a bare
// `tenant_id = $1` is ambiguous and therefore insufficient.
func sqlTableReferences(sql string) map[string]string {
	refs := map[string]string{}
	add := func(alias, table string) {
		alias = strings.ToLower(alias)
		table = strings.ToLower(table)
		if alias == "" {
			alias = table
		}
		if _, reserved := sqlReservedAfterTable[alias]; reserved {
			alias = table
		}
		refs[alias] = table
	}
	for _, m := range fromJoinRE.FindAllStringSubmatch(sql, -1) {
		add(m[2], m[1])
	}
	if m := updateTableRE.FindStringSubmatch(sql); len(m) >= 2 {
		alias := ""
		if len(m) >= 3 {
			alias = m[2]
		}
		add(alias, m[1])
	}
	if m := deleteFromRE.FindStringSubmatch(sql); len(m) >= 2 {
		alias := ""
		if len(m) >= 3 {
			alias = m[2]
		}
		add(alias, m[1])
	}
	if m := insertColListRE.FindStringSubmatch(sql); len(m) >= 2 {
		add("", m[1])
	}
	return refs
}

// scopedRefs returns the subset of sqlTableReferences that point at
// tenant-scoped tables, keyed by alias. Used to decide between the
// permissive (single-scoped-table → bare predicate OK) and the
// strict (multi-scoped-table → per-alias qualified predicate
// required) check.
func scopedRefs(sql string) map[string]string {
	out := map[string]string{}
	for alias, table := range sqlTableReferences(sql) {
		if _, scoped := tenantScopedTables[table]; scoped {
			out[alias] = table
		}
	}
	return out
}

// scopedQualifiers computes the set of qualifiers (lower-cased) the
// SQL actually scopes via a tenant_id predicate. The set includes:
//
//  1. Directly-scoped qualifiers from directBindRE — i.e. qualifiers
//     bound to a literal / placeholder / IN clause / cast.
//  2. Transitively-scoped qualifiers — qualifiers reachable from a
//     directly-scoped one via `<a>.tenant_id = <b>.tenant_id`
//     join conditions. The transitive set is computed with
//     union-find so chains of joins propagate correctly:
//     `a.tid = b.tid AND b.tid = c.tid AND a.tid = $1` scopes all
//     of {a, b, c}.
//
// A qualifier is *not* in this set merely because `<q>.tenant_id`
// appears in a SELECT list or other non-predicate position — the
// regexes deliberately require a comparison-style suffix so a
// reference is only "scoping" when it binds rows.
func scopedQualifiers(sql string) map[string]struct{} {
	// Step 1: collect direct bindings.
	direct := map[string]struct{}{}
	for _, m := range directBindRE.FindAllStringSubmatch(sql, -1) {
		direct[strings.ToLower(m[1])] = struct{}{}
	}
	// Step 2: build union-find from transitive joins. Roots are
	// keyed by qualifier; the root of a class is whichever member
	// is lexicographically first (deterministic, doesn't matter
	// for correctness).
	parent := map[string]string{}
	var find func(string) string
	find = func(q string) string {
		if p, ok := parent[q]; ok && p != q {
			r := find(p)
			parent[q] = r
			return r
		}
		if _, ok := parent[q]; !ok {
			parent[q] = q
		}
		return parent[q]
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		parent[ra] = rb
	}
	for _, m := range transitiveJoinRE.FindAllStringSubmatch(sql, -1) {
		union(strings.ToLower(m[1]), strings.ToLower(m[2]))
	}
	// Step 3: anything in the same class as a directly-scoped
	// qualifier inherits scope.
	scopedRoots := map[string]struct{}{}
	for q := range direct {
		scopedRoots[find(q)] = struct{}{}
	}
	out := map[string]struct{}{}
	for q := range direct {
		out[q] = struct{}{}
	}
	for q := range parent {
		if _, ok := scopedRoots[find(q)]; ok {
			out[q] = struct{}{}
		}
	}
	return out
}

// missingPerTablePredicates checks that every tenant-scoped table
// reference has its OWN scoping predicate — directly via a literal
// binding, or transitively via a `<a>.tenant_id = <b>.tenant_id`
// join to something directly scoped. Returns the offending tables
// (sorted, deduped) so the violation message can name them.
// Returns nil when every scoped reference is covered.
//
// The "single scoped reference" case is handled by the caller, not
// here — for one table a bare `tenant_id = $1` is unambiguous and
// sufficient.
func missingPerTablePredicates(sql string) []string {
	refs := scopedRefs(sql)
	if len(refs) < 2 {
		return nil
	}
	scoped := scopedQualifiers(sql)
	missing := map[string]struct{}{}
	for alias, table := range refs {
		if _, ok := scoped[alias]; ok {
			continue
		}
		if _, ok := scoped[table]; ok {
			continue
		}
		missing[table] = struct{}{}
	}
	if len(missing) == 0 {
		return nil
	}
	out := make([]string, 0, len(missing))
	for t := range missing {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

type violation struct {
	pos    token.Position
	table  string
	stmt   string
	reason string
	sql    string
}

func main() {
	root := flag.String("root", ".", "module root to walk")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tenant-lint: resolve root: %v\n", err)
		os.Exit(2)
	}

	var violations []violation
	fset := token.NewFileSet()
	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			// Skip vendored / generated directories.
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" || name == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(absRoot, path)
		// Normalize separators so the excluded-dir prefixes (which use
		// `/`) match on Windows hosts that walk with `\`.
		relSlash := filepath.ToSlash(rel)
		for _, ex := range excludedDirs {
			if strings.HasPrefix(relSlash, ex) {
				return nil
			}
		}
		for _, ex := range excludedSuffixes {
			if strings.HasSuffix(relSlash, ex) {
				return nil
			}
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "tenant-lint: read %s: %v\n", rel, rerr)
			os.Exit(2)
		}
		f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "tenant-lint: parse %s: %v\n", rel, perr)
			os.Exit(2)
		}
		violations = append(violations, scanFile(fset, f, src)...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tenant-lint: walk: %v\n", err)
		os.Exit(2)
	}

	if len(violations) == 0 {
		return
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].pos.Filename != violations[j].pos.Filename {
			return violations[i].pos.Filename < violations[j].pos.Filename
		}
		return violations[i].pos.Line < violations[j].pos.Line
	})
	for _, v := range violations {
		fmt.Fprintf(os.Stderr,
			"%s:%d:%d: tenant-lint: %s on tenant-scoped table %q is missing a tenant_id predicate\n  reason: %s\n  sql: %s\n",
			v.pos.Filename, v.pos.Line, v.pos.Column,
			v.stmt, v.table, v.reason, oneLine(v.sql),
		)
	}
	fmt.Fprintf(os.Stderr, "\ntenant-lint: %d violation(s).\n", len(violations))
	os.Exit(1)
}

// crossTenantAnnotation marks a SQL literal as deliberately
// cross-tenant. The pattern requires a justification — any non-empty
// trailing text after the marker is accepted (the human reviewer is
// the validation, the analyser only enforces presence).
var crossTenantAnnotation = regexp.MustCompile(`(?i)tenant-lint:cross-tenant\b\s*[-—:]\s*\S`)

// collectExemptionLines returns the set of file lines (1-indexed) that
// are exempt because of a `tenant-lint:cross-tenant — <reason>`
// annotation. A SQL literal whose start line is in the returned set
// is suppressed.
//
// Behaviour. Every line of the annotated comment group is marked
// exempt, and the analyser then walks forward through any number of
// blank or comment-only source lines and marks the first non-blank,
// non-comment line it encounters as exempt as well. This makes the
// exemption robust to formatting — a contributor who inserts a blank
// line between the justification comment and the SQL literal for
// readability does not silently lose the exemption.
//
// `src` is the original file's bytes; required so we can probe each
// candidate line for blank/comment-only content. Passing the bytes
// in (instead of re-reading) keeps the cost amortised over the whole
// file walk.
func collectExemptionLines(fset *token.FileSet, f *ast.File, src []byte) map[int]struct{} {
	out := map[int]struct{}{}
	lines := splitLines(src)
	for _, cg := range f.Comments {
		var hit bool
		for _, c := range cg.List {
			if crossTenantAnnotation.MatchString(c.Text) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		startLine := fset.Position(cg.Pos()).Line
		endLine := fset.Position(cg.End()).Line
		for ln := startLine; ln <= endLine; ln++ {
			out[ln] = struct{}{}
		}
		// Walk forward through blank-only / comment-only lines
		// and exempt the first real source line we find. The
		// upper bound (16) is a sanity cap so a stray annotation
		// at end-of-file cannot exempt unbounded subsequent
		// content.
		for ln, scanned := endLine+1, 0; scanned < 16; ln, scanned = ln+1, scanned+1 {
			if ln-1 >= len(lines) {
				break
			}
			content := strings.TrimSpace(lines[ln-1])
			if content == "" || strings.HasPrefix(content, "//") || strings.HasPrefix(content, "/*") {
				out[ln] = struct{}{}
				continue
			}
			out[ln] = struct{}{}
			break
		}
	}
	return out
}

// splitLines returns the source split into individual lines (1-indexed
// as `out[line-1]`), preserving CRLF / LF terminators by stripping
// trailing \r so blank-line detection works on Windows-edited files.
func splitLines(src []byte) []string {
	if len(src) == 0 {
		return nil
	}
	lines := strings.Split(string(src), "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, "\r")
	}
	return lines
}

func scanFile(fset *token.FileSet, f *ast.File, src []byte) []violation {
	exempt := collectExemptionLines(fset, f, src)
	var out []violation
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if _, ok := exempt[fset.Position(lit.Pos()).Line]; ok {
			return true
		}
		// Strip Go quoting (regular "..." or raw `...`).
		raw := lit.Value
		if len(raw) < 2 {
			return true
		}
		var sql string
		switch raw[0] {
		case '`':
			sql = raw[1 : len(raw)-1]
		case '"':
			sql = unquote(raw)
		default:
			return true
		}
		if !looksLikeSQL(sql) {
			return true
		}
		// At least one tenant-scoped table must appear in the SQL
		// before we care.
		hits := tablesInSQL(sql)
		if len(hits) == 0 {
			return true
		}
		// Check each tenant-scoped table the literal touches.
		for _, table := range hits {
			if reason, ok := violates(sql, table); ok {
				out = append(out, violation{
					pos:    fset.Position(lit.Pos()),
					table:  table,
					stmt:   classify(sql),
					reason: reason,
					sql:    sql,
				})
			}
		}
		return true
	})
	return out
}

// tablesInSQL returns every tenant-scoped table that appears in the SQL.
func tablesInSQL(sql string) []string {
	var out []string
	for t := range tenantScopedTables {
		if tableREs[t].MatchString(sql) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// looksLikeSQL returns true if the string starts with a SQL DML
// keyword (case-insensitive). Comments / leading whitespace are
// tolerated. This deliberately excludes DDL (CREATE / ALTER / DROP),
// which is exercised only by migrations.
func looksLikeSQL(s string) bool {
	return statementRE.MatchString(s)
}

func classify(sql string) string {
	m := statementRE.FindStringSubmatch(sql)
	if len(m) < 2 {
		return "SQL"
	}
	return strings.ToUpper(m[1])
}

// violates returns (reason, true) if the SQL touches a tenant-scoped
// table but does not include a tenant_id predicate appropriate for
// the statement type. The `table` argument is the specific
// tenant-scoped table being checked (used by INSERT's column-list
// path to decide whether the INSERT target is itself tenant-scoped);
// other statement types use the multi-table per-alias check in
// scopedRefs / missingPerTablePredicates to ensure each tenant-
// scoped reference has its own predicate (not just any predicate
// somewhere in the SQL).
func violates(sql, table string) (string, bool) {
	_ = table // referenced by INSERT path indirectly via insertColListRE
	stmt := classify(sql)
	switch stmt {
	case "SELECT", "WITH":
		// SELECT and CTEs are tenant-safe iff every tenant-scoped
		// table reference has a tenant_id predicate. There are two
		// regimes:
		//
		//   - Single scoped reference: a bare `tenant_id = $N` is
		//     unambiguous (only one table to bind to) and accepted.
		//   - Multi scoped reference: each scoped alias must have
		//     its own `<alias>.tenant_id` (or `<table>.tenant_id`)
		//     predicate. The reviewer's example
		//
		//        SELECT u.id FROM users u JOIN groups g
		//        ON u.id = g.user_id WHERE u.tenant_id = $1
		//
		//     would otherwise pass — it has a bare-ish predicate on
		//     `u` but nothing scoping `groups`, so `groups` rows
		//     from every tenant join in. The per-alias check
		//     catches this class.
		if missing := missingPerTablePredicates(sql); len(missing) > 0 {
			return "SELECT/WITH touches tenant-scoped tables " + strings.Join(missing, ", ") +
				" without a `<alias>.tenant_id =` predicate scoping each one; bare predicate is insufficient when multiple scoped tables appear", true
		}
		if tenantIDPredicateRE.MatchString(sql) {
			return "", false
		}
		return "SELECT/WITH on tenant-scoped table without `tenant_id = $N` (or equivalent) anywhere in the SQL", true
	case "UPDATE":
		// UPDATE on a tenant-scoped table must be filtered by
		// tenant_id even if the SET clause does not change tenant_id.
		if !updateTableRE.MatchString(sql) {
			return "", false
		}
		if missing := missingPerTablePredicates(sql); len(missing) > 0 {
			return "UPDATE touches tenant-scoped tables " + strings.Join(missing, ", ") +
				" without a `<alias>.tenant_id =` predicate scoping each one (UPDATE ... FROM <other_scoped>)", true
		}
		if tenantIDPredicateRE.MatchString(sql) {
			return "", false
		}
		return "UPDATE on tenant-scoped table without `tenant_id = $N` in the WHERE clause", true
	case "DELETE":
		if !deleteFromRE.MatchString(sql) {
			return "", false
		}
		if missing := missingPerTablePredicates(sql); len(missing) > 0 {
			return "DELETE touches tenant-scoped tables " + strings.Join(missing, ", ") +
				" without a `<alias>.tenant_id =` predicate scoping each one (DELETE ... USING <other_scoped>)", true
		}
		if tenantIDPredicateRE.MatchString(sql) {
			return "", false
		}
		return "DELETE FROM tenant-scoped table without `tenant_id = $N` in the WHERE clause", true
	case "INSERT":
		// INSERT must list tenant_id in the explicit column list,
		// otherwise the row defaults to NULL and the NOT NULL
		// constraint fails at runtime (good) — but we want this
		// caught at lint time before someone writes ON CONFLICT DO
		// UPDATE without re-asserting tenant_id.
		m := insertColListRE.FindStringSubmatch(sql)
		if len(m) >= 3 {
			targetTable := strings.ToLower(m[1])
			if _, scoped := tenantScopedTables[targetTable]; scoped {
				cols := strings.ToLower(m[2])
				if !insertColTenantIDRE.MatchString(cols) {
					return "INSERT INTO tenant-scoped table missing `tenant_id` in the column list", true
				}
				return "", false
			}
			// INSERT targets a non-tenant-scoped table — still
			// check for INSERT...SELECT from a tenant-scoped
			// source, see below.
		}
		// INSERT...SELECT from a tenant-scoped table requires a
		// tenant predicate on the SELECT side; otherwise rows from
		// every tenant flow into the (possibly non-tenant-scoped)
		// target table — exactly the cross-tenant leak the linter
		// is meant to catch. We treat this as the same class of bug
		// regardless of whether the target is itself scoped.
		if sm := insertSelectFromRE.FindStringSubmatch(sql); len(sm) >= 2 {
			sourceTable := strings.ToLower(sm[1])
			if _, scoped := tenantScopedTables[sourceTable]; scoped {
				if tenantIDPredicateRE.MatchString(sql) {
					return "", false
				}
				return "INSERT ... SELECT FROM tenant-scoped table `" + sourceTable + "` without `tenant_id =` predicate — rows from every tenant would be copied", true
			}
		}
		if len(m) < 3 {
			// INSERT without explicit column list on a tenant-scoped
			// target. Fall back to the global predicate check (e.g.
			// INSERT ... SELECT with a WHERE tenant_id = $1).
			if tenantIDPredicateRE.MatchString(sql) {
				return "", false
			}
			return "INSERT without explicit column list on tenant-scoped table — cannot verify tenant_id is set", true
		}
		return "", false
	case "UPSERT", "MERGE":
		if tenantIDPredicateRE.MatchString(sql) {
			return "", false
		}
		return "MERGE/UPSERT on tenant-scoped table without a `tenant_id` predicate", true
	default:
		return "", false
	}
}

// oneLine collapses whitespace so the diagnostic stays on one line.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	return strings.Join(strings.Fields(s), " ")
}

// unquote handles double-quoted Go string literals with escape
// sequences. It tolerates malformed input by returning the raw bytes
// stripped of surrounding quotes — the analyser is then permissive in
// what it matches.
func unquote(raw string) string {
	if len(raw) < 2 {
		return raw
	}
	s := raw[1 : len(raw)-1]
	// Replace common escapes that affect SQL detection.
	s = strings.NewReplacer(
		`\n`, "\n",
		`\t`, "\t",
		`\"`, `"`,
		`\\`, `\`,
	).Replace(s)
	return s
}
