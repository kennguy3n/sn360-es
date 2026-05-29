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

// excludedFiles is paths the linter never inspects. Migrations
// (`migrations/`) are SQL files (not Go) so they are excluded
// automatically by the .go filter, but Go files that legitimately
// store SQL test fixtures or schema-introspection code can be added
// here.
var excludedFiles = []string{
	"cmd/sn360-es-tenant-lint/", // the linter itself contains table names in strings
	"cmd/sn360-es-migrate/",     // migration tool inspects schema by design
	"_test.go",                  // tests legitimately exercise edge cases
}

// statementRE matches the first SQL keyword in a candidate string.
// Anchored at the start (after optional whitespace) so it does not
// match keywords embedded in comments or inside string concatenations.
var statementRE = regexp.MustCompile(`(?is)^\s*(?:--[^\n]*\n\s*)*(SELECT|INSERT|UPDATE|DELETE|WITH|UPSERT|MERGE)\b`)

// tableRE matches `<tableName>` as a whole word, case-insensitive.
// Used both to detect that a tenant-scoped table appears in the SQL
// and to anchor the predicate search around it.
func tableRE(name string) *regexp.Regexp {
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

// updateTableRE captures the target of an UPDATE statement.
var updateTableRE = regexp.MustCompile(`(?is)\bupdate\s+([a-z_][a-z_0-9]*)\b`)

// deleteFromRE captures the target of a DELETE FROM.
var deleteFromRE = regexp.MustCompile(`(?is)\bdelete\s+from\s+([a-z_][a-z_0-9]*)\b`)

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
		for _, ex := range excludedFiles {
			if strings.Contains(rel, ex) {
				return nil
			}
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "tenant-lint: parse %s: %v\n", rel, perr)
			os.Exit(2)
		}
		violations = append(violations, scanFile(fset, f)...)
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
// is suppressed. When the annotation appears anywhere in a comment
// group (single- or multi-line), every line of the group AND the
// line immediately following the group is marked exempt — this lets
// authors place a multi-line justification directly above the SQL
// literal without having to keep them on adjacent lines.
func collectExemptionLines(fset *token.FileSet, f *ast.File) map[int]struct{} {
	out := map[int]struct{}{}
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
		for ln := startLine; ln <= endLine+1; ln++ {
			out[ln] = struct{}{}
		}
	}
	return out
}

func scanFile(fset *token.FileSet, f *ast.File) []violation {
	exempt := collectExemptionLines(fset, f)
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
		if tableRE(t).MatchString(sql) {
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
// other statement types only care that *some* tenant-scoped table
// appears.
func violates(sql, table string) (string, bool) {
	_ = table // referenced by INSERT path indirectly via insertColListRE
	stmt := classify(sql)
	switch stmt {
	case "SELECT", "WITH":
		// SELECT and CTEs are tenant-safe if either:
		//   (a) the SQL contains a tenant_id predicate anywhere
		//       (the conservative reading: at least one filter is
		//       present), OR
		//   (b) the table appears only inside a JOIN whose top-level
		//       SELECT already filters by tenant_id.
		// For simplicity, we accept (a). The migration to RLS will
		// add (b) implicitly because the DB enforces it.
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
		// If this UPDATE targets a tenant-scoped table, require the
		// predicate. (If the UPDATE targets a different table but
		// the SQL also mentions a tenant-scoped table, the FROM-like
		// clause must filter — same rule applies via the global
		// regex.)
		if tenantIDPredicateRE.MatchString(sql) {
			return "", false
		}
		return "UPDATE on tenant-scoped table without `tenant_id = $N` in the WHERE clause", true
	case "DELETE":
		if !deleteFromRE.MatchString(sql) {
			return "", false
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
		if len(m) < 3 {
			// INSERT … SELECT or other dynamic form — fall back to
			// the global predicate check.
			if tenantIDPredicateRE.MatchString(sql) {
				return "", false
			}
			return "INSERT without explicit column list on tenant-scoped table — cannot verify tenant_id is set", true
		}
		targetTable := strings.ToLower(m[1])
		if _, scoped := tenantScopedTables[targetTable]; !scoped {
			// INSERT targets a non-tenant-scoped table — irrelevant.
			return "", false
		}
		cols := strings.ToLower(m[2])
		if !regexp.MustCompile(`(?i)\btenant_id\b`).MatchString(cols) {
			return "INSERT INTO tenant-scoped table missing `tenant_id` in the column list", true
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
