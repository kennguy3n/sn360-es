package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestViolates exercises the predicate-presence logic in isolation,
// independent of the AST walker. Each case is a (sql, table) pair plus
// the expected result. The cases double as the canonical specification
// of what the analyser will and will not flag — adding a new case is
// the right way to encode a new permitted SQL shape.
func TestViolates(t *testing.T) {
	cases := []struct {
		name   string
		sql    string
		table  string
		expect bool // true = violates
	}{
		{
			name:   "SELECT with tenant_id passes",
			sql:    "SELECT id FROM users WHERE tenant_id = $1",
			table:  "users",
			expect: false,
		},
		{
			name:   "SELECT without tenant_id violates",
			sql:    "SELECT id FROM users WHERE email = $1",
			table:  "users",
			expect: true,
		},
		{
			name:   "UPDATE with tenant_id passes",
			sql:    "UPDATE vendors SET display_name = $1 WHERE tenant_id = $2 AND id = $3",
			table:  "vendors",
			expect: false,
		},
		{
			name:   "UPDATE without tenant_id violates",
			sql:    "UPDATE vendors SET display_name = $1 WHERE id = $2",
			table:  "vendors",
			expect: true,
		},
		{
			name:   "DELETE with tenant_id passes",
			sql:    "DELETE FROM oauth_tokens WHERE tenant_id = $1 AND provider = $2",
			table:  "oauth_tokens",
			expect: false,
		},
		{
			name:   "DELETE without tenant_id violates",
			sql:    "DELETE FROM oauth_tokens WHERE provider = $1",
			table:  "oauth_tokens",
			expect: true,
		},
		{
			name:   "INSERT with tenant_id in col list passes",
			sql:    "INSERT INTO audit_logs (tenant_id, action, actor) VALUES ($1, $2, $3)",
			table:  "audit_logs",
			expect: false,
		},
		{
			name:   "INSERT missing tenant_id col violates",
			sql:    "INSERT INTO audit_logs (action, actor) VALUES ($1, $2)",
			table:  "audit_logs",
			expect: true,
		},
		{
			name:   "INSERT INTO non-scoped table is not checked",
			sql:    "INSERT INTO email_classifications (domain, classification) VALUES ($1, $2)",
			table:  "users", // SELECT against users would still flag but this is INSERT
			expect: false,   // INSERT target is email_classifications (not scoped)
		},
		{
			// Regression: INSERT INTO <non-scoped> SELECT FROM <scoped>
			// without a tenant filter was the blind spot Devin Review
			// flagged. Rows from every tenant would flow into a
			// shared table — exactly what tenant-lint is meant to
			// prevent.
			name:   "INSERT...SELECT FROM scoped table without tenant_id violates",
			sql:    "INSERT INTO email_classifications (domain) SELECT email FROM users",
			table:  "users",
			expect: true,
		},
		{
			name:   "INSERT...SELECT FROM scoped table with tenant_id passes",
			sql:    "INSERT INTO export_jobs (domain) SELECT email FROM users WHERE tenant_id = $1",
			table:  "users",
			expect: false,
		},
		{
			name:   "INSERT...SELECT FROM scoped into scoped with tenant_id col passes",
			sql:    "INSERT INTO audit_logs (tenant_id, action) SELECT tenant_id, 'export' FROM users WHERE tenant_id = $1",
			table:  "users",
			expect: false,
		},
		{
			name:   "tenant_id IN clause is accepted",
			sql:    "SELECT * FROM groups WHERE tenant_id IN ($1, $2)",
			table:  "groups",
			expect: false,
		},
		{
			name:   "tenant_id with cast accepted",
			sql:    "SELECT * FROM groups WHERE tenant_id::text = $1",
			table:  "groups",
			expect: false,
		},
		{
			name:   "JOIN inheriting tenant_id from outer query",
			sql:    "SELECT u.id FROM users u JOIN groups g ON u.tenant_id = g.tenant_id WHERE u.tenant_id = $1",
			table:  "groups",
			expect: false,
		},
		{
			// Devin Review #3325590915 — the reviewer's
			// canonical false-negative example. Without the
			// per-alias check, this passed because
			// `u.tenant_id = $1` matched anywhere in the SQL.
			// With per-alias scoping, `groups` has no
			// directly- or transitively-scoping predicate and
			// the linter flags it correctly.
			name:   "JOIN without scoping the joined tenant-scoped table violates",
			sql:    "SELECT u.id FROM users u JOIN groups g ON u.id = g.user_id WHERE u.tenant_id = $1",
			table:  "groups",
			expect: true,
		},
		{
			name:   "JOIN with explicit per-alias tenant_id predicates passes",
			sql:    "SELECT u.id, g.name FROM users u JOIN groups g ON u.id = g.user_id WHERE u.tenant_id = $1 AND g.tenant_id = $1",
			table:  "groups",
			expect: false,
		},
		{
			// Three-way transitive chain: a.tid = b.tid AND
			// b.tid = c.tid AND a.tid = $1 → union-find
			// propagates scope from a to b to c.
			name:   "Chained transitive joins propagate scope across qualifiers",
			sql:    "SELECT a.id FROM users a JOIN groups b ON a.tenant_id = b.tenant_id JOIN labels c ON b.tenant_id = c.tenant_id WHERE a.tenant_id = $1",
			table:  "labels",
			expect: false,
		},
		{
			// `g.tenant_id` appears only in a non-predicate
			// position (SELECT list). The qualifier is
			// referenced in the SQL but never scopes anything,
			// so the linter must still flag `groups`. This is
			// the property that prevents a false negative from
			// "merely listing a tenant_id column" as evidence
			// of scoping.
			name:   "Selecting tenant_id column does not count as scoping the table",
			sql:    "SELECT u.id, g.tenant_id FROM users u JOIN groups g ON u.id = g.user_id WHERE u.tenant_id = $1",
			table:  "groups",
			expect: true,
		},
		{
			// UPDATE ... FROM <other_scoped>: the joined
			// table must also have its own predicate.
			name:   "UPDATE ... FROM tenant-scoped without per-alias predicate violates",
			sql:    "UPDATE communication_histories ch SET count_7d = $1 FROM users u WHERE u.id = ch.user_id AND u.tenant_id = $2",
			table:  "communication_histories",
			expect: true,
		},
		{
			name:   "UPDATE ... FROM tenant-scoped with per-alias predicate passes",
			sql:    "UPDATE communication_histories ch SET count_7d = $1 FROM users u WHERE u.id = ch.user_id AND ch.tenant_id = $2 AND u.tenant_id = $2",
			table:  "communication_histories",
			expect: false,
		},
		{
			// Self-join is degenerate: both aliases refer to
			// `users`. A single literal binding scopes both
			// because the underlying table is the same — the
			// table-name lookup in missingPerTablePredicates
			// covers this.
			name:   "Self-join with one literal binding passes",
			sql:    "SELECT a.id FROM users a JOIN users b ON a.org_id = b.org_id WHERE users.tenant_id = $1",
			table:  "users",
			expect: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, got := violates(tc.sql, tc.table)
			if got != tc.expect {
				t.Fatalf("violates(%q,%q) = (%v,%q) want %v", tc.sql, tc.table, got, reason, tc.expect)
			}
		})
	}
}

// TestScanFile_DetectsAndExempts builds a tiny in-memory Go source
// file containing both a deliberately-bad query (missing predicate)
// and a deliberately-cross-tenant query annotated with the exemption.
// The analyser must flag exactly one violation: the bad query.
func TestScanFile_DetectsAndExempts(t *testing.T) {
	src := `package x

import "context"

type DB interface {
	ExecContext(context.Context, string, ...any) (any, error)
}

func bad(db DB, ctx context.Context) {
	_, _ = db.ExecContext(ctx, ` + "`SELECT id FROM users WHERE email = $1`" + `, "a")
}

func ok(db DB, ctx context.Context) {
	_, _ = db.ExecContext(ctx, ` + "`SELECT id FROM users WHERE tenant_id = $1`" + `, "t")
}

func crossTenantOK(db DB, ctx context.Context) {
	// tenant-lint:cross-tenant — boot-time enumeration of every tenant's tokens.
	_, _ = db.ExecContext(ctx, ` + "`SELECT tenant_id, provider FROM oauth_tokens ORDER BY created_at`" + `)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanFile(fset, f, []byte(src))
	if len(got) != 1 {
		for _, v := range got {
			t.Logf("violation: %s:%d table=%s stmt=%s reason=%s",
				v.pos.Filename, v.pos.Line, v.table, v.stmt, v.reason)
		}
		t.Fatalf("expected exactly 1 violation, got %d", len(got))
	}
	if got[0].table != "users" || !strings.Contains(got[0].sql, "email = $1") {
		t.Fatalf("wrong violation: table=%s sql=%s", got[0].table, got[0].sql)
	}
}

// TestCollectExemptionLines_OnlyHonoursAnnotatedComments verifies that
// a regular doc-comment without the marker does NOT exempt the line.
func TestCollectExemptionLines_OnlyHonoursAnnotatedComments(t *testing.T) {
	src := `package x

import "context"

type DB interface {
	ExecContext(context.Context, string, ...any) (any, error)
}

func notExempt(db DB, ctx context.Context) {
	// This comment is just a regular doc comment; it does NOT exempt the SQL.
	_, _ = db.ExecContext(ctx, ` + "`SELECT id FROM users WHERE email = $1`" + `, "a")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanFile(fset, f, []byte(src))
	if len(got) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(got))
	}
}

// TestCollectExemptionLines_ToleratesBlankLineBeforeSQL verifies that
// a blank line between the `tenant-lint:cross-tenant` annotation and
// the SQL literal does NOT silently lose the exemption. Devin Review
// flagged this fragility in PR #44 — a contributor adding a blank
// line for readability would previously have re-introduced a
// violation. The analyser now walks forward through blank /
// comment-only lines until it finds the first real source line.
func TestCollectExemptionLines_ToleratesBlankLineBeforeSQL(t *testing.T) {
	src := `package x

import "context"

type DB interface {
	ExecContext(context.Context, string, ...any) (any, error)
}

func crossTenantWithBlankLine(db DB, ctx context.Context) {
	// tenant-lint:cross-tenant — boot-time enumeration of every tenant's tokens.

	_, _ = db.ExecContext(ctx, ` + "`SELECT tenant_id, provider FROM oauth_tokens ORDER BY created_at`" + `)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanFile(fset, f, []byte(src))
	if len(got) != 0 {
		for _, v := range got {
			t.Logf("unexpected violation: %s:%d table=%s stmt=%s",
				v.pos.Filename, v.pos.Line, v.table, v.stmt)
		}
		t.Fatalf("expected blank line before SQL to be tolerated; got %d violation(s)", len(got))
	}
}

// TestCollectExemptionLines_ToleratesInterleavedComment exercises the
// case where a sub-comment (“// note: ...”) sits between the marker
// comment-group and the SQL literal. The forward walk treats comment-
// only lines as transparent in the same way as blank lines.
func TestCollectExemptionLines_ToleratesInterleavedComment(t *testing.T) {
	src := `package x

import "context"

type DB interface {
	ExecContext(context.Context, string, ...any) (any, error)
}

func crossTenantWithInlineComment(db DB, ctx context.Context) {
	// tenant-lint:cross-tenant — boot-time enumeration of every tenant's tokens.
	// note: kept here so the next person reading the query knows what's up.
	_, _ = db.ExecContext(ctx, ` + "`SELECT tenant_id, provider FROM oauth_tokens ORDER BY created_at`" + `)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanFile(fset, f, []byte(src))
	if len(got) != 0 {
		t.Fatalf("expected interleaved comment to be tolerated; got %d violation(s)", len(got))
	}
}

// TestCollectExemptionLines_RequiresJustification rejects an
// annotation that is missing its trailing justification text.
func TestCollectExemptionLines_RequiresJustification(t *testing.T) {
	if crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant") {
		t.Fatal("bare annotation must require justification text")
	}
	if !crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant — boot-time enumeration") {
		t.Fatal("annotation with em-dash justification must match")
	}
	if !crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant - hyphen justification") {
		t.Fatal("annotation with hyphen justification must match")
	}
	if !crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant: colon justification") {
		t.Fatal("annotation with colon justification must match")
	}
}
