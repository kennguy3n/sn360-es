package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// bootstrapTenant describes one row inserted by the bootstrap
// subcommand. The TenantID is a deterministic UUIDv4-shaped string
// derived from the per-row index so consecutive runs against the
// same Postgres instance converge on the same rows (ON CONFLICT DO
// NOTHING in the INSERT keeps re-runs idempotent).
type bootstrapTenant struct {
	Index    int    `json:"index"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// bootstrapManifest is the JSON artefact written by the bootstrap
// subcommand. k6 reads this file at scenario start to learn which
// tenant_ids exist so it can address them by index without round-
// tripping a tenant-list query before every iteration.
type bootstrapManifest struct {
	Seed        int64             `json:"seed"`
	Count       int               `json:"count"`
	PostgresURL string            `json:"postgres_url_redacted"`
	GeneratedAt time.Time         `json:"generated_at"`
	Tenants     []bootstrapTenant `json:"tenants"`
}

// runBootstrap parses the bootstrap-subcommand flags and provisions
// the requested tenants. It returns nil on success even if every
// row already existed — the manifest still gets written so k6 can
// pick up the canonical tenant set without re-running the seeder.
func runBootstrap(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := newFlagSet(cmdBootstrap)
	count := fs.Int("count", 5000, "number of tenants to provision")
	tenantPrefix := fs.String("tenant-prefix", "00000000-0000-0000-0000-",
		"shared prefix for the synthesised tenant UUIDs; the last 12 hex chars are filled with the per-row index")
	nameFormat := fs.String("name-format", "loadgen-tenant-%04d",
		"fmt-Sprintf format for the tenant name (must include exactly one %d)")
	displayFormat := fs.String("display-format", "Loadgen Tenant %d",
		"fmt-Sprintf format for the tenant display_name")
	primaryDomain := fs.String("primary-domain", "loadgen.acme.test",
		"primary_domain assigned to every bootstrapped tenant; emails on subdomains keep tenant routing realistic")
	provider := fs.String("provider", "gws",
		"tenant provider; must be one of {gws, o365} per the migrations check constraint")
	kmsKeyARN := fs.String("kms-key-arn", "arn:aws:kms:ap-southeast-1:000000000000:key/loadgen",
		"kms_key_arn column value; the load harness never invokes KMS so a placeholder ARN is fine")
	postgresURL := fs.String("postgres-url", os.Getenv("LOADGEN_POSTGRES_URL"),
		"libpq URL for the dev Postgres (default $LOADGEN_POSTGRES_URL)")
	out := fs.String("out", "tests/load/results/tenants.json",
		"path to write the bootstrap manifest JSON")
	connTimeout := fs.Duration("connect-timeout", 15*time.Second,
		"upper bound on connecting / pinging Postgres")
	insertTimeout := fs.Duration("insert-timeout", 5*time.Minute,
		"upper bound on the full INSERT batch")
	seed := fs.Int64("seed", 42,
		"seed echoed into the manifest; bootstrap itself is deterministic by -count + -tenant-prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *count <= 0 {
		return fmt.Errorf("-count must be > 0, got %d", *count)
	}
	if *postgresURL == "" {
		return errors.New("-postgres-url (or $LOADGEN_POSTGRES_URL) is required")
	}
	if !strings.Contains(*nameFormat, "%d") {
		return fmt.Errorf("-name-format %q must contain exactly one %%d placeholder", *nameFormat)
	}
	if !strings.Contains(*displayFormat, "%d") {
		return fmt.Errorf("-display-format %q must contain exactly one %%d placeholder", *displayFormat)
	}
	if *provider != "gws" && *provider != "o365" {
		return fmt.Errorf("-provider must be one of {gws, o365}, got %q", *provider)
	}
	if !strings.HasSuffix(*tenantPrefix, "-") {
		return fmt.Errorf("-tenant-prefix must end with a dash so the suffix slots cleanly onto a UUID; got %q", *tenantPrefix)
	}
	if len(*tenantPrefix) != len("00000000-0000-0000-0000-") {
		return fmt.Errorf("-tenant-prefix must match the UUID-with-trailing-dash shape (24 chars), got %d", len(*tenantPrefix))
	}

	cfg, err := postgres.ParseURL(*postgresURL)
	if err != nil {
		return fmt.Errorf("parse -postgres-url: %w", err)
	}
	openCtx, cancel := context.WithTimeout(ctx, *connTimeout)
	defer cancel()
	db, err := postgres.Open(openCtx, cfg)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	insCtx, insCancel := context.WithTimeout(ctx, *insertTimeout)
	defer insCancel()

	tenants, err := provisionTenants(insCtx, db.SQL(), provisionRequest{
		Count:         *count,
		TenantPrefix:  *tenantPrefix,
		NameFormat:    *nameFormat,
		DisplayFormat: *displayFormat,
		PrimaryDomain: *primaryDomain,
		Provider:      *provider,
		KMSKeyARN:     *kmsKeyARN,
	})
	if err != nil {
		return fmt.Errorf("provision tenants: %w", err)
	}

	manifest := bootstrapManifest{
		Seed:        *seed,
		Count:       len(tenants),
		PostgresURL: redactedDSN(*postgresURL),
		GeneratedAt: time.Now().UTC(),
		Tenants:     tenants,
	}
	if err := writeManifest(*out, manifest); err != nil {
		return fmt.Errorf("write manifest %s: %w", *out, err)
	}
	logger.Info("sn360-es-loadgen: bootstrap complete",
		slog.Int("count", manifest.Count),
		slog.String("manifest", *out),
	)
	return nil
}

// provisionRequest carries the inputs to provisionTenants. It is a
// struct so the function signature stays readable and so callers in
// the unit tests can build it from a table-driven fixture.
type provisionRequest struct {
	Count         int
	TenantPrefix  string
	NameFormat    string
	DisplayFormat string
	PrimaryDomain string
	Provider      string
	KMSKeyARN     string
}

// provisionTenants performs the bulk INSERT. It batches inserts so
// a single statement does not exceed Postgres' parameter limit
// (65535 placeholders per Extended Query). 5000 rows fit in one
// batch when we keep parameter count under that ceiling.
func provisionTenants(ctx context.Context, db *sql.DB, req provisionRequest) ([]bootstrapTenant, error) {
	tenants := make([]bootstrapTenant, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		tid, err := tenantID(req.TenantPrefix, i)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, bootstrapTenant{
			Index:    i,
			TenantID: tid,
			Name:     fmt.Sprintf(req.NameFormat, i),
			Provider: req.Provider,
		})
	}

	// Postgres' max bind parameters is 65535. We bind 6 columns per
	// row, so the safe per-batch upper bound is 65535/6 ~= 10922.
	// Batch at 2000 to keep individual statements small and easy
	// to recover from on transient failures.
	const rowsPerBatch = 2000
	const colsPerRow = 6

	const insertHead = `
INSERT INTO tenants
    (id, name, display_name, provider, primary_domain, kms_key_arn)
VALUES `
	const insertTail = `
ON CONFLICT (id) DO NOTHING`

	for start := 0; start < len(tenants); start += rowsPerBatch {
		end := start + rowsPerBatch
		if end > len(tenants) {
			end = len(tenants)
		}
		batch := tenants[start:end]

		var sb strings.Builder
		sb.WriteString(insertHead)
		args := make([]any, 0, len(batch)*colsPerRow)
		for i, t := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			base := i*colsPerRow + 1
			fmt.Fprintf(&sb, "($%d, $%d, $%d, $%d, $%d, $%d)",
				base, base+1, base+2, base+3, base+4, base+5)
			args = append(args,
				t.TenantID,
				t.Name,
				fmt.Sprintf(req.DisplayFormat, t.Index),
				req.Provider,
				req.PrimaryDomain,
				req.KMSKeyARN,
			)
		}
		sb.WriteString(insertTail)
		if _, err := db.ExecContext(ctx, sb.String(), args...); err != nil {
			return nil, fmt.Errorf("insert batch [%d:%d]: %w", start, end, err)
		}
	}

	return tenants, nil
}

// tenantID derives a UUID-shaped string from the prefix and index.
// The prefix is "00000000-0000-0000-0000-" (24 chars) and the index
// is zero-padded into the trailing 12-hex-char slot. Examples:
//
//	index=0    -> 00000000-0000-0000-0000-000000000000
//	index=4999 -> 00000000-0000-0000-0000-000000001387
//
// We refuse indexes that overflow the 12-char slot so the caller
// can't accidentally collide adjacent tenants on a future, larger
// run.
func tenantID(prefix string, index int) (string, error) {
	if index < 0 {
		return "", fmt.Errorf("tenantID: index must be >= 0, got %d", index)
	}
	const maxIndex = 1<<48 - 1 // 12 hex chars = 48 bits
	if index > maxIndex {
		return "", fmt.Errorf("tenantID: index %d overflows 12 hex chars", index)
	}
	return fmt.Sprintf("%s%012x", prefix, index), nil
}

// writeManifest writes the bootstrap manifest to path with secure
// permissions. The directory is created on demand so the default
// `tests/load/results/` location works out of the box.
func writeManifest(path string, m bootstrapManifest) error {
	if path == "" {
		return errors.New("manifest path required")
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// redactedDSN trims the password from a libpq URL so the manifest
// can record the DSN shape for reproducibility without leaking the
// dev password into a checked-in artefact.
func redactedDSN(raw string) string {
	idx := strings.Index(raw, "@")
	if idx < 0 {
		return raw
	}
	prefix := raw[:idx]
	if colon := strings.LastIndex(prefix, ":"); colon >= 0 {
		// Only mask the password if we can see the user:password
		// boundary; otherwise leave the string untouched.
		if scheme := strings.Index(prefix, "://"); scheme >= 0 && colon > scheme+2 {
			return prefix[:colon+1] + "REDACTED" + raw[idx:]
		}
	}
	return raw
}

// dirOf is a tiny wrapper around filepath.Dir that returns "." when
// path has no directory component, which is the contract os.MkdirAll
// expects (it returns an error on the empty string).
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
