package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/kennguy3n/sn360-es/pkg/intel"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// PgIntelStore implements intel.IntelStore against Postgres.
//
// The store is deployment-scoped (no tenant_id column on either
// table) so the Postgres SET LOCAL app.tenant_id row-level-security
// path is intentionally skipped. Callers MUST hand it an unbound
// *postgres.DB — binding to a tenant would force a default-deny
// outcome under the project's tenant-isolation policy and the
// worker would observe an empty feeds list every cycle.
//
// See the migration 0024 down-script for the documented exemption
// in cmd/sn360-es-tenant-lint/main.go.
type PgIntelStore struct {
	db  *postgres.DB
	now func() time.Time
}

// NewPgIntelStore constructs a Postgres-backed IntelStore.
func NewPgIntelStore(db *postgres.DB) *PgIntelStore {
	return &PgIntelStore{db: db, now: time.Now}
}

// Statically assert that the Postgres store satisfies the
// IntelStore contract. New methods added to the interface fail
// the build here rather than at runtime.
var _ intel.IntelStore = (*PgIntelStore)(nil)

// WithClock overrides the clock seam for tests.
func (s *PgIntelStore) WithClock(now func() time.Time) *PgIntelStore {
	s.now = now
	return s
}

// ListFeeds returns every feed row ordered by name. Disabled feeds
// are included; the worker filters by .Enabled in Go so admin UIs
// can show disabled feeds without an extra query.
func (s *PgIntelStore) ListFeeds(ctx context.Context) ([]intel.Feed, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, provider, url, fetch_interval, enabled,
       last_fetched_at, last_ok, last_error, consecutive_failures, created_at
FROM intel_feeds
ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("intel: list feeds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]intel.Feed, 0, 8)
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intel: list feeds: %w", err)
	}
	return out, nil
}

// GetFeed returns the feed by id.
func (s *PgIntelStore) GetFeed(ctx context.Context, id string) (intel.Feed, error) {
	if !validUUID(id) {
		return intel.Feed{}, intel.ErrFeedNotFound
	}
	return s.queryOneFeed(ctx, `WHERE id = $1`, id)
}

// GetFeedByName returns the feed by name.
func (s *PgIntelStore) GetFeedByName(ctx context.Context, name string) (intel.Feed, error) {
	if strings.TrimSpace(name) == "" {
		return intel.Feed{}, intel.ErrFeedNotFound
	}
	return s.queryOneFeed(ctx, `WHERE name = $1`, name)
}

func (s *PgIntelStore) queryOneFeed(ctx context.Context, where string, arg any) (intel.Feed, error) {
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`
SELECT id, name, provider, url, fetch_interval, enabled,
       last_fetched_at, last_ok, last_error, consecutive_failures, created_at
FROM intel_feeds
%s`, where), arg)
	f, err := scanFeed(row)
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Feed{}, intel.ErrFeedNotFound
	}
	if err != nil {
		return intel.Feed{}, fmt.Errorf("intel: get feed: %w", err)
	}
	return f, nil
}

// CreateFeed inserts a feed; returns ErrFeedExists on a unique
// violation. The returned Feed carries the server-generated id /
// created_at.
func (s *PgIntelStore) CreateFeed(ctx context.Context, f intel.Feed) (intel.Feed, error) {
	if f.Name == "" || f.Provider == "" || f.URL == "" {
		return intel.Feed{}, errors.New("intel: feed name, provider, url required")
	}
	interval := f.FetchInterval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO intel_feeds (name, provider, url, fetch_interval, enabled)
VALUES ($1, $2, $3, $4::interval, $5)
RETURNING id, name, provider, url, fetch_interval, enabled,
          last_fetched_at, last_ok, last_error, consecutive_failures, created_at`,
		f.Name, f.Provider, f.URL, formatInterval(interval), f.Enabled)
	out, err := scanFeed(row)
	if err != nil {
		if isUniqueViolation(err) {
			return intel.Feed{}, intel.ErrFeedExists
		}
		return intel.Feed{}, fmt.Errorf("intel: create feed: %w", err)
	}
	return out, nil
}

// UpdateFeed applies patch. Zero-value patches are no-ops; the
// returned Feed reflects the row post-update.
func (s *PgIntelStore) UpdateFeed(ctx context.Context, id string, patch intel.FeedPatch) (intel.Feed, error) {
	if !validUUID(id) {
		return intel.Feed{}, intel.ErrFeedNotFound
	}
	set := make([]string, 0, 3)
	args := make([]any, 0, 4)
	if patch.URL != nil {
		args = append(args, *patch.URL)
		set = append(set, fmt.Sprintf("url = $%d", len(args)))
	}
	if patch.FetchInterval != nil {
		args = append(args, formatInterval(*patch.FetchInterval))
		set = append(set, fmt.Sprintf("fetch_interval = $%d::interval", len(args)))
	}
	if patch.Enabled != nil {
		args = append(args, *patch.Enabled)
		set = append(set, fmt.Sprintf("enabled = $%d", len(args)))
	}
	if len(set) == 0 {
		// Nothing to update — just return the current row.
		return s.GetFeed(ctx, id)
	}
	args = append(args, id)
	q := fmt.Sprintf(`
UPDATE intel_feeds
SET %s
WHERE id = $%d
RETURNING id, name, provider, url, fetch_interval, enabled,
          last_fetched_at, last_ok, last_error, consecutive_failures, created_at`,
		strings.Join(set, ", "), len(args))
	row := s.db.QueryRowContext(ctx, q, args...)
	f, err := scanFeed(row)
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Feed{}, intel.ErrFeedNotFound
	}
	if err != nil {
		return intel.Feed{}, fmt.Errorf("intel: update feed: %w", err)
	}
	return f, nil
}

// DeleteFeed removes the feed; CASCADE drops owned indicators.
func (s *PgIntelStore) DeleteFeed(ctx context.Context, id string) error {
	if !validUUID(id) {
		return intel.ErrFeedNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM intel_feeds WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("intel: delete feed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return intel.ErrFeedNotFound
	}
	return nil
}

// RecordFeedResult writes the post-poll bookkeeping atomically.
// On a successful poll consecutive_failures is reset to 0; on a
// failure it increments. The 3-strike rule is enforced by the
// scheduler reading this column rather than the store.
func (s *PgIntelStore) RecordFeedResult(ctx context.Context, id string, ok bool, fetchedAt time.Time, errMsg string) error {
	if !validUUID(id) {
		return intel.ErrFeedNotFound
	}
	var nullErr sql.NullString
	if !ok && errMsg != "" {
		nullErr = sql.NullString{String: errMsg, Valid: true}
	}
	q := `
UPDATE intel_feeds
SET last_fetched_at = $1,
    last_ok = $2,
    last_error = $3,
    consecutive_failures = CASE WHEN $2 THEN 0 ELSE consecutive_failures + 1 END
WHERE id = $4`
	res, err := s.db.ExecContext(ctx, q, fetchedAt, ok, nullErr, id)
	if err != nil {
		return fmt.Errorf("intel: record feed result: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return intel.ErrFeedNotFound
	}
	return nil
}

// UpsertIndicators applies INSERT … ON CONFLICT for each Indicator
// in a single statement using the standard multi-row VALUES form.
// The hot-path constraint is correctness rather than throughput:
// the scheduler dispatches one poller at a time per feed, so a
// single round-trip per feed is acceptable.
//
// ON CONFLICT updates last_seen to now and bumps severity via
// GREATEST so a higher-confidence republish wins. first_seen and
// the feed_id stay pinned to whichever feed first reported the
// hash.
func (s *PgIntelStore) UpsertIndicators(ctx context.Context, feedID string, indicators []intel.Indicator) (int, error) {
	if !validUUID(feedID) {
		return 0, fmt.Errorf("intel: invalid feed id %q", feedID)
	}
	if len(indicators) == 0 {
		return 0, nil
	}
	// Build a multi-row VALUES statement. We use $1, $2, … placeholders
	// rather than COPY because Postgres' ON CONFLICT semantics on COPY
	// require an intermediate table and we want the single-statement
	// shape.
	const rowCols = 7
	var b strings.Builder
	b.WriteString(`INSERT INTO intel_indicators (hash, indicator, indicator_type, feed_id, severity, tags, last_seen) VALUES `)
	args := make([]any, 0, len(indicators)*rowCols)
	now := s.now()
	for i, ind := range indicators {
		if i > 0 {
			b.WriteString(", ")
		}
		base := i * rowCols
		fmt.Fprintf(&b, "($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7)
		args = append(args,
			ind.Hash,
			ind.Indicator,
			string(ind.Type),
			feedID,
			ind.Severity,
			pq.Array(ind.Tags),
			now,
		)
	}
	b.WriteString(`
ON CONFLICT (hash, feed_id) DO UPDATE
SET indicator = EXCLUDED.indicator,
    indicator_type = EXCLUDED.indicator_type,
    last_seen = EXCLUDED.last_seen,
    severity = GREATEST(intel_indicators.severity, EXCLUDED.severity),
    tags = EXCLUDED.tags`)
	res, err := s.db.ExecContext(ctx, b.String(), args...)
	if err != nil {
		return 0, fmt.Errorf("intel: upsert indicators: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// LookupByHash is the Tier 0 hot-path query. Postgres' hash array
// equality uses the PK index for `hash`, so the plan is
// index-only-scan over the (hash) PK. The feed_id is dragged
// along for the audit metadata; intel_indicators is composite-
// keyed on (hash, feed_id) so the same hash can map to multiple
// rows (one per feed) — we return them all.
func (s *PgIntelStore) LookupByHash(ctx context.Context, hashes [][]byte) ([]intel.MatchedIndicator, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT i.hash, i.indicator, i.indicator_type,
       i.feed_id, f.name, i.severity, i.tags, i.last_seen
FROM intel_indicators i
JOIN intel_feeds f ON f.id = i.feed_id
WHERE i.hash = ANY($1::bytea[])`, pq.Array(hashes))
	if err != nil {
		return nil, fmt.Errorf("intel: lookup hashes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]intel.MatchedIndicator, 0, 4)
	for rows.Next() {
		mi, err := scanMatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, mi)
	}
	return out, rows.Err()
}

// FindByIndicator canonicalises the input and looks up by hash for
// the single-row debug case. Multiple feed rows for the same hash
// are returned. The set of candidate hashes is de-duplicated via
// uniqueCandidateHashes so a value that canonicalises identically
// under multiple types doesn't multiply matches.
func (s *PgIntelStore) FindByIndicator(ctx context.Context, indicator string) ([]intel.MatchedIndicator, error) {
	hashes := uniqueCandidateHashes(indicator)
	if len(hashes) == 0 {
		return nil, nil
	}
	return s.LookupByHash(ctx, hashes)
}

// RecordStaleAlert appends an audit_logs row with tenant_id=NULL
// (the column is nullable for system events). The metadata JSON
// captures the feed id/name, failure count and most recent error
// so operators can pivot from the Prometheus alert to the audit
// trail by `action='intel.feed.stale'`.
//
// audit_logs has FORCE ROW LEVEL SECURITY (migration 0018) with a
// WITH CHECK policy that demands EITHER `sn360.tenant_id` matches
// the row OR `sn360.cross_tenant = 'on'` on the connection. The
// intel store is deployment-scoped, so it has no tenant id to bind;
// we instead acquire a cross-tenant-pinned conn for the lifetime of
// the INSERT, satisfying the OR-branch of the policy and writing
// the audit row with tenant_id=NULL. Without this binding the
// INSERT would silently be rejected by the policy (the worker would
// see a logged error but operators would never see the audit
// trail).
func (s *PgIntelStore) RecordStaleAlert(ctx context.Context, feedID, feedName string, failures int, lastError string, occurredAt time.Time) error {
	meta, err := json.Marshal(map[string]any{
		"feed_id":    feedID,
		"feed_name":  feedName,
		"failures":   failures,
		"last_error": lastError,
	})
	if err != nil {
		// json.Marshal on this map literal cannot fail; the
		// guard exists to satisfy the linter and provide a
		// safe fallback for hypothetical future fields.
		meta = []byte(`{}`)
	}
	ctxCT, release, err := s.db.WithCrossTenant(ctx)
	if err != nil {
		return fmt.Errorf("intel: record stale alert: bind cross-tenant: %w", err)
	}
	defer func() { _ = release() }()
	if _, err := s.db.ExecContext(ctxCT, `
INSERT INTO audit_logs (id, tenant_id, actor, action, target_type, target_hash, correlation_id, metadata, created_at)
VALUES (gen_random_uuid(), NULL, 'intel-worker', 'intel.feed.stale', 'intel_feed', NULL, $1, $2::jsonb, $3)`,
		feedID, meta, occurredAt); err != nil {
		return fmt.Errorf("intel: record stale alert: %w", err)
	}
	return nil
}

// GarbageCollect deletes indicators whose last_seen is older than
// cutoff AND for which no other feed_id holds a fresher row. The
// "fresher elsewhere" condition is checked via a NOT EXISTS
// correlated subquery so the planner can use the (hash) PK index.
//
// Returns the count of deleted rows.
func (s *PgIntelStore) GarbageCollect(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
DELETE FROM intel_indicators AS a
WHERE a.last_seen < $1
  AND NOT EXISTS (
    SELECT 1
    FROM intel_indicators AS b
    WHERE b.hash = a.hash
      AND b.feed_id <> a.feed_id
      AND b.last_seen >= $1
  )`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("intel: gc: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ---- helpers --------------------------------------------------------------

// scanFeed reads a single intel_feeds row. The scanner accepts both
// *sql.Row and *sql.Rows because lib/pq's *sql.Row and *sql.Rows
// have identical Scan signatures.
type sqlScanner interface {
	Scan(...any) error
}

func scanFeed(s sqlScanner) (intel.Feed, error) {
	var (
		f             intel.Feed
		intervalText  string
		lastFetchedAt sql.NullTime
		lastOK        sql.NullBool
		lastError     sql.NullString
	)
	if err := s.Scan(
		&f.ID,
		&f.Name,
		&f.Provider,
		&f.URL,
		&intervalText,
		&f.Enabled,
		&lastFetchedAt,
		&lastOK,
		&lastError,
		&f.ConsecutiveFailures,
		&f.CreatedAt,
	); err != nil {
		return intel.Feed{}, err
	}
	dur, err := parsePGInterval(intervalText)
	if err != nil {
		return intel.Feed{}, fmt.Errorf("intel: parse interval %q: %w", intervalText, err)
	}
	f.FetchInterval = dur
	if lastFetchedAt.Valid {
		t := lastFetchedAt.Time
		f.LastFetchedAt = &t
	}
	if lastOK.Valid {
		b := lastOK.Bool
		f.LastOK = &b
	}
	if lastError.Valid {
		f.LastError = lastError.String
	}
	return f, nil
}

func scanMatch(rows *sql.Rows) (intel.MatchedIndicator, error) {
	var (
		mi   intel.MatchedIndicator
		typ  string
		tags pq.StringArray
	)
	if err := rows.Scan(
		&mi.Hash,
		&mi.Indicator,
		&typ,
		&mi.FeedID,
		&mi.FeedName,
		&mi.Severity,
		&tags,
		&mi.LastSeen,
	); err != nil {
		return intel.MatchedIndicator{}, fmt.Errorf("intel: scan match: %w", err)
	}
	mi.IndicatorType = intel.IndicatorType(typ)
	mi.Tags = []string(tags)
	return mi, nil
}

// formatInterval serialises a Go duration as a Postgres interval
// literal in microseconds. Postgres accepts `123 microseconds`,
// `1 hour 30 minutes`, etc.; the microsecond form is unambiguous
// and round-trips losslessly for durations under ~292,000 years.
func formatInterval(d time.Duration) string {
	micros := d.Microseconds()
	return fmt.Sprintf("%d microseconds", micros)
}

// parsePGInterval converts an `interval`-typed column value to a
// Go time.Duration. lib/pq returns intervals as ISO-8601-ish text
// (e.g. "00:15:00" or "1 day 02:00:00"); we support the common
// `[D days ]HH:MM:SS[.fraction]` shape because that is the only
// format the migration emits.
func parsePGInterval(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	var days int
	rest := s
	if idx := strings.Index(s, " day"); idx > 0 {
		_, err := fmt.Sscanf(s, "%d", &days)
		if err != nil {
			return 0, err
		}
		// Advance past "X days " or "X day ".
		sp := strings.Index(s, " ")
		if sp < 0 {
			return 0, fmt.Errorf("bad interval: %q", s)
		}
		// Skip "N day[s]" header.
		_, after, ok := strings.Cut(s[sp+1:], " ")
		if !ok {
			rest = ""
		} else {
			rest = after
		}
	}
	d := time.Duration(days) * 24 * time.Hour
	if rest == "" {
		return d, nil
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 3 {
		return 0, fmt.Errorf("bad interval body: %q", rest)
	}
	var h, m int
	var sec float64
	if _, err := fmt.Sscanf(parts[0], "%d", &h); err != nil {
		return 0, fmt.Errorf("interval hours: %w", err)
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &m); err != nil {
		return 0, fmt.Errorf("interval minutes: %w", err)
	}
	if _, err := fmt.Sscanf(parts[2], "%f", &sec); err != nil {
		return 0, fmt.Errorf("interval seconds: %w", err)
	}
	d += time.Duration(h) * time.Hour
	d += time.Duration(m) * time.Minute
	d += time.Duration(sec * float64(time.Second))
	return d, nil
}

// validUUID reports whether s parses as a UUID. We deliberately do
// NOT canonicalise — the caller's input is treated as opaque text
// and passed to the database unchanged; the format check just
// keeps obviously-malformed input from triggering a coercion
// error inside Postgres.
func validUUID(s string) bool {
	if s == "" {
		return false
	}
	_, err := uuid.Parse(s)
	return err == nil
}
