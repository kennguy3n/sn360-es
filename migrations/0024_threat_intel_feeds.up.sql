-- 0024_threat_intel_feeds.up.sql
--
-- WS-5B.3 Threat-intel feed consumption.
--
-- Adds first-class threat-intel matching to the Tier 0 gate by
-- persisting two tables:
--
--   1. `intel_feeds` — operator-registered feed definitions
--      (provider, url, fetch_interval, enabled flag). The
--      intel_worker scheduler (internal/service/worker/intel_worker.go)
--      polls enabled rows on a cadence and dispatches to the
--      provider-specific poller in pkg/intel/<provider>/.
--
--   2. `intel_indicators` — the canonicalised IOCs the pollers
--      upsert. Each row keys off `hash` (SHA-256 of the
--      canonicalised indicator), with the raw indicator + type +
--      severity + tags carried alongside for the Tier 0 gate to
--      surface in audit / banner metadata.
--
-- Scoping decision: these tables are DEPLOYMENT-scoped, NOT
-- tenant-scoped. Threat-intel feeds (URLhaus, MISP, STIX-TAXII,
-- generic CSV) are operator-curated against the global threat
-- landscape, not customer-tenant data. The same `urlhaus-recent`
-- feed is consulted for every tenant's mail, and an indicator
-- match is a verdict about the IOC, not about the message's
-- tenant context.
--
-- Concretely:
--   - No `tenant_id` column on either table.
--   - No RLS policy (the RLS framework in 0018 is for
--     per-tenant row visibility; deployment-global tables would
--     fail-closed under an unset `sn360.tenant_id` GUC, which is
--     the opposite of what we want).
--   - The tenant-lint analyser (cmd/sn360-es-tenant-lint/main.go)
--     intentionally does NOT register these tables. The drift
--     guard in main_test.go enforces the reverse direction —
--     "every RLS-protected table must be in tenantScopedTables"
--     — but since these tables have no RLS, the drift guard
--     does not flag them. Operators reading the lint config
--     should see this comment block as the source of the
--     exemption.
--
-- Hot-path discipline. The Tier 0 gate lookup is
--   SELECT hash FROM intel_indicators WHERE hash = ANY($1)
-- which is an index-only scan against the PK and the only
-- Postgres call on the hot path. The Redis negative cache in
-- internal/service/evaluate/intel_cache.go absorbs duplicate
-- lookups (5-minute TTL); the indexes below cover the analytical
-- access patterns (the indicator-type filter on the debug
-- endpoint, and the tag-array GIN index for ad-hoc audit
-- queries).
--
-- Garbage collection. The intel_worker GC sweep deletes
-- indicators with `last_seen < now() - 30 days AND no other
-- feed_id references it` — URLhaus rotates aggressively and a
-- stale IOC can produce false-positive blocks. The FK to
-- intel_feeds is `ON DELETE CASCADE` so an operator who removes
-- a feed via DELETE /v1/intel/feeds/{id} drops the indicators
-- the feed owned in one transaction.

BEGIN;

-- ----------------------------------------------------------------------
-- 1. intel_feeds — feed registry.
--
-- Owned by operators / admins (the admin HTTP surface in
-- internal/handler/intel_feeds.go writes here). The scheduler
-- READs every minute to find feeds whose `last_fetched_at` is
-- older than `fetch_interval`, dispatches the poller, then WRITES
-- back the success / failure state for observability.
-- ----------------------------------------------------------------------

CREATE TABLE intel_feeds (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Stable operator-chosen name. UNIQUE so the operator can
    -- look up by name in the admin API without juggling UUIDs,
    -- and so the worker logs reference a memorable identifier.
    name                     TEXT NOT NULL UNIQUE,
    -- Provider key — selects the poller in pkg/intel/registry.go.
    -- Constrained to the four supported providers; widening
    -- requires both a migration AND a new poller package.
    provider                 TEXT NOT NULL
        CHECK (provider IN ('urlhaus', 'misp', 'stix-taxii', 'csv')),
    -- Endpoint URL. For MISP the URL is the API base; for STIX
    -- TAXII the URL is the collection objects endpoint; for
    -- urlhaus / csv the URL is the CSV download.
    url                      TEXT NOT NULL CHECK (length(url) > 0),
    fetch_interval           INTERVAL NOT NULL DEFAULT '15 minutes',
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    last_fetched_at          TIMESTAMPTZ,
    last_ok                  BOOLEAN,
    last_error               TEXT,
    -- consecutive_failures counts how many times in a row the
    -- poller has returned an error since the last success.
    -- intel_worker raises a Prometheus alert + emits an audit row
    -- once this reaches 3 so operators are not silently flying
    -- blind on a stuck feed. Reset to 0 on every successful
    -- fetch.
    consecutive_failures     INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_failures >= 0),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_intel_feeds_enabled_due
    ON intel_feeds (enabled, last_fetched_at)
    WHERE enabled = TRUE;

-- ----------------------------------------------------------------------
-- 2. intel_indicators — IOC store.
--
-- `hash` is the SHA-256 of the canonicalised indicator (lowercase,
-- IDN-normalised, trimmed `www.`). Using the hash as the PK has
-- three benefits:
--   - Index-only scans on the Tier 0 hot path (`SELECT hash FROM
--     intel_indicators WHERE hash = ANY($1)` reads only the PK).
--   - The pollers can do `INSERT … ON CONFLICT (hash) DO UPDATE
--     SET last_seen=now(), severity=GREATEST(...)` without
--     branching on shape.
--   - Two pollers that publish the same indicator under different
--     names collapse to one row; the GC predicate "no other
--     feed_id references it" then correctly preserves the
--     indicator while either feed is alive.
--
-- One indicator → one feed_id by design: the FK relationship is
-- the simplest shape that lets the GC predicate (`AND NOT EXISTS
-- (… same hash, different feed_id, last_seen > cutoff)`) operate
-- without a join table. Multi-feed indicators are handled by
-- recording one row per (hash, feed_id) and letting the
-- ON CONFLICT update keep last_seen current for whichever poller
-- last saw it.
-- ----------------------------------------------------------------------

CREATE TABLE intel_indicators (
    hash            BYTEA NOT NULL,
    indicator       TEXT NOT NULL CHECK (length(indicator) > 0),
    indicator_type  TEXT NOT NULL
        CHECK (indicator_type IN ('domain', 'url', 'ip', 'sha256')),
    feed_id         UUID NOT NULL REFERENCES intel_feeds(id) ON DELETE CASCADE,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    severity        SMALLINT NOT NULL DEFAULT 50
        CHECK (severity BETWEEN 0 AND 100),
    tags            TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (hash, feed_id)
);

-- Covering index on the hot-path lookup. `hash` alone is the PK
-- prefix, so `WHERE hash = ANY($1)` already uses the PK; the
-- explicit index here makes the planner choice deterministic
-- across PG versions and survives an accidental PK reshape.
CREATE INDEX idx_intel_indicators_hash
    ON intel_indicators (hash);

-- Filter index for the debug `GET /v1/intel/indicators?indicator=`
-- handler — the admin surface looks up by raw indicator + type,
-- and the per-type filter narrows the heap range read for
-- ad-hoc audit queries that count IPs vs URLs vs domains.
CREATE INDEX idx_intel_indicators_type
    ON intel_indicators (indicator_type);

-- GIN index on tags so operator queries like "every indicator
-- tagged 'malware/qakbot'" stay sub-second on large feed
-- populations.
CREATE INDEX idx_intel_indicators_tags
    ON intel_indicators USING GIN (tags);

-- Supports GC: "all indicators last_seen older than cutoff,
-- ordered by hash so the worker can stream them in batches".
CREATE INDEX idx_intel_indicators_last_seen
    ON intel_indicators (last_seen);

-- ----------------------------------------------------------------------
-- 3. sn360_app grants.
--
-- The intel worker and admin handlers run under the `sn360_app`
-- role. Both tables need full CRUD because:
--   - `intel_feeds`: the admin handlers (POST/PATCH/DELETE) and
--     the scheduler (UPDATE last_fetched_at / last_ok /
--     last_error / consecutive_failures) all mutate rows.
--   - `intel_indicators`: the pollers upsert (INSERT … ON
--     CONFLICT DO UPDATE) and the GC sweep DELETEs stale rows;
--     the admin debug endpoint only reads.
--
-- These tables are deployment-scoped (no tenant_id, no RLS) so
-- the grants are not subject to the per-tenant policy machinery
-- 0018 layered onto the business tables. A request that reaches
-- these tables has already cleared the admin auth middleware
-- (handler.RequireAdmin in internal/middleware/admin.go) or the
-- worker-internal scope.
-- ----------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sn360_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON intel_feeds       TO sn360_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON intel_indicators  TO sn360_app;
    END IF;
END $$;

COMMIT;
