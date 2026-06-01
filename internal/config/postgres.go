package config

// Multi-region routing config (WS-7a).
//
// This file owns the parser for `PG_REGION_MAP` — the JSON env var that
// declares one Postgres connection URL per region:
//
//	PG_REGION_MAP={"ap-southeast-1": "postgres://user:pw@host:5432/db?sslmode=require",
//	               "us-east-1":      "postgres://user:pw@host:5432/db?sslmode=require"}
//
// Each entry is decomposed into a fully-populated [Postgres] value: host,
// port, user, password, database, sslmode come from the URL; pool-shape
// fields (MaxOpenConns / MaxIdleConns / ConnMaxLifetime) inherit from the
// primary Postgres struct loaded via the existing PG_HOST / PG_PORT / …
// env vars so operators only have to specify the per-region wiring, not
// the pool sizing.
//
// The companion env var `PG_HOME_REGION` (default `"ap-southeast-1"` —
// matches the `tenants.region` column default in
// `migrations/0001_init.up.sql:25`) names the region that the primary
// `PG_HOST` pool serves. Tenants whose region equals PG_HOME_REGION are
// served by the primary pool (no double-open); other regions get their
// own pool from PG_REGION_MAP.
//
// Backward compatibility: when `PG_REGION_MAP` is empty or unset the
// returned map is nil and the binary continues to run single-pool against
// `PG_HOST` / `PG_READ_HOST` unchanged. This is the default for every
// existing single-region deployment.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// sortedRegionKeys returns the keys of m in lexicographic order. The
// stable ordering matters for two reasons: (a) error messages and boot
// logs are reproducible (an operator copy-pasting a stack trace into a
// ticket reads the same region list every time), and (b) the regional
// pool open loop in cmd/sn360-es/app.go uses this ordering so a
// startup-time partial failure logs the regions in a deterministic
// order rather than Go's randomised map iteration order.
func sortedRegionKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parsePostgresRegionMap parses the JSON `PG_REGION_MAP` payload into a
// region-keyed map of fully-populated Postgres connection settings.
//
// Empty / whitespace-only input returns (nil, nil) so callers can treat
// "no region map" identically to "single-region deployment". Any other
// failure mode (invalid JSON, empty region name, unparseable URL, missing
// scheme/host/database) returns a wrapped error naming the offending
// region so the boot log points operators at the exact entry to fix.
//
// Pool-shape fields (MaxOpenConns / MaxIdleConns / ConnMaxLifetime) on
// each returned Postgres value are copied from base so operators only
// have to declare per-region wiring in PG_REGION_MAP; tuning pool sizes
// continues to flow through the existing PG_MAX_OPEN_CONNS /
// PG_MAX_IDLE_CONNS / PG_CONN_MAX_LIFETIME env vars and applies
// uniformly across every regional pool.
func parsePostgresRegionMap(raw string, base Postgres) (map[string]Postgres, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var byRegion map[string]string
	if err := json.Unmarshal([]byte(raw), &byRegion); err != nil {
		return nil, fmt.Errorf("PG_REGION_MAP: invalid JSON: %w", err)
	}
	if len(byRegion) == 0 {
		return nil, errors.New("PG_REGION_MAP: must contain at least one region (set the env var to empty to disable region routing)")
	}
	out := make(map[string]Postgres, len(byRegion))
	for region, dsn := range byRegion {
		trimmed := strings.TrimSpace(region)
		if trimmed == "" {
			return nil, errors.New("PG_REGION_MAP: region name must not be empty")
		}
		pg, err := postgresFromURL(dsn, base)
		if err != nil {
			return nil, fmt.Errorf("PG_REGION_MAP[%s]: %w", trimmed, err)
		}
		out[trimmed] = pg
	}
	return out, nil
}

// postgresFromURL decomposes a `postgres://user:pw@host:port/db?sslmode=…`
// URL into a Postgres struct, falling back to the supplied base struct
// for any field the URL leaves blank (port, user/password, sslmode,
// pool-shape fields). The Read field on the returned struct is always
// zero — regional read-replica routing is out of scope for WS-7a (every
// regional pool runs single-pool against its primary; layering replica
// awareness on top would multiply pool count by 2 and is deferred until
// an operator actually needs it).
func postgresFromURL(raw string, base Postgres) (Postgres, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Postgres{}, errors.New("connection URL must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Postgres{}, fmt.Errorf("parse URL: %w", err)
	}
	switch u.Scheme {
	case "postgres", "postgresql":
		// ok
	default:
		return Postgres{}, fmt.Errorf("scheme must be postgres or postgresql; got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return Postgres{}, errors.New("host must not be empty")
	}
	port := base.Port
	if portStr := u.Port(); portStr != "" {
		n, perr := strconv.Atoi(portStr)
		if perr != nil {
			return Postgres{}, fmt.Errorf("invalid port %q: %w", portStr, perr)
		}
		if n <= 0 || n > 65535 {
			return Postgres{}, fmt.Errorf("port %d out of range (1-65535)", n)
		}
		port = n
	}
	if port <= 0 {
		port = 5432
	}
	user := base.User
	password := base.Password
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			user = name
		}
		if pw, ok := u.User.Password(); ok {
			password = pw
		}
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return Postgres{}, errors.New("database name (URL path) must not be empty")
	}
	sslMode := u.Query().Get("sslmode")
	if sslMode == "" {
		sslMode = base.SSLMode
	}
	return Postgres{
		Host:            host,
		Port:            port,
		User:            user,
		Password:        password,
		Database:        db,
		SSLMode:         sslMode,
		MaxOpenConns:    base.MaxOpenConns,
		MaxIdleConns:    base.MaxIdleConns,
		ConnMaxLifetime: base.ConnMaxLifetime,
	}, nil
}
