# Multi-Region Routing (WS-7a)

This document covers the deployment topology, env-var contract, and
failure semantics introduced by [WS-7a](PRODUCT_PLAN.md) — multi-region
routing for Postgres and the NATS super-cluster bridge.

## Why this exists

`sn360-es` runs as a single binary per region today. Each region has
its own Postgres cluster and NATS cluster; tenants are pinned to a
home region via the `tenants.region` column (default `ap-southeast-1`
— see [`migrations/0001_init.up.sql:25`](../../migrations/0001_init.up.sql)).
A single-region binary could only serve tenants whose `region` matched
its local Postgres. Cross-region traffic forced a load-balancer-level
hop that bypassed all the in-process RLS, caches, and bridge wiring.

WS-7a lets one binary instance serve tenants from **multiple regions**:
the tenant-context binder resolves the tenant's region at request
entry (HTTP middleware + NATS consumer wrapper), routes the query to
the matching regional Postgres pool, and (when configured) bridges
cross-region NATS subjects through the super-cluster.

Single-region deployments are unaffected. With `PG_REGION_MAP` empty
and `NATS_SUPERCLUSTER` empty the binary boots and runs identically to
the pre-WS-7a code path.

## Env-var contract

| Env var | Type | Default | Effect |
|---|---|---|---|
| `PG_DSN` / `PG_HOST` / `PG_PORT` / ... | scalar | (existing) | Primary Postgres pool. Unchanged. |
| `PG_READ_HOST` / ... | scalar | unset | Read-replica pool. Unchanged from WS-2a. |
| `PG_HOME_REGION` | scalar | `ap-southeast-1` | Names the region that the **primary pool** serves. MUST appear as a key in `PG_REGION_MAP` when that var is set. |
| `PG_REGION_MAP` | JSON object | empty | Maps `region -> postgres://...` URLs. When non-empty, one pool is opened per non-home region; tenants in those regions route through the regional pool. When empty, multi-region routing is disabled (single-region default). |
| `NATS_URL` / `NATS_USER` / ... | scalar | (existing) | Primary NATS connection. Unchanged. |
| `NATS_SUPERCLUSTER` | JSON object | empty | Maps `region -> "nats://leaf-a:4222,nats://leaf-b:4222"` URL lists. When non-empty, the home-region URL list is appended to `NATS_URL` so the client fails over to home-region leaf nodes. |

### `PG_REGION_MAP` shape

```json
{
  "ap-southeast-1": "postgres://sn360:pw@pg-ap.internal:5432/sn360?sslmode=require",
  "us-east-1":      "postgres://sn360:pw@pg-us-east-1.internal:5432/sn360?sslmode=verify-full",
  "eu-west-1":      "postgres://sn360:pw@pg-eu-west-1.internal:5432/sn360?sslmode=verify-full"
}
```

Pool-shape fields (`MaxOpenConns`, `MaxIdleConns`, `ConnMaxLifetime`)
are inherited from the primary `PG_MAX_OPEN_CONNS` / `PG_MAX_IDLE_CONNS`
/ `PG_CONN_MAX_LIFETIME` env vars so operators only specify the
per-region wiring; tuning continues to flow through the existing
scalar env vars and applies uniformly to every regional pool.

The home region's entry in `PG_REGION_MAP` must point at the same
Postgres reachable via `PG_HOST` — but the runtime does **not** open
a second pool for it (the primary pool doubles as the home-region
pool). This avoids burning ~25 extra idle connections on every boot
just to model the home region uniformly.

The boot-time validator enforces parity on `(host, port, database)`
between the home-region entry and `PG_HOST` / `PG_PORT` /
`PG_DATABASE` — a mismatch on any of those three fields means the
home entry's URL was parsed-and-validated but the actual home-region
traffic uses the primary pool's settings, which is a silent
misconfig. User and password are intentionally **not** part of the
parity check — operators commonly omit credentials from DSN strings
and supply them via `PG_USER` / `PG_PASSWORD` env vars instead.

### `NATS_SUPERCLUSTER` shape

```json
{
  "ap-southeast-1": "nats://nats-ap-1.internal:4222,nats://nats-ap-2.internal:4222",
  "us-east-1":      "nats://nats-us-1.internal:4222",
  "eu-west-1":      "nats://nats-eu-1.internal:4222"
}
```

The map is parsed at boot. The home-region entry (selected by
`PG_HOME_REGION`) is appended to `NATS_URL` and the merged
comma-separated list is what `nats.Connect` actually dials. nats.go
splits the list itself, so the primary URL (locally health-checked)
is tried first and the leaf-cluster URLs are the failover targets in
declared order. Duplicate entries are silently deduplicated so an
operator pasting the primary URL into the supercluster list does not
inflate the reconnect-attempt count.

Cross-region accounts, JetStream replication, and leaf-node deployment
are NATS-server-side concerns and remain operator responsibilities;
see the [NATS leaf-node docs](https://docs.nats.io/running-a-nats-service/configuration/leafnodes)
for the server side.

## Routing flow

```
HTTP request                               NATS message
─────────────                              ────────────
        │                                        │
        ▼                                        ▼
[JWT middleware]                          [consumer wrapper]
sets tenant_id in ctx                  reads tenant_id header
        │                                        │
        ▼                                        ▼
        └────── TenantConnBinder.bind() ───────────┘
                         │
                         │ regional == nil?
        ┌────────────────┴───────────────┐
        │ yes (single-region)            │ no (multi-region)
        ▼                                ▼
 pgDB.WithTenant(ctx,                  resolver.ResolveRegion(tenant_id)
                  tenant_id)              │
        │                                 │ region: "us-east-1"
        ▼                                 ▼
 returns ctx pinned                  regional.WithTenantInRegion(
   to primary pool                       ctx, region, tenant_id)
   with RLS GUC set                      │
                                         ▼
                                   ctx pinned to us-east-1 pool
                                   with RLS GUC set
```

`TenantConnBinder` lives at `internal/middleware/tenant_conn.go`. It
falls back to `pgDB.WithTenant` when either `Regional` or `Resolver`
is nil (single-region deployments), so the RLS contract holds in both
modes: every connection used to execute queries is bound to a single
tenant before any query runs.

## Region resolver

`internal/service/tenant/region.go` exposes `CachedRegionResolver`,
which wraps a `RegionLookup` against the home-region
`TenantRepository` with a 5-minute TTL in-memory cache.

- **Cache hits** answer in O(1) under a read lock.
- **Cache misses** issue one `SELECT region FROM tenants WHERE id = $1`
  against the home-region pool. The `tenants` table is NOT under RLS
  so the lookup runs on an unbound connection.
- **Successful lookups are cached.** Errors are NOT cached — a
  transient catalog-DB blip retries on the next request rather than
  poisoning the cache for the next TTL window.
- **Unknown tenants** surface `ErrTenantUnknown` and are not cached
  either; the cache resolver does not invent a region.
- **Region changes** are immutable today (changing a tenant's region
  requires a data migration), but `Invalidate(tenantID)` exists for
  the eventual catalog-event subscription that will flip cache
  entries on tenant edits.

## Failure semantics

| Misconfiguration | Where it fires | Fails at |
|---|---|---|
| `PG_REGION_MAP` malformed JSON | `internal/config.Load` | Boot |
| `PG_REGION_MAP` entry with bad URL | `internal/config.Load` | Boot |
| `PG_REGION_MAP[region]` reachable but DB closed | `postgres.Open` | Boot (fatal) |
| `PG_HOME_REGION` missing from `PG_REGION_MAP` | `internal/config.Validate` | Boot |
| `NATS_SUPERCLUSTER` malformed JSON | `internal/config.Load` | Boot |
| `NATS_SUPERCLUSTER` missing home-region entry | `pkg/events/nats.NewClient` | Boot |
| Tenant region lookup DB unavailable at request time | `RegionResolver.ResolveRegion` | Request (5xx) |
| Tenant region is configured but pool missing for it | `RegionalDB.WithTenantInRegion` | Request (5xx) |

The boot-time failures are loud on purpose: a deployment that
explicitly enumerated multiple regions in `PG_REGION_MAP` relies on
every region being reachable for tenant isolation. Silently dropping a
region would route its tenants to no pool at all and fail closed at
every request anyway — failing loudly at boot lets the operator catch
the misconfig before any traffic arrives.

Request-time failures (region lookup, missing pool) surface as 5xx
through the HTTP middleware and as NATS message NAKs through the
consumer wrapper. Both paths log the tenant ID + region so operators
can find the affected pool quickly.

## Operator deployment checklist

1. Confirm `tenants.region` is populated correctly for every tenant.
   (The default is `'ap-southeast-1'`; tenants explicitly moved to a
   different region should already have non-default values from the
   onboarding flow.)
2. Provision the per-region Postgres instances + run migrations on
   each. The Postgres URL in `PG_REGION_MAP` for each region must
   point at that region's primary, not its read replica.
3. Set `PG_HOME_REGION` to the region of the deployment's local
   Postgres (the one `PG_HOST` already points at).
4. Set `PG_REGION_MAP` to the JSON map of all regions including the
   home region.
5. Deploy and watch the boot log for the line
   `sn360-es: postgres regional router wired`. It enumerates each
   region's host so misrouting at the URL level (e.g. an `eu-west-1`
   entry pointing at `pg-us-east-1.internal`) is immediately visible.
6. (Optional) configure NATS leaf nodes per region and set
   `NATS_SUPERCLUSTER`. Each region's binary should declare the
   leaf-cluster URLs for **its own region** (the home-region entry).
   Operators may also list other regions for documentation /
   future-cross-region-publish work; this binary uses only the home-
   region entry for failover and ignores the rest.
7. Roll the deployment one region at a time. Cross-region tenants will
   start routing as soon as the binary they hit has both
   `PG_REGION_MAP` set and a Postgres pool open for their region.

## Tenant-row provisioning across regional pools

This binary opens **one pool per region** but does NOT replicate the
`tenants` catalog row across regional pools — every tenant-scoped
table in every regional pool carries a foreign-key reference to its
own `tenants.id`. The catalog (`tenants` table itself) lives on the
home region's pool by convention and is what the region resolver
queries to learn each tenant's region.

This means: **the `tenants` row for tenant T MUST exist in T's
regional pool before any handler binds T to that pool.** Concretely,
when the `onboarding.tenant.created` event fires for a non-home-region
tenant, the onboarding agent (now routing through the shared
region-aware binder) opens a connection on T's regional pool and
will hit FK violations on every tenant-scoped insert (labels,
evaluation_results, …) if T is not present in that pool's `tenants`
table.

Operators have two ways to satisfy this contract:

1. **Replicate tenant rows out-of-band** (recommended for prod). Run
   a logical-replication subscription (or equivalent) on the
   `tenants` table from the home region to each regional pool so a
   tenant row created on the catalog appears on every regional pool
   before the `onboarding.tenant.created` event is consumed. This is
   the same shape used by every multi-region SaaS — the catalog is
   the source of truth and regions are downstream subscribers.
2. **Pre-seed in the migration / provisioning script** (acceptable
   for small static tenant lists). The integration test
   `internal/repository/multi_region_test.go` uses this pattern —
   it `INSERT … tenants` into both regional pools explicitly before
   binding either pool's tenant context.

A future workstream may add an in-process "tenant catalog
replicator" that subscribes to onboarding events and writes the
`tenants` row to the right regional pool before publishing a
`tenant.regional.ready` ack. For now, the operator workflow above is
the documented contract; the regional pool is treated as opaque
infrastructure that the operator is responsible for keeping
catalog-aligned.

## Failover behaviour

- **Regional Postgres pool down.** Requests for tenants in that region
  fail closed at the middleware boundary. Requests for tenants in
  other regions continue to succeed — the routing layer does NOT fall
  back to the home pool on regional outage (doing so would either
  bypass RLS or accidentally cross-tenant data into the wrong
  region's tables). Operators alert on the per-region error rate and
  page if a single region's error budget drains.
- **Home Postgres pool down.** Same as a single-region outage: every
  request fails closed because the tenant resolver also runs on the
  home pool. This is intentional: the home pool is the catalog DB,
  so its availability is a hard binary boot precondition.
- **NATS primary down.** The reconnect loop dials the home-region
  leaf-cluster URLs from `NATS_SUPERCLUSTER` in order. The first
  successful dial wins and the client stays on that leaf until the
  primary recovers and a manual reconnect (or a leaf failure) flips
  it back.
- **NATS supercluster entry missing for home region.** Boot fails
  loudly. There is no silent degradation to "primary only" because
  the operator who set `NATS_SUPERCLUSTER` clearly intended the
  failover and the missing entry is almost certainly a typo.

## Testing

- Unit tests pin the parse + canonicalisation behaviour for both env
  vars: see `internal/config/postgres_region_test.go` and
  `internal/config/supercluster_test.go`.
- Unit tests pin the option-builder behaviour for the NATS super-
  cluster URL merge: see `pkg/events/nats/supercluster_test.go`.
- Unit tests pin the region resolver cache + TTL semantics: see
  `internal/service/tenant/region_test.go`.
- An end-to-end integration test
  (`internal/repository/multi_region_test.go`) spins up TWO
  testcontainers Postgres instances and proves that tenant-context
  binding routes the right pool by writing a region-specific marker
  row in each region and verifying both can be read back without
  cross-region leakage.
