# SN360-ES Database Migrations

This directory holds the canonical Postgres schema for SN360-ES.

## Format

Plain SQL with the [golang-migrate](https://github.com/golang-migrate/migrate)
filename convention:

```
{version}_{name}.up.sql      # forward migration
{version}_{name}.down.sql    # reverse migration
```

Versions are zero-padded 4-digit integers, applied in ascending order.

## Tooling

The Makefile drives migrations through the `sn360-es-migrate` wrapper
under `cmd/sn360-es-migrate/`, which embeds golang-migrate v4 and the
Postgres driver. No external binary is required.

```bash
make migrate-up        # apply all pending migrations
make migrate-down      # rollback the most recent migration
make migrate-check     # validate filenames + parse all SQL files
make migrate-status    # show current schema version
make migrate-force VERSION=NN   # force-set schema version (recovery)
```

The wrapper reads the same `PG_*` environment variables as the rest of
the service (see `.env.example`). The migration table defaults to
`schema_migrations`.

## Conventions

- Every `.up.sql` MUST be accompanied by a `.down.sql` that exactly
  reverses it (drop tables, drop columns, restore defaults).
- Wrap multi-statement migrations in `BEGIN; ... COMMIT;` so a failure
  rolls back cleanly.
- Use `CREATE TABLE IF NOT EXISTS` / `DROP TABLE IF EXISTS` to keep
  migrations idempotent in dev/test loops.
- Never edit a committed migration — add a new one. The schema version
  is referenced by the migration table on every environment.

## Adding a Migration

```bash
NEXT=$(printf "%04d" $(( $(ls migrations/*.up.sql | wc -l) + 1 )))
$EDITOR "migrations/${NEXT}_add_widget.up.sql"
$EDITOR "migrations/${NEXT}_add_widget.down.sql"
make migrate-check
```
