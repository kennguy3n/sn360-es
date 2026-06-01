-- 0023_score_engine_tier2_provider.up.sql
-- Per-tenant override for the Tier 2 (SLM) provider selection. Nullable
-- because the vast majority of tenants run on the deployment-default
-- provider (set via TIER2_PROVIDER); only tenants under active model
-- evaluation or vendor-diversification override here.
--
-- See WS-4c: pkg/inference/slm/registry.go documents the set of
-- supported provider names ("ternarybonsai", "llamaserver", "openai",
-- and any future providers added to pkg/inference/slm/providers/*).
-- We intentionally do NOT enforce a CHECK constraint on the value
-- here because the set of valid providers is binary-driven, not
-- DB-driven — a new provider should roll out without a migration.
-- Bogus values fall through to the deployment default at evaluator
-- resolve time (slm.Router.resolve), so a misconfigured row degrades
-- gracefully rather than blocking evaluation.

BEGIN;

ALTER TABLE score_engine
    ADD COLUMN IF NOT EXISTS tier2_provider TEXT DEFAULT NULL;

COMMIT;
