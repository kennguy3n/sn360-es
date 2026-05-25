-- 0013_score_engine_tier1_thresholds.up.sql
-- Add Tier 1 (encoder-stage) decision thresholds to the per-tenant
-- score_engine row so the tuning agent can persist its full
-- Thresholds bundle. The 5 banner thresholds (BannerBlocked /
-- BannerHighRisk / BannerWarning / BannerCaution / BannerInfo) were
-- already covered; Tier1PassBelow and Tier1FlagAbove were not, and
-- were previously lost on every restart because the agent's
-- ConfigStore was an in-memory map.
--
-- Defaults match `internal/service/agent/onboarding.go` (which seeds
-- the bundle for newly-onboarded tenants).

BEGIN;

ALTER TABLE score_engine
    ADD COLUMN IF NOT EXISTS threshold_tier1_pass_below INT NOT NULL DEFAULT 20,
    ADD COLUMN IF NOT EXISTS threshold_tier1_flag_above INT NOT NULL DEFAULT 60;

-- Keep PassBelow < FlagAbove so the gating semantics stay sane:
-- "pass below" is the lower bound below which Tier 0 short-circuits
-- a clear verdict; "flag above" is the upper bound above which Tier 1
-- promotes to Tier 2 for the SLM. Mis-configured rows shouldn't be
-- allowed to insert.
--
-- Postgres does not support `ADD CONSTRAINT IF NOT EXISTS`, so we
-- drop-then-add in a transaction to make the migration re-runnable.
ALTER TABLE score_engine
    DROP CONSTRAINT IF EXISTS chk_score_engine_tier1_pass_below_lt_flag_above;
ALTER TABLE score_engine
    ADD  CONSTRAINT       chk_score_engine_tier1_pass_below_lt_flag_above
        CHECK (threshold_tier1_pass_below < threshold_tier1_flag_above);

COMMIT;
