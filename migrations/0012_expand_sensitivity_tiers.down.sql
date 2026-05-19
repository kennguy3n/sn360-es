-- Revert any rows using new values before re-applying old constraints.
UPDATE users SET sensitivity_tier = 'executive' WHERE sensitivity_tier = 'critical';
UPDATE groups SET risk_class = 'standard'
    WHERE risk_class IN ('engineering', 'medical', 'legal', 'strategy', 'research');

-- Restore original constraints.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_sensitivity_tier_check;
ALTER TABLE users ADD CONSTRAINT users_sensitivity_tier_check
    CHECK (sensitivity_tier IN ('standard', 'elevated', 'executive'));

ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_risk_class_check;
ALTER TABLE groups ADD CONSTRAINT groups_risk_class_check
    CHECK (risk_class IN ('standard', 'finance', 'executive', 'hr', 'it'));
