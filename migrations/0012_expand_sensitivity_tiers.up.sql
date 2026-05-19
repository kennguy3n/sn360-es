-- Expand users.sensitivity_tier to support the new "critical" tier
-- for infrastructure-access roles (DBA, SysAdmin, Cloud Admin, etc.).
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_sensitivity_tier_check;
ALTER TABLE users ADD CONSTRAINT users_sensitivity_tier_check
    CHECK (sensitivity_tier IN ('standard', 'elevated', 'executive', 'critical'));

-- Expand groups.risk_class to support new industry verticals
-- (engineering, medical, legal, strategy, research).
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_risk_class_check;
ALTER TABLE groups ADD CONSTRAINT groups_risk_class_check
    CHECK (risk_class IN ('standard', 'finance', 'executive', 'hr', 'it',
                          'engineering', 'medical', 'legal', 'strategy', 'research'));
