-- 0001_init.down.sql
-- Reverse of 0001_init.up.sql. Drops tables in reverse-dependency order.

BEGIN;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS escalation_tickets;
DROP TABLE IF EXISTS simulation_results;
DROP TABLE IF EXISTS campaigns;
DROP TABLE IF EXISTS communication_histories;
DROP TABLE IF EXISTS evaluation_results;
DROP TABLE IF EXISTS vendors;
DROP TABLE IF EXISTS email_classifications;
DROP TABLE IF EXISTS score_engine;
DROP TABLE IF EXISTS labels;
DROP TABLE IF EXISTS group_memberships;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

COMMIT;
