-- Add broker-precomputed buying power to accounts.
-- Idempotent — safe to run multiple times.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0002_buying_power.sql
--
-- Fresh databases get this from schema.sql automatically; this file is for
-- DBs provisioned before the buying-power column existed. NULL values fall
-- back to a Reg-T heuristic in the /api/v1/portfolio/cash endpoint.

alter table accounts
  add column if not exists buying_power_usd numeric(20, 4);

do $$ begin
  raise notice 'accounts.buying_power_usd column ready';
end $$;
