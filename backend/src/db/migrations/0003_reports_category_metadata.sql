-- Add `category` + `metadata` (jsonb) to reports.
-- Idempotent — safe to run multiple times.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0003_reports_category_metadata.sql
--
-- Fresh databases get this from schema.sql automatically; this file is for
-- DBs provisioned before these columns existed.

alter table reports
  add column if not exists category text,
  add column if not exists metadata jsonb;

-- CHECK constraint on category (drop+recreate to keep idempotent).
alter table reports drop constraint if exists reports_category_check;
alter table reports add constraint reports_category_check check (
  category is null or category in (
    'must_read', 'attribution', 'quarterly_performance',
    'macro_regime', 'strategy_model', 'custom_research'
  )
);

do $$ begin
  raise notice 'reports.category + reports.metadata columns ready';
end $$;
