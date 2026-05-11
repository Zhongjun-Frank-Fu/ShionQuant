-- Add `metadata` (jsonb) to custom_projects (added 2026-05).
-- Idempotent — safe to run multiple times.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0006_custom_projects_metadata.sql

alter table custom_projects
  add column if not exists metadata jsonb;

do $$ begin
  raise notice 'custom_projects.metadata column ready';
end $$;
