-- Add `preferences` (jsonb) to calendar_subscriptions (added 2026-05).
-- Idempotent — safe to run multiple times.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0007_calendar_preferences.sql

alter table calendar_subscriptions
  add column if not exists preferences jsonb;

do $$ begin
  raise notice 'calendar_subscriptions.preferences column ready';
end $$;
