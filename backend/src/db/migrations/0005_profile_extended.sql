-- Extended profile fields (added 2026-05).
-- Idempotent — safe to run multiple times.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0005_profile_extended.sql

alter table profiles
  add column if not exists first_name_encrypted               bytea,
  add column if not exists last_name_encrypted                bytea,
  add column if not exists chinese_name_encrypted             bytea,
  add column if not exists preferred_name_encrypted           bytea,
  add column if not exists preferred_chinese_name_encrypted   bytea,
  add column if not exists identities_encrypted               bytea,
  add column if not exists trading_status                     text,
  add column if not exists people_and_beneficiaries_encrypted bytea;

do $$ begin
  raise notice 'profiles extended (names + identities + trading_status + people-and-beneficiaries)';
end $$;
