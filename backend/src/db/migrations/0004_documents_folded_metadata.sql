-- Add `is_folded` + `metadata` (jsonb) to documents.
-- Idempotent — safe to run multiple times.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0004_documents_folded_metadata.sql
--
-- Fresh databases get these from schema.sql automatically; this file is
-- for DBs provisioned before the columns existed.

alter table documents
  add column if not exists is_folded boolean not null default false,
  add column if not exists metadata  jsonb;

do $$ begin
  raise notice 'documents.is_folded + documents.metadata columns ready';
end $$;
