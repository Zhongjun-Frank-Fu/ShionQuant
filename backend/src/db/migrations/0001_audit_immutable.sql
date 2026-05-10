-- M8: make audit_log append-only via triggers.
-- Idempotent — safe to run multiple times.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0001_audit_immutable.sql
--
-- Fresh databases get this from schema.sql automatically; this file is for
-- DBs that were provisioned before M8.

create or replace function prevent_audit_modifications() returns trigger as $$
begin
  raise exception 'audit_log rows are immutable; % blocked by trigger', tg_op
    using errcode = 'restrict_violation';
end;
$$ language plpgsql;

drop trigger if exists audit_log_no_update on audit_log;
create trigger audit_log_no_update
  before update on audit_log
  for each row execute function prevent_audit_modifications();

drop trigger if exists audit_log_no_delete on audit_log;
create trigger audit_log_no_delete
  before delete on audit_log
  for each row execute function prevent_audit_modifications();

-- Sanity check (will raise NOTICE in psql):
do $$ begin
  raise notice 'audit_log immutable triggers installed';
end $$;
