-- Advisor admin tables — contact requests + bookable time slots (added 2026-05).
-- Idempotent — safe to re-run.
--
-- Apply with:
--   psql "$NEON_DATABASE_URL" -f src/db/migrations/0008_advisor_contact_admin.sql

create table if not exists advisor_time_slots (
  id                uuid primary key default gen_random_uuid(),
  advisor_id        uuid not null references advisors(id) on delete cascade,
  slot_type         text not null,
  location          text not null,
  starts_at         timestamptz not null,
  ends_at           timestamptz not null,
  duration_minutes  integer not null,
  capacity          integer not null default 1,
  is_active         boolean not null default true,
  notes             text,
  created_at        timestamptz not null default now(),

  check (slot_type in ('call', 'in_person')),
  check (ends_at > starts_at)
);
create index if not exists advisor_slots_advisor_starts_idx
  on advisor_time_slots (advisor_id, starts_at)
  where is_active = true;
create index if not exists advisor_slots_type_starts_idx
  on advisor_time_slots (slot_type, starts_at)
  where is_active = true;


create table if not exists advisor_contact_requests (
  id                       uuid primary key default gen_random_uuid(),
  client_id                uuid not null references clients(id) on delete cascade,
  submitted_by_user_id     uuid references users(id) on delete set null,
  submitters               jsonb,
  request_type             text not null,
  location                 text,
  preferred_starts_at      timestamptz,
  preferred_ends_at        timestamptz,
  duration_minutes         integer,
  reason                   text not null,
  urgency                  text,
  linked_slot_id           uuid references advisor_time_slots(id) on delete set null,
  status                   text not null default 'pending',
  resolved_by_advisor_id   uuid references advisors(id) on delete set null,
  resolved_at              timestamptz,
  resolution_notes         text,
  resulting_booking_id     uuid references meeting_bookings(id) on delete set null,
  metadata                 jsonb,
  created_at               timestamptz not null default now(),
  updated_at               timestamptz not null default now(),

  check (request_type in ('message', 'call', 'in_person')),
  check (status in ('pending', 'acknowledged', 'confirmed', 'declined', 'completed', 'cancelled')),
  check (urgency is null or urgency in ('routine', 'soon', 'urgent'))
);
create index if not exists contact_requests_client_idx
  on advisor_contact_requests (client_id, created_at desc);
create index if not exists contact_requests_status_idx
  on advisor_contact_requests (status, created_at desc)
  where status in ('pending', 'acknowledged');

do $$ begin
  raise notice 'advisor_time_slots + advisor_contact_requests tables ready';
end $$;
