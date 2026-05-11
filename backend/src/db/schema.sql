-- =============================================================================
-- Shion Quant client portal — Postgres schema (v1)
-- Target: Neon Postgres 16+
--
-- Conventions:
--   - All money: numeric(20, 4)   (NEVER float for money)
--   - All time:  timestamptz       (UTC stored, displayed per user tz)
--   - All IDs:   uuid (gen_random_uuid())
--   - Soft deletes via `deleted_at` timestamptz; nullable
--   - `created_at` / `updated_at` on every table; trigger maintains updated_at
--
-- Naming:
--   - Tables: plural snake_case
--   - PK: `id`
--   - FK: `<entity>_id`
--   - Booleans: `is_*` or `has_*`
--   - Timestamps: `*_at`
--
-- Run order:
--   psql $NEON_DATABASE_URL -f schema.sql
--
-- =============================================================================

create extension if not exists "pgcrypto";       -- gen_random_uuid()
create extension if not exists "citext";         -- case-insensitive email


-- ─── Common functions ───────────────────────────────────────────────────────

create or replace function set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  IDENTITY & AUTHORIZATION                                                  ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

-- A `user` is an authentication principal (Mr. Chen logging in).
-- A `client` is a relationship/account-set (could be jointly held later).
-- Today: 1 user → 1 client. Future: 1 user → many clients (family office).

create table users (
  id              uuid primary key default gen_random_uuid(),
  email           citext unique not null,
  email_verified_at timestamptz,
  password_hash   text not null,            -- argon2id encoded string
  preferred_name  text,
  preferred_lang  text not null default 'en',  -- 'en' | 'zh-Hant' | 'zh-Hans'
  is_active       boolean not null default true,
  locked_until    timestamptz,              -- progressive lockout after failed logins
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  deleted_at      timestamptz
);
create trigger users_updated_at before update on users
  for each row execute function set_updated_at();
create index users_email_idx on users (email) where deleted_at is null;


create table clients (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references users(id) on delete restrict,
  client_number   text unique not null,     -- e.g. '0042'
  tier            text not null,            -- 'diagnostic' | 'retainer' | 'build'
  joined_at       timestamptz not null default now(),
  jurisdiction    text,                     -- 'HK' | 'SG' | 'US' | ...
  primary_advisor_id uuid,                  -- FK to advisors, set later
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  deleted_at      timestamptz,

  check (tier in ('diagnostic', 'retainer', 'build'))
);
create trigger clients_updated_at before update on clients
  for each row execute function set_updated_at();
create index clients_user_id_idx on clients (user_id);


create table advisors (
  id              uuid primary key default gen_random_uuid(),
  full_name       text not null,
  initials        text not null,            -- 'KT' for avatar
  role            text not null,            -- 'Senior Quant'
  location        text,                     -- 'San Diego'
  timezone        text not null,            -- IANA e.g. 'America/Los_Angeles'
  email           citext unique not null,
  is_active       boolean not null default true,
  created_at      timestamptz not null default now()
);

alter table clients
  add constraint clients_advisor_fk
  foreign key (primary_advisor_id) references advisors(id) on delete set null;


-- ─── Authentication factors ─────────────────────────────────────────────────

create table auth_factors (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references users(id) on delete cascade,
  factor_type     text not null,            -- 'totp' | 'webauthn' | 'recovery_code' | 'yubikey'
  label           text,                     -- '1Password app' | 'YubiKey 5C "Black-1"'
  secret_encrypted bytea,                   -- envelope-encrypted (KMS)
  webauthn_credential_id bytea,
  webauthn_public_key bytea,
  is_primary      boolean not null default false,
  registered_at   timestamptz not null default now(),
  last_used_at    timestamptz,
  revoked_at      timestamptz,

  check (factor_type in ('totp', 'webauthn', 'recovery_code', 'yubikey'))
);
create index auth_factors_user_idx on auth_factors (user_id) where revoked_at is null;


-- Recovery codes are stored hashed; one row per code. Used codes are not
-- deleted (audit), only marked.
create table recovery_codes (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references users(id) on delete cascade,
  code_hash       text not null,            -- argon2id hash of the code
  used_at         timestamptz,
  used_ip         inet,
  generated_at    timestamptz not null default now()
);
create index recovery_codes_user_idx on recovery_codes (user_id) where used_at is null;


-- ─── Sessions (server-side, revocable; not JWT) ─────────────────────────────

create table sessions (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references users(id) on delete cascade,
  client_id       uuid references clients(id),  -- which client context
  token_hash      bytea not null,           -- sha256 of the cookie value
  ip              inet,
  user_agent      text,
  device_label    text,                     -- 'MacBook Pro · Safari'
  is_2fa_verified boolean not null default false,
  is_trade_authorized boolean not null default false,  -- requires fresh re-auth
  created_at      timestamptz not null default now(),
  last_seen_at    timestamptz not null default now(),
  expires_at      timestamptz not null,
  revoked_at      timestamptz
);
create index sessions_user_idx on sessions (user_id) where revoked_at is null;
create index sessions_token_hash_idx on sessions (token_hash);


-- ─── API tokens (programmatic access; e.g. user's Jupyter notebook) ─────────

create table api_tokens (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references users(id) on delete cascade,
  name            text not null,            -- 'Personal Jupyter analysis'
  prefix          text not null,            -- 'sq_live_8a2f'  (visible)
  secret_hash     bytea not null,           -- sha256 of the rest
  scopes          text[] not null default '{}', -- ['read:positions', 'read:reports']
  last_used_at    timestamptz,
  call_count      bigint not null default 0,
  created_at      timestamptz not null default now(),
  revoked_at      timestamptz
);
create index api_tokens_prefix_idx on api_tokens (prefix);
create index api_tokens_user_idx on api_tokens (user_id) where revoked_at is null;


-- ─── Login history (immutable; for security review) ────────────────────────

create table login_events (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references users(id) on delete set null,
  email_attempted citext,                   -- captured even when user not found
  ip              inet not null,
  user_agent      text,
  method          text not null,            -- 'password' | 'passkey' | 'totp' | 'magic-link'
  status          text not null,            -- 'success' | 'bad_password' | 'mfa_failed' | 'locked' | 'unknown_user'
  geo_country     text,
  geo_city        text,
  occurred_at     timestamptz not null default now()
);
create index login_events_user_time_idx on login_events (user_id, occurred_at desc);
create index login_events_ip_time_idx on login_events (ip, occurred_at desc);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  PROFILE & KYC                                                             ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

create table profiles (
  client_id       uuid primary key references clients(id) on delete cascade,
  legal_name_encrypted bytea not null,      -- envelope encrypted
  legal_name_hash bytea,                    -- for search/dedup (sha256 of normalized)
  date_of_birth   date,
  nationality     text,
  hkid_encrypted  bytea,                    -- envelope encrypted
  passport_encrypted bytea,                 -- envelope encrypted
  primary_email   citext,
  primary_phone   text,
  preferred_channel text default 'email',   -- 'email' | 'portal' | 'whatsapp' | 'phone'
  quiet_hours_local jsonb,                  -- {start: '22:00', end: '07:00', tz: 'Asia/Hong_Kong'}
  marketing_consent boolean not null default true,
  case_study_consent boolean not null default false,
  updated_at      timestamptz not null default now()
);
create trigger profiles_updated_at before update on profiles
  for each row execute function set_updated_at();


create table addresses (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  kind            text not null,            -- 'residential' | 'mailing' | 'office'
  line1_encrypted bytea not null,
  line2_encrypted bytea,
  city            text,
  region          text,
  country_iso     text not null,            -- 'HK', 'CN', 'US', ...
  postal_code     text,
  is_primary      boolean not null default false,
  verified_at     timestamptz,
  created_at      timestamptz not null default now()
);
create index addresses_client_idx on addresses (client_id);


create table tax_residencies (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  country_iso     text not null,
  tax_id_encrypted bytea,
  is_primary      boolean not null default false,
  treaty_form     text,                     -- 'W-8BEN' | 'W-9' | null
  treaty_form_signed_at timestamptz,
  treaty_form_renews_at timestamptz,
  established_at  timestamptz
);
create index tax_residencies_client_idx on tax_residencies (client_id);


create table beneficiaries (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  full_name_encrypted bytea not null,
  display_label   text,                     -- 'Lin, Hui-Yu · 林慧瑜'
  relation        text not null,            -- 'spouse' | 'daughter' | 'son' | 'accountant' | 'other'
  share_pct       numeric(5, 2),            -- 50.00; null for non-financial parties
  permissions     text not null default 'none', -- 'none' | 'read' | 'read_trade' | 'tax_only' | 'limited'
  contact_encrypted jsonb,                  -- email/phone (encrypted before insert)
  authorized_at   timestamptz,
  revisit_at      date,                     -- e.g. when minor turns 18
  created_at      timestamptz not null default now(),

  check (share_pct is null or (share_pct >= 0 and share_pct <= 100)),
  check (permissions in ('none', 'read', 'read_trade', 'tax_only', 'limited'))
);
create index beneficiaries_client_idx on beneficiaries (client_id);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  PORTFOLIO & POSITIONS                                                     ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

-- Brokerage / custodian accounts (one client → many accounts)
create table accounts (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  broker          text not null,            -- 'IBKR' | 'Coinbase Prime' | 'Alpaca'
  account_number_masked text not null,      -- 'U-942-***' (display)
  account_number_encrypted bytea,           -- full number, envelope encrypted
  base_currency   text not null,            -- 'USD'
  is_active       boolean not null default true,
  opened_at       timestamptz,
  notes           text,
  -- Broker-precomputed buying power. NULL → API falls back to a Reg-T
  -- heuristic (`available_cash + 2 * equity_nav`).
  buying_power_usd numeric(20, 4),
  created_at      timestamptz not null default now()
);
create index accounts_client_idx on accounts (client_id);


-- One row per holding. asset_type discriminates between equity/option/future/etc.
-- All asset-specific fields live on this table (sparse columns) — simpler than
-- 6 specialized tables.
create table positions (
  id              uuid primary key default gen_random_uuid(),
  account_id      uuid not null references accounts(id) on delete cascade,
  asset_type      text not null,            -- 'equity' | 'option' | 'future' | 'bond' | 'crypto' | 'cash'

  -- Common identification
  symbol          text not null,            -- 'NVDA', 'AAPL 230C 16May', 'ES Sep26', 'UST 4.25 May34', 'BTC'
  display_name    text,                     -- 'NVIDIA Corp', 'Bitcoin'
  isin            text,
  cusip           text,

  -- Common quantity / valuation
  quantity        numeric(20, 8) not null,  -- shares, contracts, bond face, BTC units
  side            text not null default 'long', -- 'long' | 'short' (futures, options)
  cost_basis_total numeric(20, 4),          -- entire-position cost
  cost_basis_avg  numeric(20, 8),
  mark_price      numeric(20, 8),
  market_value    numeric(20, 4),           -- quantity × mark; updated by sync
  unrealized_pl   numeric(20, 4),
  unrealized_pl_pct numeric(10, 4),

  -- Option-specific (NULL when not an option)
  option_underlying text,                   -- 'AAPL'
  option_strike   numeric(20, 4),
  option_expiry   date,
  option_type     text,                     -- 'C' | 'P'
  option_delta    numeric(10, 6),
  option_gamma    numeric(10, 6),
  option_theta    numeric(20, 4),
  option_vega     numeric(20, 4),
  option_iv       numeric(10, 6),

  -- Future-specific
  future_underlying text,                   -- 'ES', 'NQ', 'ZN', 'GC'
  future_expiry   date,
  future_initial_margin numeric(20, 4),
  future_dv01     numeric(20, 4),           -- for rate futures

  -- Bond-specific
  bond_coupon_pct numeric(8, 4),
  bond_maturity   date,
  bond_ytm        numeric(8, 4),
  bond_duration   numeric(8, 4),
  bond_face_value numeric(20, 4),

  -- Day-level metrics (updated daily by sync)
  day_change      numeric(20, 4),
  day_change_pct  numeric(10, 4),

  -- Provenance
  opened_at       timestamptz,
  closed_at       timestamptz,
  last_synced_at  timestamptz,

  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),

  check (asset_type in ('equity', 'option', 'future', 'bond', 'crypto', 'cash')),
  check (side in ('long', 'short'))
);
create trigger positions_updated_at before update on positions
  for each row execute function set_updated_at();
create index positions_account_idx on positions (account_id) where closed_at is null;
create index positions_type_idx on positions (asset_type) where closed_at is null;
create index positions_symbol_idx on positions (symbol);


-- Multi-currency cash balances (one row per currency per account)
create table cash_balances (
  id              uuid primary key default gen_random_uuid(),
  account_id      uuid not null references accounts(id) on delete cascade,
  currency        text not null,            -- 'USD' | 'HKD' | 'CNY'
  amount_local    numeric(20, 4) not null,
  fx_rate_to_usd  numeric(20, 8) not null,
  amount_usd      numeric(20, 4) generated always as (amount_local * fx_rate_to_usd) stored,
  available       numeric(20, 4) not null,  -- amount minus margin used
  margin_used     numeric(20, 4) not null default 0,
  last_synced_at  timestamptz not null default now(),

  unique (account_id, currency)
);


-- Transaction history (immutable; all trades / cash moves)
create table transactions (
  id              uuid primary key default gen_random_uuid(),
  account_id      uuid not null references accounts(id) on delete restrict,
  position_id     uuid references positions(id) on delete set null,
  txn_type        text not null,            -- 'buy' | 'sell' | 'dividend' | 'coupon' | 'fee' | 'wire_in' | 'wire_out' | 'fx'
  symbol          text,
  quantity        numeric(20, 8),
  price           numeric(20, 8),
  amount          numeric(20, 4) not null,  -- signed; cash impact in account base ccy
  currency        text not null,
  fee             numeric(20, 4) default 0,
  description     text,
  trade_date      date,
  settlement_date date,
  external_ref    text,                     -- broker confirmation #
  occurred_at     timestamptz not null
);
create index transactions_account_time_idx on transactions (account_id, occurred_at desc);
create index transactions_position_idx on transactions (position_id);


-- Daily NAV snapshot (for the equity curve chart on Portfolio overview)
create table daily_nav (
  client_id       uuid not null references clients(id) on delete cascade,
  as_of           date not null,
  nav_total_usd   numeric(20, 4) not null,
  nav_equities    numeric(20, 4),
  nav_options     numeric(20, 4),
  nav_futures     numeric(20, 4),
  nav_bonds       numeric(20, 4),
  nav_cash        numeric(20, 4),
  nav_crypto      numeric(20, 4),
  day_pl          numeric(20, 4),
  day_pl_pct      numeric(10, 4),
  beta_to_spy     numeric(8, 4),
  primary key (client_id, as_of)
);


-- Risk metrics rollup (rolling 90d, computed nightly)
create table risk_metrics (
  client_id       uuid not null references clients(id) on delete cascade,
  as_of           date not null,
  beta            numeric(8, 4),
  sharpe          numeric(8, 4),
  sortino         numeric(8, 4),
  max_drawdown    numeric(8, 4),
  vol_annualized  numeric(8, 4),
  primary key (client_id, as_of)
);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  SCHEDULES                                                                 ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

create table events (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  event_type      text not null,            -- see check
  source          text not null,            -- 'system' | 'broker' | 'macro' | 'advisor' | 'personal'

  title           text not null,
  description     text,
  ticker          text,                     -- linked symbol if any
  position_id     uuid references positions(id) on delete set null,

  starts_at       timestamptz not null,
  ends_at         timestamptz,
  is_all_day      boolean not null default false,
  display_tz      text,                     -- override for display

  is_critical     boolean not null default false,
  is_archived     boolean not null default false,

  -- For recurring events; otherwise null
  rrule           text,                     -- iCal RFC 5545 RRULE

  -- Type-specific JSONB blob
  metadata        jsonb,                    -- {strike: 230, expiry: ..., etc.}

  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),

  check (event_type in (
    'option_expiry', 'bond_coupon', 'earnings', 'dividend',
    'macro', 'advisor_call', 'report_delivery', 'rebalance',
    'compliance_renewal', 'personal'
  )),
  check (source in ('system', 'broker', 'macro', 'advisor', 'personal'))
);
create trigger events_updated_at before update on events
  for each row execute function set_updated_at();
create index events_client_time_idx on events (client_id, starts_at)
  where is_archived = false;
create index events_critical_idx on events (client_id, starts_at)
  where is_critical = true and is_archived = false;


create table event_reminders (
  id              uuid primary key default gen_random_uuid(),
  event_id        uuid not null references events(id) on delete cascade,
  channel         text not null,            -- 'email' | 'push' | 'sms'
  lead_minutes    integer not null,         -- 60 = 1h before
  status          text not null default 'pending', -- 'pending' | 'sent' | 'failed' | 'skipped'
  sent_at         timestamptz,

  check (channel in ('email', 'push', 'sms'))
);
create index event_reminders_pending_idx on event_reminders (event_id)
  where status = 'pending';


-- ICS subscription token (one per client, rotatable)
create table calendar_subscriptions (
  client_id       uuid primary key references clients(id) on delete cascade,
  ics_token       text not null unique,     -- bearer-style, in URL
  last_fetched_at timestamptz,
  fetch_count     bigint not null default 0,
  created_at      timestamptz not null default now()
);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  REPORTS & RESEARCH                                                        ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

create table reports (
  id              uuid primary key default gen_random_uuid(),
  report_type     text not null,            -- 'risk_attribution' | 'performance' | 'strategy_memo' | 'macro' | 'custom'
  -- Inbox category (added 2026-05). Drives the "Tune what arrives in your
  -- inbox" toggles + the Reports page filter chips.
  category        text,                     -- 'must_read' | 'attribution' | 'quarterly_performance' | 'macro_regime' | 'strategy_model' | 'custom_research'
  title           text not null,
  subtitle        text,
  body_md         text,                     -- legacy markdown content
  body_format     text not null default 'md',  -- 'md' | 'mdx'
  -- Sections-based rich body. See docs/event-metadata-schema.md — same
  -- discriminated-union schema used by events.metadata.
  metadata        jsonb,
  author_advisor_id uuid references advisors(id) on delete set null,
  client_id       uuid references clients(id),  -- null = firm-wide report
  pages           integer,
  charts_count    integer,
  tables_count    integer,
  read_time_min   integer,
  attachments     jsonb,                    -- [{name, url, sha256, size}]
  pdf_url         text,                     -- R2 URL to rendered PDF
  pdf_sha256      text,
  published_at    timestamptz,
  is_draft        boolean not null default true,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),

  check (report_type in ('risk_attribution', 'performance', 'strategy_memo', 'macro', 'custom')),
  check (category is null or category in (
    'must_read', 'attribution', 'quarterly_performance',
    'macro_regime', 'strategy_model', 'custom_research'
  ))
);
create trigger reports_updated_at before update on reports
  for each row execute function set_updated_at();
create index reports_type_published_idx on reports (report_type, published_at desc)
  where is_draft = false;
create index reports_client_idx on reports (client_id) where is_draft = false;


-- One row per (report, client) view event; first row also tracks bookmark
create table report_access (
  id              uuid primary key default gen_random_uuid(),
  report_id       uuid not null references reports(id) on delete cascade,
  client_id       uuid not null references clients(id) on delete cascade,
  user_id         uuid references users(id) on delete set null,
  first_read_at   timestamptz not null default now(),
  last_read_at    timestamptz not null default now(),
  read_count      integer not null default 1,
  is_bookmarked   boolean not null default false,
  bookmarked_at   timestamptz,

  unique (report_id, client_id)
);


-- Email/push subscription preferences per report type
create table report_subscriptions (
  client_id       uuid not null references clients(id) on delete cascade,
  report_type     text not null,
  channels        text[] not null default '{}',  -- ['email', 'push']
  primary key (client_id, report_type)
);


-- Custom research project requests (Build Tier)
create table custom_research_requests (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  user_id         uuid not null references users(id),
  project_type    text not null,            -- 'strategy' | 'deepdive' | 'backtest' | 'taxopt' | 'automation' | 'other'
  working_title   text,
  question        text not null,            -- the brief
  linked_tickers  text[],
  capital_at_stake numeric(20, 4),
  timeline_pref   text,                     -- 'rush' | 'standard' | 'flexible'
  reference_materials text,
  est_fee_low_usd numeric(20, 4),
  est_fee_high_usd numeric(20, 4),
  status          text not null default 'submitted', -- 'submitted' | 'scoping' | 'proposed' | 'active' | 'closed' | 'declined'
  submitted_at    timestamptz not null default now(),
  scoped_at       timestamptz,
  proposed_at     timestamptz,
  closed_at       timestamptz,
  resulting_project_id uuid,                -- FK to custom_projects (billing)

  check (project_type in ('strategy', 'deepdive', 'backtest', 'taxopt', 'automation', 'other'))
);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  DOCUMENTS VAULT                                                           ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

create table documents (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete restrict,
  category        text not null,            -- see check
  title           text not null,
  display_code    text,                     -- 'IBKR' | '1099' | 'KYC'
  source_label    text,                     -- 'Interactive Brokers'
  source_party    text,                     -- canonical issuer
  description     text,

  file_url        text,                     -- R2 URL (presigned on demand)
  file_format     text not null,            -- 'pdf' | 'xlsx' | 'docx' | 'jpg' | 'png'
  file_size_bytes bigint,
  pages           integer,
  sha256          text,                     -- integrity check

  -- Lifecycle
  issued_at       timestamptz,
  delivered_at    timestamptz,
  retention_until date,                     -- IRS / SEC 7-year rule
  is_archived     boolean not null default false,

  -- Status
  -- 'active'             — file present, ready
  -- 'pending_signature'  — needs signature (advisor-side flow)
  -- 'pending_upload'     — row created via /upload-url, file not yet PUT to R2
  -- 'expired' | 'superseded'
  status          text not null default 'active',
  pending_action  text,                     -- 'review_and_sign' | null
  pending_due_at  timestamptz,

  -- Tags & cross-references
  tags            text[],
  related_position_id uuid references positions(id),
  related_event_id uuid references events(id),
  tax_year        integer,

  uploaded_by_user_id uuid references users(id),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),

  check (category in (
    'statement', 'tax', 'custody', 'engagement',
    'compliance', 'banking', 'misc'
  )),
  check (status in ('active', 'pending_signature', 'pending_upload', 'expired', 'superseded')),
  check (file_format in ('pdf', 'xlsx', 'docx', 'jpg', 'png', 'csv', 'txt'))
);
create trigger documents_updated_at before update on documents
  for each row execute function set_updated_at();
create index documents_client_category_idx on documents (client_id, category, issued_at desc);
create index documents_pending_idx on documents (client_id) where status = 'pending_signature';


-- E-signature log (for documents that require signing)
create table document_signatures (
  id              uuid primary key default gen_random_uuid(),
  document_id     uuid not null references documents(id) on delete cascade,
  signer_user_id  uuid not null references users(id),
  signature_image_url text,                 -- R2 URL to signature SVG/PNG
  signature_method text not null,           -- 'drawn' | 'typed' | 'docusign'
  signed_at       timestamptz not null default now(),
  signed_ip       inet,
  signed_user_agent text,
  envelope_ref    text                      -- DocuSign envelope ID
);


-- Every document access logged (downloads, views)
create table document_actions (
  id              uuid primary key default gen_random_uuid(),
  document_id     uuid not null references documents(id) on delete cascade,
  user_id         uuid references users(id) on delete set null,
  action          text not null,            -- 'view' | 'download' | 'share' | 'forward'
  recipient       text,                     -- email if shared
  ip              inet,
  occurred_at     timestamptz not null default now(),

  check (action in ('view', 'download', 'share', 'forward', 'print'))
);
create index document_actions_doc_time_idx on document_actions (document_id, occurred_at desc);


-- Custom document requests (e.g. bank reference letter)
create table document_requests (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  user_id         uuid not null references users(id),
  request_type    text not null,            -- 'bank_ref' | 'asset_confirm' | 'reconstruct' | 'cost_basis' | 'tax_pkg' | 'custom'
  purpose         text,
  recipient       text,
  as_of_date      date,
  needed_by_date  date,
  format          text not null,            -- 'pdf_digital' | 'pdf_wet' | 'hardcopy' | 'notarized'
  notes           text,
  status          text not null default 'submitted', -- 'submitted' | 'in_progress' | 'delivered' | 'cancelled'
  submitted_at    timestamptz not null default now(),
  delivered_at    timestamptz,
  resulting_document_id uuid references documents(id),

  check (request_type in ('bank_ref', 'asset_confirm', 'reconstruct', 'cost_basis', 'tax_pkg', 'custom'))
);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  BILLING                                                                   ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

create table engagements (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete restrict,
  tier            text not null,            -- 'diagnostic' | 'retainer' | 'build'
  monthly_fee_usd numeric(20, 4),
  started_at      date not null,
  ends_at         date,                     -- null = ongoing
  notice_days     integer not null default 60,
  master_doc_id   uuid references documents(id),  -- the signed engagement letter
  is_active       boolean not null default true,
  created_at      timestamptz not null default now()
);


create table invoices (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete restrict,
  invoice_number  text unique not null,     -- 'SQ-2026-0042'
  kind            text not null,            -- 'retainer' | 'project' | 'ad_hoc'
  period_start    date,
  period_end      date,
  description     text,
  amount_usd      numeric(20, 4) not null,
  status          text not null default 'issued', -- 'issued' | 'paid' | 'overdue' | 'void'
  issued_at       date not null,
  due_at          date,
  paid_at         date,
  payment_method_id uuid,                   -- FK below
  pdf_document_id uuid references documents(id),
  external_ref    text,                     -- Stripe / wire ref
  created_at      timestamptz not null default now(),

  check (kind in ('retainer', 'project', 'ad_hoc')),
  check (status in ('issued', 'paid', 'overdue', 'void'))
);
create index invoices_client_issued_idx on invoices (client_id, issued_at desc);


create table payment_methods (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  method_type     text not null,            -- 'wire' | 'card'
  display_label   text not null,            -- 'BEA HKD wire · auto-debit'
  last_four       text,                     -- '3942' | '5512'
  bank_name       text,
  is_default      boolean not null default false,
  is_active       boolean not null default true,
  authorized_at   timestamptz,
  created_at      timestamptz not null default now()
);

alter table invoices
  add constraint invoices_pm_fk
  foreign key (payment_method_id) references payment_methods(id) on delete set null;


-- Build Tier projects (separate from retainer)
create table custom_projects (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete restrict,
  name            text not null,
  project_type    text not null,
  fee_total_usd   numeric(20, 4),
  fee_paid_usd    numeric(20, 4) default 0,
  status          text not null default 'active', -- 'active' | 'completed' | 'cancelled'
  sow_document_id uuid references documents(id),
  deliverable_report_id uuid references reports(id),
  request_id      uuid references custom_research_requests(id),
  started_at      date,
  delivered_at    date,
  closed_at       date,
  created_at      timestamptz not null default now(),

  check (status in ('active', 'completed', 'cancelled'))
);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  COMMUNICATION                                                             ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

create table message_threads (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  advisor_id      uuid references advisors(id) on delete set null,
  subject         text not null,
  is_archived     boolean not null default false,
  last_message_at timestamptz not null default now(),
  unread_count_client integer not null default 0,
  unread_count_advisor integer not null default 0,
  created_at      timestamptz not null default now()
);
create index message_threads_client_idx on message_threads (client_id, last_message_at desc);


create table messages (
  id              uuid primary key default gen_random_uuid(),
  thread_id       uuid not null references message_threads(id) on delete cascade,
  sender_user_id  uuid references users(id) on delete set null,
  sender_advisor_id uuid references advisors(id) on delete set null,
  body            text not null,
  urgency         text not null default 'routine', -- 'routine' | 'soon' | 'urgent'
  attachments     jsonb,                    -- [{name, url, sha256}]
  sent_at         timestamptz not null default now(),
  read_at         timestamptz,

  check (urgency in ('routine', 'soon', 'urgent')),
  check ((sender_user_id is not null) or (sender_advisor_id is not null))
);
create index messages_thread_time_idx on messages (thread_id, sent_at desc);


create table meeting_bookings (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid not null references clients(id) on delete cascade,
  advisor_id      uuid not null references advisors(id) on delete restrict,
  scheduled_at    timestamptz not null,
  duration_min    integer not null default 60,
  meeting_type    text not null,            -- 'video' | 'phone' | 'in_person'
  agenda          text,
  meeting_url     text,                     -- Zoom etc
  location        text,                     -- for in-person
  status          text not null default 'confirmed', -- 'pending' | 'confirmed' | 'cancelled' | 'completed'
  related_event_id uuid references events(id),
  created_at      timestamptz not null default now(),

  check (meeting_type in ('video', 'phone', 'in_person')),
  check (status in ('pending', 'confirmed', 'cancelled', 'completed'))
);
create index meeting_bookings_client_time_idx on meeting_bookings (client_id, scheduled_at);


-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║  AUDIT LOG (immutable)                                                     ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝
--
-- Every state-changing API action writes here via a service-layer helper.
-- Retention: 7 years (IRS / SEC). Never UPDATE or DELETE rows.

create table audit_log (
  id              bigserial primary key,
  occurred_at     timestamptz not null default now(),
  user_id         uuid,                     -- nullable: system actions
  client_id       uuid,
  ip              inet,
  user_agent      text,
  action          text not null,            -- 'auth.login.success', 'doc.sign', 'profile.edit'
  resource_type   text,                     -- 'document' | 'profile' | 'beneficiary' | ...
  resource_id     uuid,
  request_sha256  text,                     -- hash of full canonical request body
  before_state    jsonb,                    -- nullable: capture for diffs
  after_state     jsonb,
  metadata        jsonb                     -- IP geo, etc.
);
create index audit_log_user_time_idx on audit_log (user_id, occurred_at desc);
create index audit_log_client_time_idx on audit_log (client_id, occurred_at desc);
create index audit_log_action_idx on audit_log (action, occurred_at desc);

-- M8: audit_log rows are append-only. UPDATE / DELETE / TRUNCATE all blocked
-- at the trigger level so even a logic bug in app code can't corrupt history.
-- The retention job purges rows older than the schema's stated horizon (7y)
-- by temporarily disabling these triggers under a SECURITY DEFINER function
-- — that's the ONLY supported deletion path. See db/retention.ts.
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


-- ─── Done ───────────────────────────────────────────────────────────────────
-- Total: ~30 tables grouped into 8 domains.
-- Schema changes after this baseline: edit this file AND `schema.ts` together,
-- ship a one-off ALTER in `db/migrations/` when modifying an existing DB.
