/**
 * Drizzle ORM schema for the Shion Quant client portal.
 *
 * This file is the TypeScript mirror of `schema.sql`. Use it for type-safe
 * queries throughout the app:
 *
 *     import { db } from "./client.js"
 *     import { users, sessions } from "./schema.js"
 *     import { eq } from "drizzle-orm"
 *
 *     const user = await db.select().from(users).where(eq(users.email, "...")).limit(1)
 *
 * Source-of-truth policy:
 *   - For initial provisioning, run `schema.sql` directly on a fresh Neon DB.
 *     It includes triggers and functions that drizzle-kit doesn't manage.
 *   - For subsequent schema changes, edit this file AND `schema.sql` together,
 *     run drizzle-kit migrations, then manually apply any non-table objects
 *     (triggers, functions). Yes, dual-write is annoying. The alternative
 *     (giving up the SQL triggers) is worse for a finance app.
 *
 * Type-level enforcement here uses `.$type<...>()` — DB-level CHECK constraints
 * are in schema.sql.
 */

import { sql } from "drizzle-orm"
import {
  bigint,
  bigserial,
  boolean,
  customType,
  date,
  index,
  integer,
  jsonb,
  numeric,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core"

import type { EventMetadata } from "../types/event-metadata.js"

// ─── Custom Postgres types not in drizzle/pg-core ─────────────────────────

const inet = customType<{ data: string }>({ dataType: () => "inet" })
const bytea = customType<{ data: Buffer; default: false }>({ dataType: () => "bytea" })
const citext = customType<{ data: string; notNull: false }>({ dataType: () => "citext" })

// Convenience for common column patterns
const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" })

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  IDENTITY & AUTHORIZATION                                                  ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

export const users = pgTable(
  "users",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    email: citext("email").notNull(),
    emailVerifiedAt: ts("email_verified_at"),
    passwordHash: text("password_hash").notNull(),
    preferredName: text("preferred_name"),
    preferredLang: text("preferred_lang")
      .notNull()
      .default("en")
      .$type<"en" | "zh-Hant" | "zh-Hans">(),
    isActive: boolean("is_active").notNull().default(true),
    lockedUntil: ts("locked_until"),
    createdAt: ts("created_at").notNull().defaultNow(),
    updatedAt: ts("updated_at").notNull().defaultNow(),
    deletedAt: ts("deleted_at"),
  },
  (t) => [uniqueIndex("users_email_uq").on(t.email).where(sql`deleted_at is null`)],
)

export const clients = pgTable(
  "clients",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    clientNumber: text("client_number").notNull().unique(),
    tier: text("tier").notNull().$type<"diagnostic" | "retainer" | "build">(),
    joinedAt: ts("joined_at").notNull().defaultNow(),
    jurisdiction: text("jurisdiction"),
    primaryAdvisorId: uuid("primary_advisor_id"),
    createdAt: ts("created_at").notNull().defaultNow(),
    updatedAt: ts("updated_at").notNull().defaultNow(),
    deletedAt: ts("deleted_at"),
  },
  (t) => [index("clients_user_idx").on(t.userId)],
)

export const advisors = pgTable("advisors", {
  id: uuid("id").defaultRandom().primaryKey(),
  fullName: text("full_name").notNull(),
  initials: text("initials").notNull(),
  role: text("role").notNull(),
  location: text("location"),
  timezone: text("timezone").notNull(),
  email: citext("email").notNull().unique(),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: ts("created_at").notNull().defaultNow(),
})

export const authFactors = pgTable(
  "auth_factors",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    factorType: text("factor_type")
      .notNull()
      .$type<"totp" | "webauthn" | "recovery_code" | "yubikey">(),
    label: text("label"),
    secretEncrypted: bytea("secret_encrypted"),
    webauthnCredentialId: bytea("webauthn_credential_id"),
    webauthnPublicKey: bytea("webauthn_public_key"),
    isPrimary: boolean("is_primary").notNull().default(false),
    registeredAt: ts("registered_at").notNull().defaultNow(),
    lastUsedAt: ts("last_used_at"),
    revokedAt: ts("revoked_at"),
  },
  (t) => [index("auth_factors_user_idx").on(t.userId).where(sql`revoked_at is null`)],
)

export const recoveryCodes = pgTable(
  "recovery_codes",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    codeHash: text("code_hash").notNull(),
    usedAt: ts("used_at"),
    usedIp: inet("used_ip"),
    generatedAt: ts("generated_at").notNull().defaultNow(),
  },
  (t) => [index("recovery_codes_user_idx").on(t.userId).where(sql`used_at is null`)],
)

export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    clientId: uuid("client_id").references(() => clients.id),
    tokenHash: bytea("token_hash").notNull(),
    ip: inet("ip"),
    userAgent: text("user_agent"),
    deviceLabel: text("device_label"),
    is2faVerified: boolean("is_2fa_verified").notNull().default(false),
    isTradeAuthorized: boolean("is_trade_authorized").notNull().default(false),
    createdAt: ts("created_at").notNull().defaultNow(),
    lastSeenAt: ts("last_seen_at").notNull().defaultNow(),
    expiresAt: ts("expires_at").notNull(),
    revokedAt: ts("revoked_at"),
  },
  (t) => [
    index("sessions_user_idx").on(t.userId).where(sql`revoked_at is null`),
    index("sessions_token_hash_idx").on(t.tokenHash),
  ],
)

export const apiTokens = pgTable(
  "api_tokens",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    prefix: text("prefix").notNull(),
    secretHash: bytea("secret_hash").notNull(),
    scopes: text("scopes").array().notNull().default(sql`'{}'::text[]`),
    lastUsedAt: ts("last_used_at"),
    callCount: bigint("call_count", { mode: "number" }).notNull().default(0),
    createdAt: ts("created_at").notNull().defaultNow(),
    revokedAt: ts("revoked_at"),
  },
  (t) => [
    index("api_tokens_prefix_idx").on(t.prefix),
    index("api_tokens_user_idx").on(t.userId).where(sql`revoked_at is null`),
  ],
)

export const loginEvents = pgTable(
  "login_events",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    emailAttempted: citext("email_attempted"),
    ip: inet("ip").notNull(),
    userAgent: text("user_agent"),
    method: text("method").notNull().$type<"password" | "passkey" | "totp" | "magic-link">(),
    status: text("status")
      .notNull()
      .$type<"success" | "bad_password" | "mfa_failed" | "locked" | "unknown_user">(),
    geoCountry: text("geo_country"),
    geoCity: text("geo_city"),
    occurredAt: ts("occurred_at").notNull().defaultNow(),
  },
  (t) => [
    index("login_events_user_time_idx").on(t.userId, t.occurredAt),
    index("login_events_ip_time_idx").on(t.ip, t.occurredAt),
  ],
)

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  PROFILE & KYC                                                             ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

/**
 * Schema for a single non-HKID identity document. HKID stays in its own
 * dedicated `hkid_encrypted` column because it's the primary KYC anchor in
 * HK; everything else (passports, foreign IDs, tax IDs, driver licenses)
 * collapses into this unified shape and lives in `identities_encrypted`.
 */
export interface ProfileIdentity {
  kind: "passport" | "tax_id" | "national_id" | "driver_license" | "other"
  /** ISO country code, e.g. "HK" / "US" / "CN". Required for passports + tax IDs. */
  country?: string
  /** Encrypted-at-rest in identities_encrypted; never sent to the client raw. */
  number: string
  /** Optional display label override ("US SSN", "TW NHI", …). */
  label?: string
  issuedAt?: string
  expiresAt?: string
  notes?: string
}

/**
 * People & beneficiaries — alternative source-of-truth to the `beneficiaries`
 * table. Stored in `people_and_beneficiaries_encrypted`. If both this and
 * the beneficiaries table have data, the JSON wins.
 */
export interface ProfilePerson {
  /** Stable id (uuid string) so the frontend can render keys. */
  id: string
  /** Bilingual full name, e.g. "Lin, Hui-Yu · 林慧瑜". Stored encrypted. */
  fullName: string
  displayLabel?: string
  relation: "spouse" | "daughter" | "son" | "accountant" | "lawyer" | "other"
  /** Beneficiary share (0–100). Null = not a beneficiary. */
  sharePct?: number
  /** What the portal allows this person to see. */
  permissions: "none" | "read" | "read_trade" | "tax_only" | "limited"
  contact?: { email?: string; phone?: string }
  revisitAt?: string
}

export const profiles = pgTable("profiles", {
  clientId: uuid("client_id")
    .primaryKey()
    .references(() => clients.id, { onDelete: "cascade" }),
  legalNameEncrypted: bytea("legal_name_encrypted").notNull(),
  legalNameHash: bytea("legal_name_hash"),
  // Granular name fields — added 2026-05. legal_name_encrypted stays as the
  // KYC-anchor (single string, locked). These four are the per-component
  // names the Profile page shows + can edit.
  firstNameEncrypted: bytea("first_name_encrypted"),
  lastNameEncrypted: bytea("last_name_encrypted"),
  chineseNameEncrypted: bytea("chinese_name_encrypted"),
  preferredNameEncrypted: bytea("preferred_name_encrypted"),
  preferredChineseNameEncrypted: bytea("preferred_chinese_name_encrypted"),
  dateOfBirth: date("date_of_birth"),
  nationality: text("nationality"),
  hkidEncrypted: bytea("hkid_encrypted"),
  passportEncrypted: bytea("passport_encrypted"),
  /** Unified identities slot: encrypted JSON array of ProfileIdentity. */
  identitiesEncrypted: bytea("identities_encrypted"),
  /** Custodian-side trading status; e.g. 'active' / 'restricted' / 'pending'. */
  tradingStatus: text("trading_status"),
  primaryEmail: citext("primary_email"),
  primaryPhone: text("primary_phone"),
  /** Encrypted JSON array of ProfilePerson — alternative to the
   *  `beneficiaries` table. Populated when the editor mode is active. */
  peopleAndBeneficiariesEncrypted: bytea("people_and_beneficiaries_encrypted"),
  preferredChannel: text("preferred_channel")
    .default("email")
    .$type<"email" | "portal" | "whatsapp" | "phone">(),
  quietHoursLocal: jsonb("quiet_hours_local"),
  marketingConsent: boolean("marketing_consent").notNull().default(true),
  caseStudyConsent: boolean("case_study_consent").notNull().default(false),
  updatedAt: ts("updated_at").notNull().defaultNow(),
})

export const addresses = pgTable(
  "addresses",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    kind: text("kind").notNull().$type<"residential" | "mailing" | "office">(),
    line1Encrypted: bytea("line1_encrypted").notNull(),
    line2Encrypted: bytea("line2_encrypted"),
    city: text("city"),
    region: text("region"),
    countryIso: text("country_iso").notNull(),
    postalCode: text("postal_code"),
    isPrimary: boolean("is_primary").notNull().default(false),
    verifiedAt: ts("verified_at"),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [index("addresses_client_idx").on(t.clientId)],
)

export const taxResidencies = pgTable(
  "tax_residencies",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    countryIso: text("country_iso").notNull(),
    taxIdEncrypted: bytea("tax_id_encrypted"),
    isPrimary: boolean("is_primary").notNull().default(false),
    treatyForm: text("treaty_form"),
    treatyFormSignedAt: ts("treaty_form_signed_at"),
    treatyFormRenewsAt: ts("treaty_form_renews_at"),
    establishedAt: ts("established_at"),
  },
  (t) => [index("tax_residencies_client_idx").on(t.clientId)],
)

export const beneficiaries = pgTable(
  "beneficiaries",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    fullNameEncrypted: bytea("full_name_encrypted").notNull(),
    displayLabel: text("display_label"),
    relation: text("relation")
      .notNull()
      .$type<"spouse" | "daughter" | "son" | "accountant" | "other">(),
    sharePct: numeric("share_pct", { precision: 5, scale: 2 }),
    permissions: text("permissions")
      .notNull()
      .default("none")
      .$type<"none" | "read" | "read_trade" | "tax_only" | "limited">(),
    contactEncrypted: jsonb("contact_encrypted"),
    authorizedAt: ts("authorized_at"),
    revisitAt: date("revisit_at"),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [index("beneficiaries_client_idx").on(t.clientId)],
)

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  PORTFOLIO & POSITIONS                                                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

export const accounts = pgTable(
  "accounts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    broker: text("broker").notNull(),
    accountNumberMasked: text("account_number_masked").notNull(),
    accountNumberEncrypted: bytea("account_number_encrypted"),
    baseCurrency: text("base_currency").notNull(),
    isActive: boolean("is_active").notNull().default(true),
    openedAt: ts("opened_at"),
    notes: text("notes"),
    // Broker-precomputed buying power, USD-denominated. NULL means the API
    // falls back to a Reg-T heuristic (`available_cash + 2 * equity_nav`).
    buyingPowerUsd: numeric("buying_power_usd", { precision: 20, scale: 4 }),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [index("accounts_client_idx").on(t.clientId)],
)

export const positions = pgTable(
  "positions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    accountId: uuid("account_id").notNull().references(() => accounts.id, { onDelete: "cascade" }),
    assetType: text("asset_type")
      .notNull()
      .$type<"equity" | "option" | "future" | "bond" | "crypto" | "cash">(),
    symbol: text("symbol").notNull(),
    displayName: text("display_name"),
    isin: text("isin"),
    cusip: text("cusip"),

    quantity: numeric("quantity", { precision: 20, scale: 8 }).notNull(),
    side: text("side").notNull().default("long").$type<"long" | "short">(),
    costBasisTotal: numeric("cost_basis_total", { precision: 20, scale: 4 }),
    costBasisAvg: numeric("cost_basis_avg", { precision: 20, scale: 8 }),
    markPrice: numeric("mark_price", { precision: 20, scale: 8 }),
    marketValue: numeric("market_value", { precision: 20, scale: 4 }),
    unrealizedPl: numeric("unrealized_pl", { precision: 20, scale: 4 }),
    unrealizedPlPct: numeric("unrealized_pl_pct", { precision: 10, scale: 4 }),

    // Option-specific
    optionUnderlying: text("option_underlying"),
    optionStrike: numeric("option_strike", { precision: 20, scale: 4 }),
    optionExpiry: date("option_expiry"),
    optionType: text("option_type").$type<"C" | "P" | null>(),
    optionDelta: numeric("option_delta", { precision: 10, scale: 6 }),
    optionGamma: numeric("option_gamma", { precision: 10, scale: 6 }),
    optionTheta: numeric("option_theta", { precision: 20, scale: 4 }),
    optionVega: numeric("option_vega", { precision: 20, scale: 4 }),
    optionIv: numeric("option_iv", { precision: 10, scale: 6 }),

    // Future-specific
    futureUnderlying: text("future_underlying"),
    futureExpiry: date("future_expiry"),
    futureInitialMargin: numeric("future_initial_margin", { precision: 20, scale: 4 }),
    futureDv01: numeric("future_dv01", { precision: 20, scale: 4 }),

    // Bond-specific
    bondCouponPct: numeric("bond_coupon_pct", { precision: 8, scale: 4 }),
    bondMaturity: date("bond_maturity"),
    bondYtm: numeric("bond_ytm", { precision: 8, scale: 4 }),
    bondDuration: numeric("bond_duration", { precision: 8, scale: 4 }),
    bondFaceValue: numeric("bond_face_value", { precision: 20, scale: 4 }),

    dayChange: numeric("day_change", { precision: 20, scale: 4 }),
    dayChangePct: numeric("day_change_pct", { precision: 10, scale: 4 }),

    openedAt: ts("opened_at"),
    closedAt: ts("closed_at"),
    lastSyncedAt: ts("last_synced_at"),

    createdAt: ts("created_at").notNull().defaultNow(),
    updatedAt: ts("updated_at").notNull().defaultNow(),
  },
  (t) => [
    index("positions_account_idx").on(t.accountId).where(sql`closed_at is null`),
    index("positions_type_idx").on(t.assetType).where(sql`closed_at is null`),
    index("positions_symbol_idx").on(t.symbol),
  ],
)

export const cashBalances = pgTable(
  "cash_balances",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    accountId: uuid("account_id").notNull().references(() => accounts.id, { onDelete: "cascade" }),
    currency: text("currency").notNull(),
    amountLocal: numeric("amount_local", { precision: 20, scale: 4 }).notNull(),
    fxRateToUsd: numeric("fx_rate_to_usd", { precision: 20, scale: 8 }).notNull(),
    // amount_usd is a generated column in the DB; not writable from app code.
    amountUsd: numeric("amount_usd", { precision: 20, scale: 4 }).generatedAlwaysAs(
      sql`amount_local * fx_rate_to_usd`,
    ),
    available: numeric("available", { precision: 20, scale: 4 }).notNull(),
    marginUsed: numeric("margin_used", { precision: 20, scale: 4 }).notNull().default("0"),
    lastSyncedAt: ts("last_synced_at").notNull().defaultNow(),
  },
  (t) => [uniqueIndex("cash_balances_acct_ccy_uq").on(t.accountId, t.currency)],
)

export const transactions = pgTable(
  "transactions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    accountId: uuid("account_id").notNull().references(() => accounts.id, { onDelete: "restrict" }),
    positionId: uuid("position_id").references(() => positions.id, { onDelete: "set null" }),
    txnType: text("txn_type")
      .notNull()
      .$type<"buy" | "sell" | "dividend" | "coupon" | "fee" | "wire_in" | "wire_out" | "fx">(),
    symbol: text("symbol"),
    quantity: numeric("quantity", { precision: 20, scale: 8 }),
    price: numeric("price", { precision: 20, scale: 8 }),
    amount: numeric("amount", { precision: 20, scale: 4 }).notNull(),
    currency: text("currency").notNull(),
    fee: numeric("fee", { precision: 20, scale: 4 }).default("0"),
    description: text("description"),
    tradeDate: date("trade_date"),
    settlementDate: date("settlement_date"),
    externalRef: text("external_ref"),
    occurredAt: ts("occurred_at").notNull(),
  },
  (t) => [
    index("txn_account_time_idx").on(t.accountId, t.occurredAt),
    index("txn_position_idx").on(t.positionId),
  ],
)

export const dailyNav = pgTable(
  "daily_nav",
  {
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    asOf: date("as_of").notNull(),
    navTotalUsd: numeric("nav_total_usd", { precision: 20, scale: 4 }).notNull(),
    navEquities: numeric("nav_equities", { precision: 20, scale: 4 }),
    navOptions: numeric("nav_options", { precision: 20, scale: 4 }),
    navFutures: numeric("nav_futures", { precision: 20, scale: 4 }),
    navBonds: numeric("nav_bonds", { precision: 20, scale: 4 }),
    navCash: numeric("nav_cash", { precision: 20, scale: 4 }),
    navCrypto: numeric("nav_crypto", { precision: 20, scale: 4 }),
    dayPl: numeric("day_pl", { precision: 20, scale: 4 }),
    dayPlPct: numeric("day_pl_pct", { precision: 10, scale: 4 }),
    betaToSpy: numeric("beta_to_spy", { precision: 8, scale: 4 }),
  },
  (t) => [primaryKey({ columns: [t.clientId, t.asOf] })],
)

export const riskMetrics = pgTable(
  "risk_metrics",
  {
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    asOf: date("as_of").notNull(),
    beta: numeric("beta", { precision: 8, scale: 4 }),
    sharpe: numeric("sharpe", { precision: 8, scale: 4 }),
    sortino: numeric("sortino", { precision: 8, scale: 4 }),
    maxDrawdown: numeric("max_drawdown", { precision: 8, scale: 4 }),
    volAnnualized: numeric("vol_annualized", { precision: 8, scale: 4 }),
  },
  (t) => [primaryKey({ columns: [t.clientId, t.asOf] })],
)

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  SCHEDULES                                                                 ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

export type EventType =
  | "option_expiry" | "bond_coupon" | "earnings" | "dividend"
  | "macro" | "advisor_call" | "report_delivery" | "rebalance"
  | "compliance_renewal" | "personal"

export const events = pgTable(
  "events",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    eventType: text("event_type").notNull().$type<EventType>(),
    source: text("source")
      .notNull()
      .$type<"system" | "broker" | "macro" | "advisor" | "personal">(),
    title: text("title").notNull(),
    description: text("description"),
    ticker: text("ticker"),
    positionId: uuid("position_id").references(() => positions.id, { onDelete: "set null" }),
    startsAt: ts("starts_at").notNull(),
    endsAt: ts("ends_at"),
    isAllDay: boolean("is_all_day").notNull().default(false),
    displayTz: text("display_tz"),
    isCritical: boolean("is_critical").notNull().default(false),
    isArchived: boolean("is_archived").notNull().default(false),
    rrule: text("rrule"),
    // Free-form jsonb that drives Event Detail's rich main column.
    // See docs/event-metadata-schema.md + types/event-metadata.ts.
    metadata: jsonb("metadata").$type<EventMetadata>(),
    createdAt: ts("created_at").notNull().defaultNow(),
    updatedAt: ts("updated_at").notNull().defaultNow(),
  },
  (t) => [
    index("events_client_time_idx").on(t.clientId, t.startsAt).where(sql`is_archived = false`),
    index("events_critical_idx").on(t.clientId, t.startsAt)
      .where(sql`is_critical = true and is_archived = false`),
  ],
)

export const eventReminders = pgTable(
  "event_reminders",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    eventId: uuid("event_id").notNull().references(() => events.id, { onDelete: "cascade" }),
    channel: text("channel").notNull().$type<"email" | "push" | "sms">(),
    leadMinutes: integer("lead_minutes").notNull(),
    status: text("status")
      .notNull()
      .default("pending")
      .$type<"pending" | "sent" | "failed" | "skipped">(),
    sentAt: ts("sent_at"),
  },
  (t) => [index("event_reminders_pending_idx").on(t.eventId).where(sql`status = 'pending'`)],
)

export const calendarSubscriptions = pgTable("calendar_subscriptions", {
  clientId: uuid("client_id")
    .primaryKey()
    .references(() => clients.id, { onDelete: "cascade" }),
  icsToken: text("ics_token").notNull().unique(),
  lastFetchedAt: ts("last_fetched_at"),
  fetchCount: bigint("fetch_count", { mode: "number" }).notNull().default(0),
  createdAt: ts("created_at").notNull().defaultNow(),
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  REPORTS & RESEARCH                                                        ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

/**
 * Inbox-classification category for reports. Drives the "Tune what arrives
 * in your inbox" toggle list on the Reports page and acts as the primary
 * filter chip. Distinct from `reportType` (which is more granular and
 * legacy) — a report can be `reportType: 'risk_attribution'` AND
 * `category: 'must_read'`.
 */
export type ReportCategory =
  | "must_read"
  | "attribution"
  | "quarterly_performance"
  | "macro_regime"
  | "strategy_model"
  | "custom_research"

export const reports = pgTable(
  "reports",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    reportType: text("report_type")
      .notNull()
      .$type<"risk_attribution" | "performance" | "strategy_memo" | "macro" | "custom">(),
    // Inbox category (added 2026-05). Optional for now so legacy rows still
    // load; future inserts should always set it.
    category: text("category").$type<ReportCategory>(),
    title: text("title").notNull(),
    subtitle: text("subtitle"),
    bodyMd: text("body_md"),
    bodyFormat: text("body_format").notNull().default("md").$type<"md" | "mdx">(),
    // Rich body (sections-based, see docs/event-metadata-schema.md). Same
    // schema as events.metadata; `bodyMd` stays as a legacy / fallback.
    metadata: jsonb("metadata").$type<EventMetadata>(),
    authorAdvisorId: uuid("author_advisor_id").references(() => advisors.id, {
      onDelete: "set null",
    }),
    clientId: uuid("client_id").references(() => clients.id),
    pages: integer("pages"),
    chartsCount: integer("charts_count"),
    tablesCount: integer("tables_count"),
    readTimeMin: integer("read_time_min"),
    attachments: jsonb("attachments"),
    pdfUrl: text("pdf_url"),
    pdfSha256: text("pdf_sha256"),
    publishedAt: ts("published_at"),
    isDraft: boolean("is_draft").notNull().default(true),
    createdAt: ts("created_at").notNull().defaultNow(),
    updatedAt: ts("updated_at").notNull().defaultNow(),
  },
  (t) => [
    index("reports_type_published_idx").on(t.reportType, t.publishedAt).where(sql`is_draft = false`),
    index("reports_client_idx").on(t.clientId).where(sql`is_draft = false`),
  ],
)

export const reportAccess = pgTable(
  "report_access",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    reportId: uuid("report_id").notNull().references(() => reports.id, { onDelete: "cascade" }),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    firstReadAt: ts("first_read_at").notNull().defaultNow(),
    lastReadAt: ts("last_read_at").notNull().defaultNow(),
    readCount: integer("read_count").notNull().default(1),
    isBookmarked: boolean("is_bookmarked").notNull().default(false),
    bookmarkedAt: ts("bookmarked_at"),
  },
  (t) => [uniqueIndex("report_access_uq").on(t.reportId, t.clientId)],
)

export const reportSubscriptions = pgTable(
  "report_subscriptions",
  {
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    reportType: text("report_type").notNull(),
    channels: text("channels").array().notNull().default(sql`'{}'::text[]`),
  },
  (t) => [primaryKey({ columns: [t.clientId, t.reportType] })],
)

export const customResearchRequests = pgTable("custom_research_requests", {
  id: uuid("id").defaultRandom().primaryKey(),
  clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
  userId: uuid("user_id").notNull().references(() => users.id),
  projectType: text("project_type")
    .notNull()
    .$type<"strategy" | "deepdive" | "backtest" | "taxopt" | "automation" | "other">(),
  workingTitle: text("working_title"),
  question: text("question").notNull(),
  linkedTickers: text("linked_tickers").array(),
  capitalAtStake: numeric("capital_at_stake", { precision: 20, scale: 4 }),
  timelinePref: text("timeline_pref").$type<"rush" | "standard" | "flexible">(),
  referenceMaterials: text("reference_materials"),
  estFeeLowUsd: numeric("est_fee_low_usd", { precision: 20, scale: 4 }),
  estFeeHighUsd: numeric("est_fee_high_usd", { precision: 20, scale: 4 }),
  status: text("status")
    .notNull()
    .default("submitted")
    .$type<"submitted" | "scoping" | "proposed" | "active" | "closed" | "declined">(),
  submittedAt: ts("submitted_at").notNull().defaultNow(),
  scopedAt: ts("scoped_at"),
  proposedAt: ts("proposed_at"),
  closedAt: ts("closed_at"),
  resultingProjectId: uuid("resulting_project_id"),
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  DOCUMENTS VAULT                                                           ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

/**
 * Structured DocumentMetadata for the Document Viewer sidebar.
 * Stored in `documents.metadata` (jsonb). Kept distinct from
 * EventMetadata because the use case is different (no rendered body,
 * just sidebar context).
 */
export interface DocumentLinkedEntity {
  kind: "position" | "account" | "report" | "event" | "invoice" | "advisor" | "external"
  /** Internal id (e.g. position UUID) when kind is one of ours; null/omit for external. */
  id?: string
  /** Human-facing label (bilingual or plain). */
  label: { en: string; zh: string } | string
  /** Optional short subtitle / detail. */
  sub?: { en: string; zh: string } | string
}

export interface DocumentMetadata {
  /** Entities this document relates to (positions, accounts, advisors, …). */
  linkedEntities?: DocumentLinkedEntity[]
  /** Sibling document UUIDs to surface as "Related documents" in the sidebar. */
  relatedDocumentIds?: string[]
  /** Free-form notes / issuer details / etc. */
  [key: string]: unknown
}

export const documents = pgTable(
  "documents",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "restrict" }),
    category: text("category")
      .notNull()
      .$type<"statement" | "tax" | "custody" | "engagement" | "compliance" | "banking" | "misc">(),
    title: text("title").notNull(),
    displayCode: text("display_code"),
    sourceLabel: text("source_label"),
    sourceParty: text("source_party"),
    description: text("description"),
    fileUrl: text("file_url"),
    fileFormat: text("file_format")
      .notNull()
      .$type<"pdf" | "xlsx" | "docx" | "jpg" | "png" | "csv" | "txt">(),
    fileSizeBytes: bigint("file_size_bytes", { mode: "number" }),
    pages: integer("pages"),
    sha256: text("sha256"),
    issuedAt: ts("issued_at"),
    deliveredAt: ts("delivered_at"),
    retentionUntil: date("retention_until"),
    isArchived: boolean("is_archived").notNull().default(false),
    /**
     * UI grouping flag. When true, the document collapses into a single
     * "Folded" group at the bottom of the Documents list page, regardless
     * of its category. Only changeable via backend write (no UI toggle in MVP).
     */
    isFolded: boolean("is_folded").notNull().default(false),
    /** Structured sidebar metadata (linked entities + related docs). */
    metadata: jsonb("metadata").$type<DocumentMetadata>(),
    status: text("status")
      .notNull()
      .default("active")
      .$type<"active" | "pending_signature" | "pending_upload" | "expired" | "superseded">(),
    pendingAction: text("pending_action"),
    pendingDueAt: ts("pending_due_at"),
    tags: text("tags").array(),
    relatedPositionId: uuid("related_position_id").references(() => positions.id),
    relatedEventId: uuid("related_event_id").references(() => events.id),
    taxYear: integer("tax_year"),
    uploadedByUserId: uuid("uploaded_by_user_id").references(() => users.id),
    createdAt: ts("created_at").notNull().defaultNow(),
    updatedAt: ts("updated_at").notNull().defaultNow(),
  },
  (t) => [
    index("documents_client_cat_idx").on(t.clientId, t.category, t.issuedAt),
    index("documents_pending_idx").on(t.clientId).where(sql`status = 'pending_signature'`),
  ],
)

export const documentSignatures = pgTable("document_signatures", {
  id: uuid("id").defaultRandom().primaryKey(),
  documentId: uuid("document_id").notNull().references(() => documents.id, { onDelete: "cascade" }),
  signerUserId: uuid("signer_user_id").notNull().references(() => users.id),
  signatureImageUrl: text("signature_image_url"),
  signatureMethod: text("signature_method").notNull().$type<"drawn" | "typed" | "docusign">(),
  signedAt: ts("signed_at").notNull().defaultNow(),
  signedIp: inet("signed_ip"),
  signedUserAgent: text("signed_user_agent"),
  envelopeRef: text("envelope_ref"),
})

export const documentActions = pgTable(
  "document_actions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    documentId: uuid("document_id").notNull().references(() => documents.id, { onDelete: "cascade" }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    action: text("action")
      .notNull()
      .$type<"view" | "download" | "share" | "forward" | "print">(),
    recipient: text("recipient"),
    ip: inet("ip"),
    occurredAt: ts("occurred_at").notNull().defaultNow(),
  },
  (t) => [index("doc_actions_doc_time_idx").on(t.documentId, t.occurredAt)],
)

export const documentRequests = pgTable("document_requests", {
  id: uuid("id").defaultRandom().primaryKey(),
  clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
  userId: uuid("user_id").notNull().references(() => users.id),
  requestType: text("request_type")
    .notNull()
    .$type<"bank_ref" | "asset_confirm" | "reconstruct" | "cost_basis" | "tax_pkg" | "custom">(),
  purpose: text("purpose"),
  recipient: text("recipient"),
  asOfDate: date("as_of_date"),
  neededByDate: date("needed_by_date"),
  format: text("format")
    .notNull()
    .$type<"pdf_digital" | "pdf_wet" | "hardcopy" | "notarized">(),
  notes: text("notes"),
  status: text("status")
    .notNull()
    .default("submitted")
    .$type<"submitted" | "in_progress" | "delivered" | "cancelled">(),
  submittedAt: ts("submitted_at").notNull().defaultNow(),
  deliveredAt: ts("delivered_at"),
  resultingDocumentId: uuid("resulting_document_id").references(() => documents.id),
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  BILLING                                                                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

export const engagements = pgTable("engagements", {
  id: uuid("id").defaultRandom().primaryKey(),
  clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "restrict" }),
  tier: text("tier").notNull().$type<"diagnostic" | "retainer" | "build">(),
  monthlyFeeUsd: numeric("monthly_fee_usd", { precision: 20, scale: 4 }),
  startedAt: date("started_at").notNull(),
  endsAt: date("ends_at"),
  noticeDays: integer("notice_days").notNull().default(60),
  masterDocId: uuid("master_doc_id").references(() => documents.id),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: ts("created_at").notNull().defaultNow(),
})

export const paymentMethods = pgTable("payment_methods", {
  id: uuid("id").defaultRandom().primaryKey(),
  clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
  methodType: text("method_type").notNull().$type<"wire" | "card">(),
  displayLabel: text("display_label").notNull(),
  lastFour: text("last_four"),
  bankName: text("bank_name"),
  isDefault: boolean("is_default").notNull().default(false),
  isActive: boolean("is_active").notNull().default(true),
  authorizedAt: ts("authorized_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
})

export const invoices = pgTable(
  "invoices",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "restrict" }),
    invoiceNumber: text("invoice_number").notNull().unique(),
    kind: text("kind").notNull().$type<"retainer" | "project" | "ad_hoc">(),
    periodStart: date("period_start"),
    periodEnd: date("period_end"),
    description: text("description"),
    amountUsd: numeric("amount_usd", { precision: 20, scale: 4 }).notNull(),
    status: text("status")
      .notNull()
      .default("issued")
      .$type<"issued" | "paid" | "overdue" | "void">(),
    issuedAt: date("issued_at").notNull(),
    dueAt: date("due_at"),
    paidAt: date("paid_at"),
    paymentMethodId: uuid("payment_method_id").references(() => paymentMethods.id, {
      onDelete: "set null",
    }),
    pdfDocumentId: uuid("pdf_document_id").references(() => documents.id),
    externalRef: text("external_ref"),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [index("invoices_client_issued_idx").on(t.clientId, t.issuedAt)],
)

/**
 * Structured metadata for a custom project. Stored in
 * `custom_projects.metadata` (jsonb). Drives the Billing page's per-project
 * detail row + (later) a dedicated project-detail view. Free-form by
 * design — we want to be able to add new project shapes without schema
 * migration.
 */
export interface CustomProjectMilestone {
  /** Stable id for editor diffing. */
  id: string
  label: { en: string; zh: string } | string
  /** ISO date when this milestone is targeted (or null = TBD). */
  dueAt?: string | null
  /** When it actually closed; null = not yet. */
  completedAt?: string | null
}

export interface CustomProjectDeliverable {
  kind: "report" | "memo" | "spreadsheet" | "code" | "other"
  label: { en: string; zh: string } | string
  /** Optional reference to a delivered document / report id. */
  documentId?: string
  reportId?: string
  /** Free-form notes shown under the deliverable line. */
  notes?: { en: string; zh: string } | string
}

export interface CustomProjectMetadata {
  /** Short bilingual summary shown in the Billing page expansion. */
  summary?: { en: string; zh: string } | string
  /** Per-milestone progress timeline. */
  milestones?: CustomProjectMilestone[]
  /** Tangible outputs produced by the project. */
  deliverables?: CustomProjectDeliverable[]
  /** Anything else clients/advisors want to record here. */
  notes?: { en: string; zh: string } | string
  [key: string]: unknown
}

export const customProjects = pgTable("custom_projects", {
  id: uuid("id").defaultRandom().primaryKey(),
  clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "restrict" }),
  name: text("name").notNull(),
  projectType: text("project_type").notNull(),
  feeTotalUsd: numeric("fee_total_usd", { precision: 20, scale: 4 }),
  feePaidUsd: numeric("fee_paid_usd", { precision: 20, scale: 4 }).default("0"),
  status: text("status")
    .notNull()
    .default("active")
    .$type<"active" | "completed" | "cancelled">(),
  sowDocumentId: uuid("sow_document_id").references(() => documents.id),
  deliverableReportId: uuid("deliverable_report_id").references(() => reports.id),
  requestId: uuid("request_id").references(() => customResearchRequests.id),
  startedAt: date("started_at"),
  deliveredAt: date("delivered_at"),
  closedAt: date("closed_at"),
  /** Structured project payload — see CustomProjectMetadata above. */
  metadata: jsonb("metadata").$type<CustomProjectMetadata>(),
  createdAt: ts("created_at").notNull().defaultNow(),
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  COMMUNICATION                                                             ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

export const messageThreads = pgTable(
  "message_threads",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    advisorId: uuid("advisor_id").references(() => advisors.id, { onDelete: "set null" }),
    subject: text("subject").notNull(),
    isArchived: boolean("is_archived").notNull().default(false),
    lastMessageAt: ts("last_message_at").notNull().defaultNow(),
    unreadCountClient: integer("unread_count_client").notNull().default(0),
    unreadCountAdvisor: integer("unread_count_advisor").notNull().default(0),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [index("threads_client_idx").on(t.clientId, t.lastMessageAt)],
)

export const messages = pgTable(
  "messages",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    threadId: uuid("thread_id").notNull().references(() => messageThreads.id, { onDelete: "cascade" }),
    senderUserId: uuid("sender_user_id").references(() => users.id, { onDelete: "set null" }),
    senderAdvisorId: uuid("sender_advisor_id").references(() => advisors.id, { onDelete: "set null" }),
    body: text("body").notNull(),
    urgency: text("urgency")
      .notNull()
      .default("routine")
      .$type<"routine" | "soon" | "urgent">(),
    attachments: jsonb("attachments"),
    sentAt: ts("sent_at").notNull().defaultNow(),
    readAt: ts("read_at"),
  },
  (t) => [index("messages_thread_time_idx").on(t.threadId, t.sentAt)],
)

export const meetingBookings = pgTable(
  "meeting_bookings",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id").notNull().references(() => clients.id, { onDelete: "cascade" }),
    advisorId: uuid("advisor_id").notNull().references(() => advisors.id, { onDelete: "restrict" }),
    scheduledAt: ts("scheduled_at").notNull(),
    durationMin: integer("duration_min").notNull().default(60),
    meetingType: text("meeting_type")
      .notNull()
      .$type<"video" | "phone" | "in_person">(),
    agenda: text("agenda"),
    meetingUrl: text("meeting_url"),
    location: text("location"),
    status: text("status")
      .notNull()
      .default("confirmed")
      .$type<"pending" | "confirmed" | "cancelled" | "completed">(),
    relatedEventId: uuid("related_event_id").references(() => events.id),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [index("meetings_client_time_idx").on(t.clientId, t.scheduledAt)],
)

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  AUDIT LOG (immutable; 7-year retention; never UPDATE/DELETE)              ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

export const auditLog = pgTable(
  "audit_log",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    occurredAt: ts("occurred_at").notNull().defaultNow(),
    userId: uuid("user_id"),
    clientId: uuid("client_id"),
    ip: inet("ip"),
    userAgent: text("user_agent"),
    action: text("action").notNull(),
    resourceType: text("resource_type"),
    resourceId: uuid("resource_id"),
    requestSha256: text("request_sha256"),
    beforeState: jsonb("before_state"),
    afterState: jsonb("after_state"),
    metadata: jsonb("metadata"),
  },
  (t) => [
    index("audit_user_time_idx").on(t.userId, t.occurredAt),
    index("audit_client_time_idx").on(t.clientId, t.occurredAt),
    index("audit_action_idx").on(t.action, t.occurredAt),
  ],
)

// ─── Inferred types for convenience ────────────────────────────────────────

export type User = typeof users.$inferSelect
export type NewUser = typeof users.$inferInsert
export type Client = typeof clients.$inferSelect
export type Session = typeof sessions.$inferSelect
export type Position = typeof positions.$inferSelect
export type Event = typeof events.$inferSelect
export type Report = typeof reports.$inferSelect
export type Document = typeof documents.$inferSelect
export type Invoice = typeof invoices.$inferSelect
