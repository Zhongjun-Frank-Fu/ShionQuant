/**
 * Development seed.
 *
 * Inserts a known-good test fixture so M1 / M2 (and beyond) can be exercised
 * without a manual signup flow:
 *
 *   User      chen@test.local                / password: demo-password-2026
 *   Client    SQ-0042 · tier=retainer · HK
 *   Advisor   KT — Kira Tanaka — Hong Kong (UTC+8)
 *   Auth      TOTP factor (provisioning URI printed to console for QR scanning)
 *   Recovery  10 single-use codes (printed once to console)
 *   Profile   M2: encrypted legal name + DOB + nationality + HKID
 *   Address   M2: residential, encrypted lines
 *   Tax       M2: HK primary tax residency
 *   People    M2: spouse beneficiary
 *
 * Idempotent: re-running deletes the old fixture rows and recreates them.
 * Safe in dev only — refuses to run if NODE_ENV=production.
 *
 * Run with: pnpm seed
 */

import "dotenv/config"
import { initEnv } from "../env.js"

// Standalone Node script — manually init env before any module reads it.
initEnv(process.env)
import { and, eq, inArray } from "drizzle-orm"

import { generateRecoveryCodes, hashPassword } from "../auth/argon2.js"
import { hashRecoveryCodes } from "../auth/recovery.js"
import { generateSecret, provisioningUri } from "../auth/totp.js"
import { encryptAndHash, encryptField, encryptSecret } from "../lib/crypto.js"
import { randomBytes } from "node:crypto"

import {
  accounts,
  addresses,
  advisors,
  authFactors,
  beneficiaries,
  calendarSubscriptions,
  cashBalances,
  clients,
  customResearchRequests,
  dailyNav,
  db,
  documents,
  eventReminders,
  events,
  meetingBookings,
  messageThreads,
  messages,
  positions,
  profiles,
  recoveryCodes,
  reportSubscriptions,
  reports,
  riskMetrics,
  taxResidencies,
  users,
} from "./client.js"

const TEST_EMAIL = "chen@test.local"
const TEST_PASSWORD = "demo-password-2026"
const TEST_CLIENT_NUMBER = "SQ-0042"
const ADVISOR_EMAIL = "kt@shion.test"

async function main() {
  if (process.env.NODE_ENV === "production") {
    console.error("Refusing to seed in production.")
    process.exit(1)
  }

  console.log("Seeding test fixture...")

  // ─── 1. Wipe prior fixture (cascade does most of the work) ────────────────
  const existingUser = await db.query.users.findFirst({
    where: eq(users.email, TEST_EMAIL),
  })
  if (existingUser) {
    console.log("  • removing prior user:", existingUser.id)
    // FK ON DELETE CASCADE handles auth_factors, recovery_codes, sessions,
    // login_events (set null), and most child rows. Clients reference users
    // via ON DELETE RESTRICT, so we must remove the client row first.
    await db.delete(clients).where(eq(clients.userId, existingUser.id))
    await db.delete(users).where(eq(users.id, existingUser.id))
  }
  await db.delete(advisors).where(inArray(advisors.email, [ADVISOR_EMAIL]))

  // ─── 2. Advisor (KT) ──────────────────────────────────────────────────────
  const [advisor] = await db
    .insert(advisors)
    .values({
      fullName: "Kira Tanaka",
      initials: "KT",
      role: "Lead advisor",
      location: "Hong Kong",
      timezone: "Asia/Hong_Kong",
      email: ADVISOR_EMAIL,
      isActive: true,
    })
    .returning()
  console.log("  ✓ advisor:", advisor!.fullName, `<${advisor!.email}>`)

  // ─── 3. User (Mr. Chen) ───────────────────────────────────────────────────
  const passwordHash = await hashPassword(TEST_PASSWORD)
  const [user] = await db
    .insert(users)
    .values({
      email: TEST_EMAIL,
      passwordHash,
      preferredName: "Chen",
      preferredLang: "zh-Hant",
      isActive: true,
      emailVerifiedAt: new Date(),
    })
    .returning()
  console.log("  ✓ user:", user!.email)

  // ─── 4. Client record ─────────────────────────────────────────────────────
  const [client] = await db
    .insert(clients)
    .values({
      userId: user!.id,
      clientNumber: TEST_CLIENT_NUMBER,
      tier: "retainer",
      jurisdiction: "HK",
      primaryAdvisorId: advisor!.id,
    })
    .returning()
  console.log("  ✓ client:", client!.clientNumber, `(${client!.tier})`)

  // ─── 5. TOTP factor ───────────────────────────────────────────────────────
  const totpSecret = generateSecret()
  await db.insert(authFactors).values({
    userId: user!.id,
    factorType: "totp",
    label: "Authenticator (seeded)",
    secretEncrypted: await encryptSecret(totpSecret),
    isPrimary: true,
  })
  const otpauthUri = provisioningUri(totpSecret, TEST_EMAIL)

  // ─── 6. Recovery codes ────────────────────────────────────────────────────
  const codes = generateRecoveryCodes(10)
  const hashed = await hashRecoveryCodes(codes)
  await db.insert(recoveryCodes).values(
    hashed.map((codeHash) => ({
      userId: user!.id,
      codeHash,
    })),
  )

  // ─── 7. Profile (encrypted KYC) ───────────────────────────────────────────
  const legalName = "陳啟明"
  const { encrypted: legalNameEncrypted, hash: legalNameHash } =
    await encryptAndHash(legalName)
  await db.insert(profiles).values({
    clientId: client!.id,
    legalNameEncrypted,
    legalNameHash,
    dateOfBirth: "1968-04-23",
    nationality: "HK",
    hkidEncrypted: await encryptField("A1234567"),
    passportEncrypted: null,
    primaryEmail: TEST_EMAIL,
    primaryPhone: "+852 9123 4567",
    preferredChannel: "portal",
    quietHoursLocal: { start: "22:00", end: "08:00", timezone: "Asia/Hong_Kong" },
    marketingConsent: true,
    caseStudyConsent: false,
  })
  console.log("  ✓ profile (encrypted)")

  // ─── 8. Address ───────────────────────────────────────────────────────────
  await db.insert(addresses).values({
    clientId: client!.id,
    kind: "residential",
    line1Encrypted: await encryptField("中半山干德道 12 號"),
    line2Encrypted: await encryptField("Mid-Levels Tower, 28/F"),
    city: "Hong Kong",
    region: "Hong Kong Island",
    countryIso: "HK",
    postalCode: null,
    isPrimary: true,
  })
  console.log("  ✓ address (residential, primary)")

  // ─── 9. Tax residency ─────────────────────────────────────────────────────
  await db.insert(taxResidencies).values({
    clientId: client!.id,
    countryIso: "HK",
    taxIdEncrypted: await encryptField("A1234567"),
    isPrimary: true,
    treatyForm: null,
    establishedAt: new Date("1968-04-23"),
  })
  console.log("  ✓ tax residency (HK, primary)")

  // ─── 10. Beneficiary ──────────────────────────────────────────────────────
  await db.insert(beneficiaries).values({
    clientId: client!.id,
    fullNameEncrypted: await encryptField("陳麗華"),
    displayLabel: "Wife",
    relation: "spouse",
    sharePct: "100.00",
    permissions: "tax_only",
    contactEncrypted: { email: "lihua@chen.family.test", phone: "+852 9988 7766" },
    authorizedAt: new Date(),
  })
  console.log("  ✓ beneficiary (spouse)")

  // ─── 11. Broker account ───────────────────────────────────────────────────
  const [account] = await db
    .insert(accounts)
    .values({
      clientId: client!.id,
      broker: "Interactive Brokers",
      accountNumberMasked: "U•••4291",
      accountNumberEncrypted: await encryptField("U7204291"),
      baseCurrency: "USD",
      isActive: true,
      openedAt: new Date("2022-09-15"),
      notes: "Pattern-day-trader margin enabled",
      // Broker-precomputed buying power. Mr. Chen's IBKR account reports
      // ~$1.876M; portfolio.ts will use this directly (source: 'broker').
      buyingPowerUsd: "1876500",
    })
    .returning()
  console.log("  ✓ broker account:", account!.accountNumberMasked)

  // ─── 12. Positions (mix of equity / option / future / bond) ───────────────
  await db.insert(positions).values([
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "0700.HK",
      displayName: "Tencent Holdings",
      isin: "KYG875721634",
      quantity: "1500",
      costBasisAvg: "320.5",
      costBasisTotal: "480750",
      markPrice: "382.4",
      marketValue: "573600",
      unrealizedPl: "92850",
      unrealizedPlPct: "19.31",
      dayChange: "1234.5",
      dayChangePct: "0.22",
      openedAt: new Date("2023-04-12"),
    },
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "00388.HK",
      displayName: "HKEX",
      quantity: "2000",
      costBasisAvg: "260.4",
      costBasisTotal: "520800",
      markPrice: "295.5",
      marketValue: "591000",
      unrealizedPl: "70200",
      unrealizedPlPct: "13.48",
      dayChange: "-820.0",
      dayChangePct: "-0.14",
      openedAt: new Date("2023-06-22"),
    },
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "AAPL",
      displayName: "Apple Inc",
      isin: "US0378331005",
      quantity: "500",
      costBasisAvg: "152.3",
      costBasisTotal: "76150",
      markPrice: "185.2",
      marketValue: "92600",
      unrealizedPl: "16450",
      unrealizedPlPct: "21.60",
      dayChange: "412.0",
      dayChangePct: "0.45",
      openedAt: new Date("2023-01-10"),
    },
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "MSFT",
      displayName: "Microsoft",
      isin: "US5949181045",
      quantity: "200",
      costBasisAvg: "338.9",
      costBasisTotal: "67780",
      markPrice: "412.1",
      marketValue: "82420",
      unrealizedPl: "14640",
      unrealizedPlPct: "21.60",
      dayChange: "-184.0",
      dayChangePct: "-0.22",
      openedAt: new Date("2023-08-04"),
    },
    {
      accountId: account!.id,
      assetType: "option",
      symbol: "SPY 600C 2026-06-19",
      displayName: "SPY Jun-26 600 Call",
      quantity: "10",
      costBasisAvg: "18.5",
      costBasisTotal: "18500",
      markPrice: "24.5",
      marketValue: "24500",
      unrealizedPl: "6000",
      unrealizedPlPct: "32.43",
      dayChange: "300.0",
      dayChangePct: "1.24",
      optionUnderlying: "SPY",
      optionStrike: "600",
      optionExpiry: "2026-06-19",
      optionType: "C",
      optionDelta: "0.420000",
      optionGamma: "0.012000",
      optionTheta: "-32.5",
      optionVega: "210.4",
      optionIv: "0.165000",
      openedAt: new Date("2025-09-10"),
    },
    {
      accountId: account!.id,
      assetType: "future",
      symbol: "ESM6",
      displayName: "S&P 500 Jun-26 E-mini",
      quantity: "2",
      costBasisAvg: "5680",
      costBasisTotal: "568000",
      markPrice: "5742.5",
      marketValue: "574250",
      unrealizedPl: "6250",
      unrealizedPlPct: "1.10",
      dayChange: "525.0",
      dayChangePct: "0.09",
      futureUnderlying: "ES",
      futureExpiry: "2026-06-19",
      futureInitialMargin: "14000",
      futureDv01: "0",
      openedAt: new Date("2026-04-22"),
    },
    {
      accountId: account!.id,
      assetType: "bond",
      symbol: "US 4.25% 2034-08-15",
      displayName: "US Treasury 4.25% Aug-34",
      quantity: "200000",
      costBasisAvg: "0.985",
      costBasisTotal: "197000",
      markPrice: "1.0050",
      marketValue: "201000",
      unrealizedPl: "4000",
      unrealizedPlPct: "2.03",
      dayChange: "120.0",
      dayChangePct: "0.06",
      bondCouponPct: "4.25",
      bondMaturity: "2034-08-15",
      bondYtm: "4.45",
      bondDuration: "8.20",
      bondFaceValue: "200000",
      openedAt: new Date("2024-09-01"),
    },
    {
      accountId: account!.id,
      assetType: "crypto",
      symbol: "BTC",
      displayName: "Bitcoin",
      quantity: "1.25",
      costBasisAvg: "42100",
      costBasisTotal: "52625",
      markPrice: "61500",
      marketValue: "76875",
      unrealizedPl: "24250",
      unrealizedPlPct: "46.08",
      dayChange: "-825.0",
      dayChangePct: "-1.06",
      openedAt: new Date("2024-01-15"),
    },
  ])
  console.log("  ✓ 8 positions (4 equity + 1 option + 1 future + 1 bond + 1 crypto)")

  // ─── 13. Cash balances ────────────────────────────────────────────────────
  await db.insert(cashBalances).values([
    {
      accountId: account!.id,
      currency: "USD",
      amountLocal: "373357",
      fxRateToUsd: "1.0",
      available: "300000",
      marginUsed: "73357",
    },
    {
      accountId: account!.id,
      currency: "HKD",
      amountLocal: "750000",
      fxRateToUsd: "0.12820",
      available: "750000",
      marginUsed: "0",
    },
    {
      accountId: account!.id,
      currency: "CNY",
      amountLocal: "300000",
      fxRateToUsd: "0.13900",
      available: "300000",
      marginUsed: "0",
    },
  ])
  console.log("  ✓ 3 cash balances (USD / HKD / CNY)")

  // ─── 14. Daily NAV (90 days, slow upward drift with noise) ────────────────
  const navRows: Array<typeof dailyNav.$inferInsert> = []
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  let nav = 2_650_000 // 90 days ago — drifts up to ~2.81M today
  let prevNav = nav
  for (let i = 89; i >= 0; i--) {
    const d = new Date(today)
    d.setDate(d.getDate() - i)
    // Random walk: -0.6% to +0.7% daily, slight upward bias.
    const ret = (Math.random() - 0.46) * 0.013
    nav = nav * (1 + ret)
    const dayPl = nav - prevNav
    const dayPlPct = (dayPl / prevNav) * 100
    const equityShare = 0.49
    const cashShare = 0.18
    navRows.push({
      clientId: client!.id,
      asOf: d.toISOString().slice(0, 10),
      navTotalUsd: nav.toFixed(4),
      navEquities: (nav * equityShare).toFixed(4),
      navOptions: (nav * 0.009).toFixed(4),
      navFutures: (nav * 0.205).toFixed(4),
      navBonds: (nav * 0.073).toFixed(4),
      navCash: (nav * cashShare).toFixed(4),
      navCrypto: (nav * 0.027).toFixed(4),
      dayPl: dayPl.toFixed(4),
      dayPlPct: dayPlPct.toFixed(4),
      betaToSpy: "0.83",
    })
    prevNav = nav
  }
  await db.insert(dailyNav).values(navRows)
  console.log(`  ✓ ${navRows.length} days of daily_nav (random walk)`)

  // ─── 15. Risk metrics (latest snapshot) ───────────────────────────────────
  await db.insert(riskMetrics).values({
    clientId: client!.id,
    asOf: today.toISOString().slice(0, 10),
    beta: "0.83",
    sharpe: "1.42",
    sortino: "2.10",
    maxDrawdown: "-12.40",
    volAnnualized: "14.20",
  })
  console.log("  ✓ risk_metrics (latest)")

  // ─── 16. Sample documents (M4 fixtures) ───────────────────────────────────
  // file_url stores R2 object keys. With R2 not configured in dev, list/detail
  // endpoints work fine; download presign will 503 until R2_* are set.
  const fakeKey = (id: string, ext: string) => `clients/${client!.id}/${id}.${ext}`
  const docRows: Array<typeof documents.$inferInsert> = [
    {
      clientId: client!.id,
      category: "statement",
      title: "Q1 2026 IBKR Statement",
      displayCode: "STMT-2026-Q1",
      sourceLabel: "Interactive Brokers",
      sourceParty: "Interactive Brokers LLC",
      description: "Quarterly statement covering 2026-01-01 to 2026-03-31.",
      fileUrl: fakeKey("STMT-Q1-2026", "pdf"),
      fileFormat: "pdf",
      fileSizeBytes: 184_320,
      pages: 12,
      sha256: "0".repeat(64),
      issuedAt: new Date("2026-04-05"),
      deliveredAt: new Date("2026-04-05"),
      tags: ["quarterly", "broker"],
      uploadedByUserId: user!.id,
      status: "active",
    },
    {
      clientId: client!.id,
      category: "tax",
      title: "1042-S — 2025 Withholding",
      displayCode: "TAX-1042S-2025",
      sourceLabel: "Interactive Brokers",
      sourceParty: "Interactive Brokers LLC",
      description: "Annual withholding statement for non-US persons.",
      fileUrl: fakeKey("TAX-1042S-2025", "pdf"),
      fileFormat: "pdf",
      fileSizeBytes: 64_512,
      pages: 2,
      sha256: "1".repeat(64),
      issuedAt: new Date("2026-02-28"),
      deliveredAt: new Date("2026-02-28"),
      tags: ["tax", "withholding"],
      taxYear: 2025,
      uploadedByUserId: user!.id,
      status: "active",
    },
    {
      clientId: client!.id,
      category: "engagement",
      title: "Master Engagement Letter v3.2",
      displayCode: "ENG-MASTER-2024",
      sourceLabel: "Shion Quant",
      sourceParty: "Shion Quant Limited",
      description:
        "Retainer engagement letter governing the advisory relationship. Renewed annually.",
      fileUrl: fakeKey("ENG-MASTER-V3.2", "pdf"),
      fileFormat: "pdf",
      fileSizeBytes: 287_103,
      pages: 18,
      sha256: "2".repeat(64),
      issuedAt: new Date("2024-09-15"),
      deliveredAt: new Date("2024-09-15"),
      retentionUntil: "2031-09-15",
      tags: ["engagement", "annual"],
      uploadedByUserId: user!.id,
      status: "active",
    },
    {
      clientId: client!.id,
      category: "compliance",
      title: "FATCA W-8BEN — Renewal Required",
      displayCode: "FATCA-W8BEN-2026",
      sourceLabel: "Shion Quant Compliance",
      sourceParty: "Shion Quant Limited",
      description:
        "W-8BEN renewal — please review and sign before the 30-day deadline.",
      fileUrl: fakeKey("FATCA-W8BEN-2026", "pdf"),
      fileFormat: "pdf",
      fileSizeBytes: 41_472,
      pages: 4,
      sha256: "3".repeat(64),
      issuedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      deliveredAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      tags: ["compliance", "tax"],
      uploadedByUserId: user!.id,
      status: "pending_signature",
      pendingAction: "review_and_sign",
      pendingDueAt: new Date(Date.now() + 25 * 24 * 60 * 60 * 1000),
    },
  ]
  await db.insert(documents).values(docRows)
  console.log("  ✓ 4 documents (1 pending signature: FATCA-W8BEN-2026)")

  // ─── 17. Schedule events (M5) ────────────────────────────────────────────
  const day = (offsetDays: number, hour = 0, minute = 0): Date => {
    const d = new Date(today)
    d.setUTCDate(d.getUTCDate() + offsetDays)
    d.setUTCHours(hour, minute, 0, 0)
    return d
  }

  // Insert events one by one so we can attach reminders to specific ids.
  const eventInserts: Array<{
    label: string
    row: typeof events.$inferInsert
    reminders?: Array<{
      channel: "email" | "push" | "sms"
      leadMinutes: number
    }>
  }> = [
    {
      label: "option expiry",
      row: {
        clientId: client!.id,
        eventType: "option_expiry",
        source: "broker",
        title: "SPY 600C 2026-06-19 — Option Expiry",
        description:
          "Long call, 10 contracts. Currently OTM by ~2.6%. Roll, close, or let expire.",
        ticker: "SPY",
        startsAt: day(40, 20, 0), // 4 PM ET ~ 20:00 UTC
        endsAt: day(40, 21, 0),
        isAllDay: false,
        isCritical: true,
      },
      reminders: [
        { channel: "email", leadMinutes: 60 * 24 * 7 }, // 7 days
        { channel: "email", leadMinutes: 60 * 24 }, // 1 day
      ],
    },
    {
      label: "bond coupon",
      row: {
        clientId: client!.id,
        eventType: "bond_coupon",
        source: "broker",
        title: "US Treasury 4.25% — Coupon Payment",
        description:
          "Semi-annual coupon on US 4.25% 2034-08-15. Expected payment ~$4,250.",
        ticker: "US-2034-08",
        startsAt: day(80),
        isAllDay: true,
        isCritical: false,
      },
    },
    {
      label: "earnings",
      row: {
        clientId: client!.id,
        eventType: "earnings",
        source: "broker",
        title: "AAPL Q3 2026 Earnings",
        description:
          "Apple Inc. fiscal Q3 earnings. Holding 500 shares. Consensus EPS: $1.62.",
        ticker: "AAPL",
        startsAt: day(55, 20, 30),
        endsAt: day(55, 21, 30),
        isAllDay: false,
      },
      reminders: [{ channel: "email", leadMinutes: 60 * 24 }],
    },
    {
      label: "advisor call",
      row: {
        clientId: client!.id,
        eventType: "advisor_call",
        source: "advisor",
        title: "Quarterly Review with KT",
        description: "Q2 portfolio review. 60 min, video.",
        startsAt: day(8, 6, 0), // 14:00 HKT ≈ 06:00 UTC
        endsAt: day(8, 7, 0),
        isAllDay: false,
        displayTz: "Asia/Hong_Kong",
        isCritical: true,
        metadata: { location: "Zoom (link in confirmation email)" },
      },
      reminders: [
        { channel: "email", leadMinutes: 60 * 24 },
        { channel: "push", leadMinutes: 30 },
      ],
    },
    {
      label: "compliance renewal",
      row: {
        clientId: client!.id,
        eventType: "compliance_renewal",
        source: "advisor",
        title: "FATCA W-8BEN Renewal Due",
        description:
          "Required to maintain reduced US withholding rates. Forms in Documents.",
        startsAt: day(25),
        isAllDay: true,
        isCritical: true,
      },
      reminders: [
        { channel: "email", leadMinutes: 60 * 24 * 7 },
        { channel: "email", leadMinutes: 60 * 24 * 2 },
      ],
    },
    {
      label: "macro",
      row: {
        clientId: client!.id,
        eventType: "macro",
        source: "macro",
        title: "FOMC Rate Decision",
        description: "Federal Reserve interest rate announcement.",
        startsAt: day(42, 18, 0), // 14:00 ET
        endsAt: day(42, 18, 30),
        isAllDay: false,
        isCritical: false,
      },
    },
    {
      label: "report delivery (recurring)",
      row: {
        clientId: client!.id,
        eventType: "report_delivery",
        source: "system",
        title: "Monthly Performance Report",
        description: "Auto-generated end-of-month performance brief.",
        startsAt: day(30 - today.getUTCDate() + 1), // ~1st of next month
        isAllDay: true,
        rrule: "FREQ=MONTHLY;BYMONTHDAY=1",
      },
    },
    {
      label: "personal vacation",
      row: {
        clientId: client!.id,
        eventType: "personal",
        source: "personal",
        title: "Family Vacation — Tokyo",
        description: "Limited availability for advisor calls.",
        startsAt: day(95),
        endsAt: day(105),
        isAllDay: true,
        displayTz: "Asia/Hong_Kong",
      },
    },
  ]

  for (const e of eventInserts) {
    const [created] = await db.insert(events).values(e.row).returning({ id: events.id })
    if (e.reminders && created) {
      await db.insert(eventReminders).values(
        e.reminders.map((r) => ({
          eventId: created.id,
          channel: r.channel,
          leadMinutes: r.leadMinutes,
        })),
      )
    }
  }
  console.log(`  ✓ ${eventInserts.length} schedule events (with reminders)`)

  // ─── 18. ICS subscription ─────────────────────────────────────────────────
  const icsToken = randomBytes(24).toString("base64url")
  await db.insert(calendarSubscriptions).values({
    clientId: client!.id,
    icsToken,
  })
  const icsUrl = `http://localhost:3001/api/v1/schedules/ics/${icsToken}`
  console.log(`  ✓ ICS subscription token created`)

  // ─── 19. Reports library (M6 fixtures) ────────────────────────────────────
  // Mix of firm-wide (clientId=null) and client-specific reports.
  await db.insert(reports).values([
    {
      reportType: "macro",
      title: "Macro Brief — Q2 2026",
      subtitle: "Rates, FX, and the China credit pulse",
      bodyFormat: "md",
      bodyMd:
        "# Macro Brief — Q2 2026\n\n" +
        "## Headlines\n" +
        "- Fed expected to hold through summer; first cut priced for September.\n" +
        "- HKD remains pegged at the strong-side convertibility band.\n" +
        "- Onshore CNY pressure easing as PBoC steps back from intervention.\n\n" +
        "## What this means for HK family-office allocations\n" +
        "Real yields in USD remain attractive vs HKD-denominated alternatives...\n",
      authorAdvisorId: advisor!.id,
      clientId: null, // firm-wide
      pages: 8,
      chartsCount: 6,
      tablesCount: 2,
      readTimeMin: 12,
      publishedAt: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000),
      isDraft: false,
    },
    {
      reportType: "performance",
      title: "March 2026 Performance Brief",
      subtitle: "Monthly P&L, attribution, and forward look",
      bodyFormat: "md",
      bodyMd:
        "# March 2026 Performance\n\n" +
        "Net return: **+2.4%** (vs SPY +1.9%, HSI +0.6%).\n\n" +
        "## Attribution\n" +
        "- Tencent: +1.1% contribution; HKEX: +0.6%; SPY call: +0.4%; bonds flat.\n\n" +
        "## Risk profile\n" +
        "Beta to SPY: 0.83. Vol annualized: 14.2%. Sharpe (3-yr): 1.42.\n",
      authorAdvisorId: advisor!.id,
      clientId: client!.id, // client-specific
      pages: 4,
      chartsCount: 3,
      tablesCount: 1,
      readTimeMin: 6,
      publishedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      isDraft: false,
    },
    {
      reportType: "risk_attribution",
      title: "Risk Attribution — March 2026",
      subtitle: "Factor decomposition + scenario stress",
      bodyFormat: "md",
      bodyMd:
        "# Risk Attribution — March 2026\n\n" +
        "## Factor exposures\n" +
        "| Factor | Exposure | Contribution to vol |\n" +
        "|--------|----------|---------------------|\n" +
        "| Equity beta (HK + US) | 0.83 | 9.6% |\n" +
        "| Duration (UST 10y eq.) | 1.6 yr | 2.4% |\n" +
        "| FX (HKD/USD) | 0.04 | 0.1% |\n" +
        "| Idiosyncratic | — | 2.1% |\n",
      authorAdvisorId: advisor!.id,
      clientId: client!.id,
      pages: 6,
      chartsCount: 4,
      tablesCount: 3,
      readTimeMin: 10,
      publishedAt: new Date(Date.now() - 32 * 24 * 60 * 60 * 1000),
      isDraft: false,
    },
    {
      reportType: "strategy_memo",
      title: "Strategy Memo — Treasury Ladder Refresh",
      subtitle: "Reset the 1-5 year ladder with current curve shape",
      bodyFormat: "md",
      bodyMd:
        "# Treasury Ladder Refresh\n\n" +
        "Current US 4.25% Aug-34 holding has DV01 of ~$160. Curve has flattened ~30bp since entry; we recommend rolling half the position to a 2-year and keeping the rest as the long-duration anchor.\n\n" +
        "## Proposed action\n" +
        "Reduce US 4.25% Aug-34 from $200k face to $100k face. Buy $100k face of 2-year. Net cash: ~+$1,200.\n",
      authorAdvisorId: advisor!.id,
      clientId: client!.id,
      pages: 3,
      chartsCount: 1,
      tablesCount: 2,
      readTimeMin: 5,
      publishedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      isDraft: false,
    },
    {
      reportType: "macro",
      title: "Macro Watch — Weekly (May 5)",
      subtitle: "Three things that matter, ranked",
      bodyFormat: "md",
      bodyMd:
        "# Macro Watch — May 5\n\n" +
        "1. **FOMC** — June 17. Markets pricing 0% odds of a hike, 18% of a cut. We hold base case: hold.\n" +
        "2. **PBoC** — RRR cut likely Q3. Watch USD/CNY 7.30 as the pain threshold.\n" +
        "3. **Hong Kong** — Aggregate balance trending down; HKMA may need to support.\n",
      authorAdvisorId: advisor!.id,
      clientId: null,
      pages: 2,
      readTimeMin: 3,
      publishedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      isDraft: false,
    },
  ])
  console.log("  ✓ 5 reports (3 firm-wide macro, 2 client-specific perf+risk)")

  // ─── 20. Report subscriptions (default channels) ─────────────────────────
  await db.insert(reportSubscriptions).values([
    { clientId: client!.id, reportType: "performance", channels: ["email", "portal"] },
    { clientId: client!.id, reportType: "risk_attribution", channels: ["email"] },
    { clientId: client!.id, reportType: "macro", channels: ["portal"] },
  ])
  console.log("  ✓ report subscriptions (3 types)")

  // ─── 21. Outstanding custom research request ─────────────────────────────
  await db.insert(customResearchRequests).values({
    clientId: client!.id,
    userId: user!.id,
    projectType: "taxopt",
    workingTitle: "HK→US dividend tax optimization",
    question:
      "Looking at the AAPL/MSFT positions held in the IBKR account, can we reduce US withholding via portfolio holding company structure? Want a deep-dive on viability + ongoing compliance burden vs current 30% withholding.",
    linkedTickers: ["AAPL", "MSFT"],
    capitalAtStake: "175020",
    timelinePref: "standard",
    status: "submitted",
  })
  console.log("  ✓ 1 outstanding custom research request (taxopt)")

  // ─── 22. Message thread (M7) ──────────────────────────────────────────────
  // One in-flight thread between Mr. Chen and KT, four messages, last one
  // is from the advisor — so unread_count_client = 1.
  const threadStart = new Date(Date.now() - 6 * 24 * 60 * 60_000)
  const [thread] = await db
    .insert(messageThreads)
    .values({
      clientId: client!.id,
      advisorId: advisor!.id,
      subject: "Q1 results & Tencent rebalance",
      lastMessageAt: new Date(Date.now() - 18 * 60 * 60_000), // ~yesterday
      unreadCountClient: 1,
      unreadCountAdvisor: 0,
      createdAt: threadStart,
    })
    .returning()

  await db.insert(messages).values([
    {
      threadId: thread!.id,
      senderUserId: user!.id,
      senderAdvisorId: null,
      body:
        "你好 KT — Q1 表現我看了一下,Tencent 那邊已經漲了快 20%。" +
        "你之前說過 25% 是個 trim 的 trigger,我們現在是不是該開始準備?",
      urgency: "routine",
      sentAt: new Date(threadStart.getTime() + 0),
      readAt: new Date(threadStart.getTime() + 30 * 60_000),
    },
    {
      threadId: thread!.id,
      senderUserId: null,
      senderAdvisorId: advisor!.id,
      body:
        "Hi Mr. Chen — yes, I saw the +19% on 0700.HK. " +
        "Trim trigger is 25% from cost; we're at 19.3% now. " +
        "I'll prepare a memo with three rebalance options (full trim / partial / let-it-run) for next week's review.",
      urgency: "routine",
      sentAt: new Date(threadStart.getTime() + 2 * 60 * 60_000),
      readAt: new Date(threadStart.getTime() + 3 * 60 * 60_000),
    },
    {
      threadId: thread!.id,
      senderUserId: user!.id,
      senderAdvisorId: null,
      body:
        "好,順便也想看一下 if we go to partial trim,稅務上怎麼處理最有效?HK 沒有 capital gains tax 但 IBKR 那邊?",
      urgency: "routine",
      sentAt: new Date(threadStart.getTime() + 5 * 24 * 60 * 60_000), // ~5 days later
      readAt: new Date(threadStart.getTime() + 5 * 24 * 60 * 60_000 + 4 * 60 * 60_000),
    },
    {
      threadId: thread!.id,
      senderUserId: null,
      senderAdvisorId: advisor!.id,
      body:
        "Good question. Since the position is in a US-cleared IBKR account, " +
        "no withholding on capital gains for non-US persons (you have a W-8BEN on file). " +
        "I'll fold the tax angle into the memo. Drafting now — should land in your portal by EOD Friday.",
      urgency: "routine",
      sentAt: new Date(Date.now() - 18 * 60 * 60_000),
      readAt: null, // unread on the client side
    },
  ])
  console.log("  ✓ 1 message thread with 4 messages (1 unread from KT)")

  // ─── 23. Confirmed upcoming meeting (M7) ──────────────────────────────────
  // Schedule 8 days out at 14:00 HKT (06:00 UTC) — matches the Q2 review event
  // we already inserted earlier, so the calendar feed is internally consistent.
  const meetingAt = (() => {
    const d = new Date(today)
    d.setUTCDate(d.getUTCDate() + 8)
    d.setUTCHours(6, 0, 0, 0)
    return d
  })()

  // Link to the advisor_call event we already seeded so the meeting page
  // and the calendar feed point at the same row.
  const reviewEvent = await db.query.events.findFirst({
    where: and(
      eq(events.clientId, client!.id),
      eq(events.eventType, "advisor_call"),
    ),
  })

  await db.insert(meetingBookings).values({
    clientId: client!.id,
    advisorId: advisor!.id,
    scheduledAt: meetingAt,
    durationMin: 60,
    meetingType: "video",
    agenda:
      "Q2 portfolio review — Tencent rebalance options, treasury ladder refresh, " +
      "FATCA renewal, and tax-opt deep-dive scope.",
    meetingUrl: "https://meet.shion.test/kt-chen-q2-2026",
    status: "confirmed",
    relatedEventId: reviewEvent?.id ?? null,
  })
  console.log(
    `  ✓ confirmed meeting booked for ${meetingAt.toISOString()} (60min, video)`,
  )

  // ─── Final summary ────────────────────────────────────────────────────────
  console.log("")
  console.log("─".repeat(64))
  console.log("Seed complete.")
  console.log("")
  console.log("  Login:    " + TEST_EMAIL)
  console.log("  Password: " + TEST_PASSWORD)
  console.log("")
  console.log("  TOTP secret (base32): " + totpSecret)
  console.log("  TOTP otpauth URI: " + otpauthUri)
  console.log("    → Paste into a QR generator, or import URI directly into")
  console.log("      1Password / Authy / Google Authenticator.")
  console.log("")
  console.log("  Recovery codes (single-use, displayed ONCE):")
  for (const code of codes) console.log("    " + code)
  console.log("─".repeat(64))
  console.log("")
  console.log("Test the auth flow:")
  console.log("  curl -i -c /tmp/cookies -b /tmp/cookies \\")
  console.log("    -H 'Content-Type: application/json' \\")
  console.log("    -H 'Origin: http://localhost:5173' \\")
  console.log("    -X POST http://localhost:3001/api/v1/auth/login \\")
  console.log(`    -d '{"email":"${TEST_EMAIL}","password":"${TEST_PASSWORD}"}'`)
  console.log("")
  console.log("  # → 200 with mfaRequired: true and a challengeToken")
  console.log("  # Then exchange the challenge for a session:")
  console.log("  curl -i -c /tmp/cookies -b /tmp/cookies \\")
  console.log("    -H 'Content-Type: application/json' \\")
  console.log("    -H 'Origin: http://localhost:5173' \\")
  console.log("    -X POST http://localhost:3001/api/v1/auth/mfa \\")
  console.log("    -d '{\"challengeToken\":\"<from /login>\",\"code\":\"<6-digit TOTP>\"}'")
  console.log("")
  console.log("  # Once MFA-verified, fetch the (decrypted) profile:")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/account/profile")
  console.log("")
  console.log("  # M3 portfolio reads:")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/portfolio/overview")
  console.log("  curl -b /tmp/cookies 'http://localhost:3001/api/v1/portfolio/positions?assetType=equity'")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/portfolio/cash")
  console.log("  curl -b /tmp/cookies 'http://localhost:3001/api/v1/portfolio/nav?range=3m'")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/portfolio/risk")
  console.log("")
  console.log("  # M4 documents:")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/documents")
  console.log("  curl -b /tmp/cookies 'http://localhost:3001/api/v1/documents?status=pending_signature'")
  console.log("  # (download URL endpoint requires R2 configured)")
  console.log("")
  console.log("  # M5 schedules:")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/schedules/events")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/schedules/settings")
  console.log("")
  console.log("  # ICS feed (no auth — token-gated, subscribe in any calendar app):")
  console.log("  " + icsUrl)
  console.log("")
  console.log("  # M6 reports:")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/reports")
  console.log("  curl -b /tmp/cookies 'http://localhost:3001/api/v1/reports?scope=mine&type=performance'")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/reports/subscriptions")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/reports/custom-requests")
  console.log("")
  console.log("  # M7 communication:")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/communication/threads")
  console.log("  curl -b /tmp/cookies http://localhost:3001/api/v1/communication/advisor/availability")
  console.log("")
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Seed failed:", err)
    process.exit(1)
  })
