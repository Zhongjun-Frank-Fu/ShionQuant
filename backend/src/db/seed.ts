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
  sessions,
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
    // FK ON DELETE CASCADE handles auth_factors, recovery_codes, login_events
    // (set null), and most client-child rows. But several tables intentionally
    // use NO ACTION / RESTRICT to preserve audit / firm history, and we have
    // to clear those before the clients row can go:
    //   - reports.client_id           (NO ACTION — firm history preserved)
    //   - documents.client_id         (RESTRICT — regulatory)
    //   - sessions.client_id          (NO ACTION — live logins from CLI tests)
    const ownedClients = await db
      .select({ id: clients.id })
      .from(clients)
      .where(eq(clients.userId, existingUser.id))
    const ownedClientIds = ownedClients.map((c) => c.id)
    // sessions reference BOTH client_id and user_id; deleting by user_id is
    // safer (covers also sessions issued before this client existed).
    await db.delete(sessions).where(eq(sessions.userId, existingUser.id))
    if (ownedClientIds.length > 0) {
      await db.delete(reports).where(inArray(reports.clientId, ownedClientIds))
      await db.delete(documents).where(inArray(documents.clientId, ownedClientIds))
    }
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

  // ─── 12. Positions (HK + US equities, options, futures, bonds, crypto) ───
  // Mix mirrors the Portal home page demo: 2 HK + 5 US large-cap equities,
  // 3 options strategies, 3 futures contracts (ES/NQ/ZN), 2 US Treasuries,
  // 2 crypto holdings. Numbers are quoted in USD (we don't track per-position
  // currency in the schema yet; HK names use HKD-quoted prices but USD-equiv
  // market_value to keep the allocation math tidy).
  await db.insert(positions).values([
    // ─── HK equities ────────────────────────────────────────────────────────
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
    // ─── US equities ────────────────────────────────────────────────────────
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "NVDA",
      displayName: "NVIDIA Corp",
      isin: "US67066G1040",
      quantity: "200",
      costBasisAvg: "487.30",
      costBasisTotal: "97460",
      markPrice: "642.18",
      marketValue: "128436",
      unrealizedPl: "30976",
      unrealizedPlPct: "31.78",
      dayChange: "1824.0",
      dayChangePct: "1.42",
      openedAt: new Date("2023-11-08"),
    },
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "AAPL",
      displayName: "Apple Inc",
      isin: "US0378331005",
      quantity: "800",
      costBasisAvg: "178.50",
      costBasisTotal: "142800",
      markPrice: "215.62",
      marketValue: "172496",
      unrealizedPl: "29696",
      unrealizedPlPct: "20.80",
      dayChange: "656.0",
      dayChangePct: "0.38",
      openedAt: new Date("2023-01-10"),
    },
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "MSFT",
      displayName: "Microsoft",
      isin: "US5949181045",
      quantity: "300",
      costBasisAvg: "372.10",
      costBasisTotal: "111630",
      markPrice: "428.85",
      marketValue: "128655",
      unrealizedPl: "17025",
      unrealizedPlPct: "15.25",
      dayChange: "798.0",
      dayChangePct: "0.62",
      openedAt: new Date("2023-08-04"),
    },
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "TSM",
      displayName: "Taiwan Semi ADR",
      isin: "US8740391003",
      quantity: "400",
      costBasisAvg: "142.80",
      costBasisTotal: "57120",
      markPrice: "168.95",
      marketValue: "67580",
      unrealizedPl: "10460",
      unrealizedPlPct: "18.31",
      dayChange: "-575.0",
      dayChangePct: "-0.85",
      openedAt: new Date("2023-09-22"),
    },
    {
      accountId: account!.id,
      assetType: "equity",
      symbol: "BRK.B",
      displayName: "Berkshire Hathaway B",
      isin: "US0846707026",
      quantity: "100",
      costBasisAvg: "392.40",
      costBasisTotal: "39240",
      markPrice: "458.20",
      marketValue: "45820",
      unrealizedPl: "6580",
      unrealizedPlPct: "16.77",
      dayChange: "82.5",
      dayChangePct: "0.18",
      openedAt: new Date("2024-01-15"),
    },
    // ─── Options (3 strategies) ────────────────────────────────────────────
    {
      accountId: account!.id,
      assetType: "option",
      symbol: "AAPL 230C 2026-05-16",
      displayName: "AAPL May-26 230 Call (covered)",
      quantity: "15",
      side: "short", // covered call written against the AAPL stock position
      costBasisAvg: "4.20",
      costBasisTotal: "6300",
      markPrice: "2.85",
      marketValue: "-4275", // short premium liability
      unrealizedPl: "2025",
      unrealizedPlPct: "32.14",
      dayChange: "120.0",
      dayChangePct: "1.24",
      optionUnderlying: "AAPL",
      optionStrike: "230",
      optionExpiry: "2026-05-16",
      optionType: "C",
      optionDelta: "-0.380000",
      optionGamma: "-0.014000",
      optionTheta: "180.5",
      optionVega: "-185.2",
      optionIv: "0.215000",
      openedAt: new Date("2026-03-04"),
    },
    {
      accountId: account!.id,
      assetType: "option",
      symbol: "SPY 530P 2026-06-20",
      displayName: "SPY Jun-26 530 Put (protective)",
      quantity: "8",
      side: "long",
      costBasisAvg: "9.40",
      costBasisTotal: "7520",
      markPrice: "11.20",
      marketValue: "8960",
      unrealizedPl: "1440",
      unrealizedPlPct: "19.15",
      dayChange: "60.0",
      dayChangePct: "0.68",
      optionUnderlying: "SPY",
      optionStrike: "530",
      optionExpiry: "2026-06-20",
      optionType: "P",
      optionDelta: "-0.310000",
      optionGamma: "0.011000",
      optionTheta: "-78.5",
      optionVega: "320.4",
      optionIv: "0.182000",
      openedAt: new Date("2026-02-12"),
    },
    {
      accountId: account!.id,
      assetType: "option",
      symbol: "NVDA 580P 2026-05-16",
      displayName: "NVDA May-26 580 Put (cash-secured)",
      quantity: "3",
      side: "short",
      costBasisAvg: "11.50",
      costBasisTotal: "3450",
      markPrice: "4.20",
      marketValue: "-1260",
      unrealizedPl: "2190",
      unrealizedPlPct: "63.48",
      dayChange: "-45.0",
      dayChangePct: "-3.45",
      optionUnderlying: "NVDA",
      optionStrike: "580",
      optionExpiry: "2026-05-16",
      optionType: "P",
      optionDelta: "0.110000",
      optionGamma: "-0.008000",
      optionTheta: "92.5",
      optionVega: "-148.7",
      optionIv: "0.345000",
      openedAt: new Date("2026-04-01"),
    },
    // ─── Futures (3 contracts: ES short / NQ long / ZN long) ────────────────
    {
      accountId: account!.id,
      assetType: "future",
      symbol: "ESU6",
      displayName: "S&P 500 E-mini · Sep 2026",
      quantity: "1",
      side: "short",
      costBasisAvg: "5510",
      costBasisTotal: "275500",
      markPrice: "5435",
      marketValue: "-271750", // notional, signed by side
      unrealizedPl: "3750",
      unrealizedPlPct: "1.36",
      dayChange: "-200.0",
      dayChangePct: "-0.07",
      futureUnderlying: "ES",
      futureExpiry: "2026-09-18",
      futureInitialMargin: "14000",
      futureDv01: "0",
      openedAt: new Date("2026-04-22"),
    },
    {
      accountId: account!.id,
      assetType: "future",
      symbol: "NQM6",
      displayName: "Nasdaq 100 E-mini · Jun 2026",
      quantity: "1",
      side: "long",
      costBasisAvg: "18800",
      costBasisTotal: "376000",
      markPrice: "19000",
      marketValue: "380000",
      unrealizedPl: "4000",
      unrealizedPlPct: "1.06",
      dayChange: "240.0",
      dayChangePct: "0.06",
      futureUnderlying: "NQ",
      futureExpiry: "2026-06-19",
      futureInitialMargin: "21000",
      futureDv01: "0",
      openedAt: new Date("2026-03-18"),
    },
    {
      accountId: account!.id,
      assetType: "future",
      symbol: "ZNU6",
      displayName: "10Y T-Note · Sep 2026",
      quantity: "4",
      side: "long",
      costBasisAvg: "108.3125",
      costBasisTotal: "433250",
      markPrice: "108.6875",
      marketValue: "434750",
      unrealizedPl: "1500",
      unrealizedPlPct: "0.35",
      dayChange: "62.5",
      dayChangePct: "0.01",
      futureUnderlying: "ZN",
      futureExpiry: "2026-09-19",
      futureInitialMargin: "1825", // per contract
      futureDv01: "70", // per contract; 4 ct → DV01 ≈ +$280
      openedAt: new Date("2026-04-08"),
    },
    // ─── US Treasuries (2 holdings) ─────────────────────────────────────────
    {
      accountId: account!.id,
      assetType: "bond",
      symbol: "US 4.25% 2034-05-15",
      displayName: "US Treasury 4.25% May-34 (10Y)",
      quantity: "200000",
      costBasisAvg: "0.965",
      costBasisTotal: "193000",
      markPrice: "0.976",
      marketValue: "195200",
      unrealizedPl: "2200",
      unrealizedPlPct: "1.14",
      dayChange: "120.0",
      dayChangePct: "0.06",
      bondCouponPct: "4.25",
      bondMaturity: "2034-05-15",
      bondYtm: "4.42",
      bondDuration: "7.80",
      bondFaceValue: "200000",
      openedAt: new Date("2024-09-01"),
    },
    {
      accountId: account!.id,
      assetType: "bond",
      symbol: "US 4.85% 2026-04-30",
      displayName: "US Treasury 4.85% Apr-26 (2Y)",
      quantity: "150000",
      costBasisAvg: "0.972",
      costBasisTotal: "145800",
      markPrice: "0.97653",
      marketValue: "146479",
      unrealizedPl: "679",
      unrealizedPlPct: "0.47",
      dayChange: "30.0",
      dayChangePct: "0.02",
      bondCouponPct: "4.85",
      bondMaturity: "2026-04-30",
      bondYtm: "4.95",
      bondDuration: "0.90",
      bondFaceValue: "150000",
      openedAt: new Date("2025-04-30"),
    },
    // ─── Digital assets (2 holdings) ────────────────────────────────────────
    {
      accountId: account!.id,
      assetType: "crypto",
      symbol: "BTC",
      displayName: "Bitcoin",
      quantity: "1.65",
      costBasisAvg: "48500",
      costBasisTotal: "80025",
      markPrice: "96200",
      marketValue: "158730",
      unrealizedPl: "78705",
      unrealizedPlPct: "98.35",
      dayChange: "-1680.0",
      dayChangePct: "-1.05",
      openedAt: new Date("2024-01-15"),
    },
    {
      accountId: account!.id,
      assetType: "crypto",
      symbol: "ETH",
      displayName: "Ethereum",
      quantity: "5.80",
      costBasisAvg: "2420",
      costBasisTotal: "14036",
      markPrice: "3070",
      marketValue: "17806",
      unrealizedPl: "3770",
      unrealizedPlPct: "26.86",
      dayChange: "-58.0",
      dayChangePct: "-0.32",
      openedAt: new Date("2024-03-21"),
    },
  ])
  console.log(
    "  ✓ 17 positions (7 equity + 3 option + 3 future + 2 bond + 2 crypto)",
  )

  // ─── 13. Cash balances ────────────────────────────────────────────────────
  // USD margin_used reflects the futures-margin reservation; the
  // /portfolio/cash endpoint sums it across currencies for the
  // "Margin Used" KPI on the Portal home page.
  await db.insert(cashBalances).values([
    {
      accountId: account!.id,
      currency: "USD",
      amountLocal: "373357",
      fxRateToUsd: "1.0",
      available: "259464", // 373,357 − 113,893 margin
      marginUsed: "113893",
    },
    {
      accountId: account!.id,
      currency: "HKD",
      amountLocal: "768300",
      fxRateToUsd: "0.12820",
      available: "768300",
      marginUsed: "0",
    },
    {
      accountId: account!.id,
      currency: "CNY",
      amountLocal: "295200",
      fxRateToUsd: "0.13780",
      available: "295200",
      marginUsed: "0",
    },
  ])
  console.log("  ✓ 3 cash balances (USD / HKD / CNY)")

  // ─── 14. Daily NAV (≈400 days; supports YTD / 1Y / Inception returns) ────
  // Long enough that the /overview endpoint can compute meaningful YTD,
  // trailing-1Y, and since-inception return %s. Uses a deterministic-feeling
  // random walk anchored to the current ~$2.85M total portfolio NAV.
  const navRows: Array<typeof dailyNav.$inferInsert> = []
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const HISTORY_DAYS = 400
  let nav = 1_932_000 // ≈400 days ago; drifts up to ~$2.85M (~+47% inception)
  let prevNav = nav
  for (let i = HISTORY_DAYS - 1; i >= 0; i--) {
    const d = new Date(today)
    d.setDate(d.getDate() - i)
    // Random walk: -0.6% to +0.7% daily, slight upward bias.
    const ret = (Math.random() - 0.44) * 0.013
    nav = nav * (1 + ret)
    const dayPl = nav - prevNav
    const dayPlPct = (dayPl / prevNav) * 100
    navRows.push({
      clientId: client!.id,
      asOf: d.toISOString().slice(0, 10),
      navTotalUsd: nav.toFixed(4),
      navEquities: (nav * 0.533).toFixed(4),
      navOptions: (nav * 0.012).toFixed(4),
      navFutures: (nav * 0.040).toFixed(4),
      navBonds: (nav * 0.120).toFixed(4),
      navCash: (nav * 0.180).toFixed(4),
      navCrypto: (nav * 0.062).toFixed(4),
      dayPl: dayPl.toFixed(4),
      dayPlPct: dayPlPct.toFixed(4),
      betaToSpy: "0.82",
    })
    prevNav = nav
  }
  await db.insert(dailyNav).values(navRows)
  console.log(`  ✓ ${navRows.length} days of daily_nav (random walk)`)

  // ─── 15. Risk metrics (latest snapshot) ───────────────────────────────────
  await db.insert(riskMetrics).values({
    clientId: client!.id,
    asOf: today.toISOString().slice(0, 10),
    beta: "0.82",
    sharpe: "1.74",
    sortino: "2.41",
    maxDrawdown: "-8.40",
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
        metadata: {
          sections: [
            {
              kind: "prose",
              title: { en: "Position context", zh: "仓位背景" },
              eyebrow: { en: "Long call · 10 contracts", zh: "看涨期权 · 10 张" },
              body: {
                en: "The 600-strike SPY call from September has decayed roughly 50% from entry as the underlying drifted sideways through Q2. Currently OTM by ~2.6%; with three weeks of theta-burn ahead and IV likely to compress into summer doldrums, doing nothing trends to zero.",
                zh: "9 月开仓的 600 行权价 SPY 看涨已较成本损耗约 50%，标的二季度横盘。当前虚值约 2.6%；后续三周 Theta 持续消耗 + 夏季 IV 大概率走低，被动持有将逼近归零。",
              },
            },
            {
              kind: "table",
              title: { en: "Affected position", zh: "关联仓位" },
              columns: [
                { key: "symbol", label: { en: "Symbol", zh: "代码" } },
                { key: "qty", label: { en: "Qty", zh: "数量" }, align: "right" },
                { key: "cost", label: { en: "Avg cost", zh: "成本" }, align: "right" },
                { key: "mark", label: { en: "Mark", zh: "现价" }, align: "right" },
                { key: "pl", label: { en: "P/L", zh: "盈亏" }, align: "right", tone: "sign" },
              ],
              rows: [
                {
                  symbol: "SPY 600C 2026-06-19",
                  qty: "10",
                  cost: "$24.50",
                  mark: "$12.10",
                  pl: "−$12,400",
                },
              ],
            },
            {
              kind: "actions",
              title: { en: "Three options", zh: "三种选择" },
              eyebrow: { en: "Decide before 19 Jun · 4 PM ET", zh: "请于 6/19 美东 16:00 前决定" },
              items: [
                {
                  priority: "high",
                  action: { en: "Roll to Aug 590C", zh: "滚动至 8 月 590C" },
                  rationale: {
                    en: "Drop 10 strikes for ~$3.20 net debit; preserves ~70% of original delta exposure with 8 extra weeks of premium.",
                    zh: "下移 10 个行权价，净付出约 $3.20；保留约 70% 原 delta 暴露，多 8 周时间价值。",
                  },
                },
                {
                  priority: "medium",
                  action: { en: "Close for residual value", zh: "平仓回收剩余价值" },
                  rationale: {
                    en: "Bank $12,100 in proceeds, redeploy capital. Cleanest exit if you've lost conviction in the upside thesis.",
                    zh: "回收 $12,100 资金，重新部署。若已不看好上行逻辑，这是最干净的退出。",
                  },
                },
                {
                  priority: "low",
                  action: { en: "Let it expire worthless", zh: "放任到期作废" },
                  rationale: {
                    en: "Acceptable only if you expect a >3% rally in the next 3 weeks. Historical hit rate from this distance is ~22%.",
                    zh: "仅当预期 3 周内涨幅 >3% 时合理。从该虚值距离到期内 ITM 的历史命中率约 22%。",
                  },
                },
              ],
            },
          ],
        },
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
        metadata: {
          sections: [
            {
              kind: "prose",
              title: { en: "Coupon overview", zh: "付息概览" },
              body: {
                en: "Routine semi-annual coupon on the $200,000 face holding of US 4.25% Aug-34. Payment hits the IBKR USD cash account on the settlement date; reinvestment is your choice — see actions below.",
                zh: "$200,000 面值美国 4.25% 2034-08 半年期付息，常规事件。付款日当日打入 IBKR 美元现金账户；是否再投资见下方建议。",
              },
            },
            {
              kind: "kvgrid",
              title: { en: "Payment facts", zh: "付息要素" },
              items: [
                {
                  label: { en: "Gross coupon", zh: "票息总额" },
                  value: "$4,250.00",
                  sub: { en: "200k face × 4.25% / 2", zh: "20 万面值 × 4.25% / 2" },
                },
                {
                  label: { en: "Settlement", zh: "结算日" },
                  value: "T+1 USD",
                  sub: { en: "Lands in IBKR cash", zh: "结算到 IBKR 现金账户" },
                },
                {
                  label: { en: "YTM (entry)", zh: "建仓 YTM" },
                  value: "4.42%",
                },
                {
                  label: { en: "Duration", zh: "久期" },
                  value: "7.8 yr",
                  pill: { text: { en: "MID", zh: "中等" } },
                },
              ],
            },
            {
              kind: "actions",
              title: { en: "Cash deployment", zh: "现金部署" },
              items: [
                {
                  priority: "medium",
                  action: { en: "Re-invest into 2-yr Treasury", zh: "再投资 2 年期国债" },
                  rationale: {
                    en: "Front-end yields ~4.95% currently; keeps duration profile balanced.",
                    zh: "当前 2 年期收益率约 4.95%，使整体久期更均衡。",
                  },
                },
                {
                  priority: "low",
                  action: { en: "Hold as USD cash", zh: "保留为美元现金" },
                  rationale: {
                    en: "Money-market sweep yields ~4.30%; flexibility for opportunistic deployment.",
                    zh: "货币市场基金收益约 4.30%，保留机动性。",
                  },
                },
              ],
            },
          ],
        },
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
          "Apple Inc. fiscal Q3 earnings. Holding 800 shares. Consensus EPS: $1.62.",
        ticker: "AAPL",
        startsAt: day(55, 20, 30),
        endsAt: day(55, 21, 30),
        isAllDay: false,
        metadata: {
          sections: [
            {
              kind: "prose",
              title: { en: "Position context", zh: "仓位背景" },
              eyebrow: { en: "Direct + linked exposures", zh: "直接 + 关联敞口" },
              body: {
                en: "Two positions on the book react to Thursday's print: 800 shares of AAPL (6.05% portfolio weight) plus a covered call written at 230C / 16 May. The covered-call leg caps upside above $230 but is currently +47% on premium decay — letting it ride through earnings risks an upside gap.",
                zh: "两笔仓位将受到周四财报直接影响：800 股 AAPL（占组合 6.05%）+ 卖出 16 May 230C 备兑看涨。备兑期权封顶 $230 以上上行，但当前权利金已浮盈 47%；财报跳空上涨将放大对冲缺口。",
              },
            },
            {
              kind: "table",
              title: { en: "Linked positions", zh: "关联仓位" },
              columns: [
                { key: "symbol", label: { en: "Symbol", zh: "代码" } },
                { key: "qty", label: { en: "Qty", zh: "数量" }, align: "right" },
                { key: "mark", label: { en: "Mark", zh: "现价" }, align: "right" },
                { key: "notional", label: { en: "Notional", zh: "名义" }, align: "right" },
                { key: "pl", label: { en: "P/L", zh: "盈亏" }, align: "right", tone: "sign" },
              ],
              rows: [
                { symbol: "AAPL", qty: "800", mark: "$215.62", notional: "$172,496", pl: "+$29,696" },
                { symbol: "AAPL 230C 16-May", qty: "−15", mark: "$2.85", notional: "−$4,275", pl: "+$2,025" },
              ],
            },
            {
              kind: "kvgrid",
              title: { en: "Consensus & implied", zh: "市场共识与隐含" },
              items: [
                {
                  label: { en: "Consensus EPS", zh: "EPS 共识" },
                  value: "$1.62",
                  sub: { en: "vs $1.51 prior", zh: "上季 $1.51" },
                  pill: { text: { en: "Beat ?", zh: "可能超预期" }, tone: "gain" },
                },
                {
                  label: { en: "IV before", zh: "事件前隐含波动" },
                  value: "34%",
                  sub: { en: "ATM 1-week", zh: "1 周平值" },
                },
                {
                  label: { en: "Implied move", zh: "预期波幅" },
                  value: "±5.2%",
                  pill: { text: { en: "Normal", zh: "正常" } },
                },
                {
                  label: { en: "Concentration", zh: "集中度" },
                  value: "6.05%",
                  sub: { en: "Of total portfolio", zh: "占组合总值" },
                },
              ],
            },
            {
              kind: "reaction",
              title: { en: "Historical reaction", zh: "历史反应" },
              eyebrow: { en: "Last 4 quarters", zh: "近 4 季度" },
              rows: [
                {
                  period: { en: "Q2 2026", zh: "Q2 2026" },
                  surprise: { en: "+8.4% vs consensus", zh: "超共识 +8.4%" },
                  reaction: { en: "Stock +4.1% next session", zh: "次日 +4.1%" },
                  tone: "gain",
                },
                {
                  period: { en: "Q1 2026", zh: "Q1 2026" },
                  surprise: { en: "+1.2% vs consensus", zh: "微超 +1.2%" },
                  reaction: { en: "Stock −0.6% (guidance soft)", zh: "次日 −0.6%（指引偏软）" },
                  tone: "loss",
                },
                {
                  period: { en: "Q4 2025", zh: "Q4 2025" },
                  surprise: { en: "+6.8% vs consensus", zh: "超共识 +6.8%" },
                  reaction: { en: "Stock +5.9% next session", zh: "次日 +5.9%" },
                  tone: "gain",
                },
                {
                  period: { en: "Q3 2025", zh: "Q3 2025" },
                  surprise: { en: "−2.3% miss", zh: "低于共识 2.3%" },
                  reaction: { en: "Stock −7.1% next session", zh: "次日 −7.1%" },
                  tone: "loss",
                },
              ],
            },
            {
              kind: "actions",
              title: { en: "Pre-print playbook", zh: "财报前预案" },
              items: [
                {
                  priority: "high",
                  action: { en: "Roll the 230C up to 240C", zh: "将 230C 上移至 240C" },
                  rationale: {
                    en: "Removes the upside cap that would bite on a beat; net cost ~$1.05/share given current premium.",
                    zh: "解除上行封顶（若超预期反弹将受损），按当前权利金净付出约 $1.05/股。",
                  },
                },
                {
                  priority: "medium",
                  action: { en: "Close the covered call", zh: "平掉备兑看涨" },
                  rationale: {
                    en: "Locks in the +$2,025 premium gain. Leaves stock fully exposed to the print — fine if you're bullish.",
                    zh: "锁定 +$2,025 权利金浮盈；股票端裸露全部财报敞口（若看多则合理）。",
                  },
                },
                {
                  priority: "low",
                  action: { en: "Hold both legs through the print", zh: "原样持有" },
                  rationale: {
                    en: "Status quo. Caps upside above $230 but earns full theta decay if AAPL stays flat-to-down.",
                    zh: "维持现状。封顶 $230 以上上行，AAPL 持平或下跌时全额吃 theta 收益。",
                  },
                },
              ],
            },
          ],
        },
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
        metadata: {
          location: "Zoom (link in confirmation email)",
          sections: [
            {
              kind: "prose",
              title: { en: "Meeting overview", zh: "会议概要" },
              body: {
                en: "Standing quarterly review with Kira Tanaka (lead advisor). Sixty minutes, video. Agenda spans Q2 attribution, the Tencent rebalance memo, the treasury ladder refresh, and FATCA renewal logistics. KT will share screen and walk through positioning charts.",
                zh: "与 Kira Tanaka（首席顾问）的例行季度复盘，60 分钟视频。议程涵盖 Q2 归因、腾讯调仓备忘、国债梯形再平衡，以及 FATCA 续签流程。KT 将共享屏幕讲解仓位图表。",
              },
            },
            {
              kind: "kvgrid",
              title: { en: "Meeting facts", zh: "会议要素" },
              items: [
                {
                  label: { en: "Advisor", zh: "顾问" },
                  value: "Kira Tanaka",
                  sub: { en: "Lead advisor · Hong Kong", zh: "首席顾问 · 香港" },
                },
                {
                  label: { en: "Duration", zh: "时长" },
                  value: "60 min",
                },
                {
                  label: { en: "Mode", zh: "形式" },
                  value: "Video",
                  pill: { text: { en: "Zoom", zh: "Zoom" } },
                },
                {
                  label: { en: "Recurrence", zh: "周期" },
                  value: "Quarterly",
                  sub: { en: "Next: Aug 2026", zh: "下次：2026/8" },
                },
              ],
            },
            {
              kind: "actions",
              title: { en: "Agenda", zh: "议程" },
              eyebrow: { en: "Four discussion items", zh: "四项议题" },
              items: [
                {
                  priority: "high",
                  action: { en: "Q2 attribution walkthrough", zh: "Q2 归因解读" },
                  rationale: {
                    en: "Where did the +2.4% net return come from? Sector vs security vs FX vs tactical.",
                    zh: "+2.4% 净回报的拆解：行业 / 个股 / 汇率 / 交易性。",
                  },
                },
                {
                  priority: "high",
                  action: { en: "Tencent trim trigger review", zh: "腾讯减仓阈值检视" },
                  rationale: {
                    en: "Position is at +19.3% — KT to present three rebalance options (full / partial / let-run).",
                    zh: "腾讯仓位浮盈 19.3%；KT 将给出三种方案（全减 / 部分 / 不动）。",
                  },
                },
                {
                  priority: "medium",
                  action: { en: "Treasury ladder refresh", zh: "国债梯形再平衡" },
                  rationale: {
                    en: "Curve has flattened ~30bp; consider rolling half the 10-yr into a 2-yr.",
                    zh: "曲线趋平约 30bp；考虑将一半 10 年期滚动到 2 年期。",
                  },
                },
                {
                  priority: "medium",
                  action: { en: "FATCA W-8BEN renewal logistics", zh: "FATCA W-8BEN 续签流程" },
                  rationale: {
                    en: "Due in 25 days; KT to walk through the e-signature flow.",
                    zh: "25 天后到期；KT 讲解电子签流程。",
                  },
                },
              ],
            },
          ],
        },
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
        metadata: {
          sections: [
            {
              kind: "prose",
              title: { en: "Why this matters", zh: "为什么重要" },
              body: {
                en: "Your W-8BEN expires in 25 days. If not renewed, IBKR is required by US regulation to apply the punitive 30% non-resident withholding rate on dividends and certain interest — versus the 15% treaty rate currently in place. Estimated cost of a lapse over a full year: ~$3,800 in extra withholding given current US-listed holdings.",
                zh: "您的 W-8BEN 将在 25 天后到期。若未续签，按美国法规 IBKR 必须对您的分红与部分利息适用 30% 非居民惩罚预扣，而非目前的 15% 协定优惠。按当前美股持仓估算，过期一年将多被预扣约 $3,800。",
              },
            },
            {
              kind: "actions",
              title: { en: "Three ways forward", zh: "三种选择" },
              items: [
                {
                  priority: "high",
                  action: { en: "Sign electronically now", zh: "立即电子签署" },
                  rationale: {
                    en: "Fastest path: pre-filled form in Documents → review → e-sign → done in 5 minutes.",
                    zh: "最快路径：文档库已预填表单 → 复核 → 电子签 → 5 分钟内完成。",
                  },
                },
                {
                  priority: "medium",
                  action: { en: "Schedule a 15-min call with KT", zh: "与 KT 预约 15 分钟通话" },
                  rationale: {
                    en: "If you want to walk through the form before signing.",
                    zh: "若希望先和顾问过一遍表单再签。",
                  },
                },
                {
                  priority: "low",
                  action: { en: "Print, wet-sign, mail back", zh: "打印纸质签字并寄回" },
                  rationale: {
                    en: "Required only if you've changed name / passport since the last filing.",
                    zh: "仅在上次申报后姓名 / 护照有变更时才需要走纸质流程。",
                  },
                },
              ],
            },
          ],
        },
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
        metadata: {
          sections: [
            {
              kind: "prose",
              title: { en: "Portfolio sensitivity", zh: "组合敏感度" },
              body: {
                en: "Two sleeves of the book are directly rate-sensitive. The long-end of the Treasury holding (10-yr) has ~$160 DV01, so a 25bp surprise either direction moves NAV by ~$4,000. The futures sleeve includes a +4 ZN long that adds another $280 DV01. Equity beta is the second-order risk — historical Fed-day reactions average ±0.8% on SPY.",
                zh: "组合中两段对利率直接敏感。国债部分 10 年期 DV01 约 $160，任一方向 25bp 意外将影响 NAV 约 $4,000；期货段含 +4 ZN 多头，DV01 增加 $280。股票 Beta 是次级风险——历史 FOMC 当日 SPY 反应平均 ±0.8%。",
              },
            },
            {
              kind: "kvgrid",
              title: { en: "Market pricing", zh: "市场定价" },
              items: [
                {
                  label: { en: "Hike probability", zh: "加息概率" },
                  value: "8%",
                  sub: { en: "Fed Funds futures", zh: "联邦基金期货" },
                },
                {
                  label: { en: "Hold probability", zh: "持平概率" },
                  value: "70%",
                  pill: { text: { en: "BASE", zh: "基准" } },
                },
                {
                  label: { en: "Cut probability", zh: "降息概率" },
                  value: "22%",
                },
                {
                  label: { en: "Combined DV01", zh: "总 DV01" },
                  value: "$440",
                  sub: { en: "Bonds + futures", zh: "国债 + 期货" },
                },
              ],
            },
            {
              kind: "actions",
              title: { en: "Scenario playbook", zh: "情景预案" },
              items: [
                {
                  priority: "high",
                  action: { en: "Surprise cut (22% odds)", zh: "意外降息（22%）" },
                  rationale: {
                    en: "Expect +$11k bond MTM gain, +$2.5k futures gain. Consider trimming half the ZN position into strength.",
                    zh: "预计国债 MTM +$11k，期货 +$2.5k；可考虑在 ZN 大涨时减一半。",
                  },
                },
                {
                  priority: "medium",
                  action: { en: "Hawkish hold (typical path)", zh: "鹰派持平（基准情形）" },
                  rationale: {
                    en: "No book change. Watch the press-conference Q&A for September signal.",
                    zh: "仓位不动；关注新闻发布会 Q&A 中对 9 月的暗示。",
                  },
                },
                {
                  priority: "high",
                  action: { en: "Surprise hike (8% odds)", zh: "意外加息（8%）" },
                  rationale: {
                    en: "Expect −$11k bond MTM hit. The SPY 530P put provides ~2% equity downside cushion that would activate.",
                    zh: "预计国债 MTM −$11k；现有 SPY 530P 可激活，提供约 2% 股票端下行缓冲。",
                  },
                },
              ],
            },
          ],
        },
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
        metadata: {
          sections: [
            {
              kind: "prose",
              title: { en: "Report scope", zh: "报告范围" },
              body: {
                en: "Monthly performance brief covers MTD net return, attribution by sleeve (HK equities / US equities / options / futures / bonds / crypto), top contributors and detractors, risk metrics (Beta / Sharpe / Vol / MaxDD), and a forward-looking 'what to watch' note from KT. PDF + portal versions delivered together.",
                zh: "月度报告覆盖：当月净回报、按板块归因（港股 / 美股 / 期权 / 期货 / 国债 / 加密）、贡献最大与拖累最大的仓位、风险指标（Beta / Sharpe / 波动率 / 最大回撤），以及 KT 撰写的下月关注要点。同时投递 PDF 与门户版本。",
              },
            },
            {
              kind: "actions",
              title: { en: "When it arrives", zh: "投递后" },
              items: [
                {
                  priority: "high",
                  action: { en: "Read in the portal", zh: "在门户中阅读" },
                  rationale: {
                    en: "Charts are interactive; click any position bar to drill into trade-level history.",
                    zh: "图表可交互；点击任一仓位条目可下钻到交易级历史。",
                  },
                },
                {
                  priority: "medium",
                  action: { en: "Download the PDF", zh: "下载 PDF" },
                  rationale: { en: "For records / accountant sharing.", zh: "便于存档或转给会计。" },
                },
                {
                  priority: "low",
                  action: { en: "Forward to spouse / family CFO", zh: "转发给配偶 / 家族 CFO" },
                  rationale: {
                    en: "Read-only link expires after 30 days.",
                    zh: "只读链接 30 天后过期。",
                  },
                },
              ],
            },
          ],
        },
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
        metadata: {
          location: "Tokyo, Japan",
          sections: [
            {
              kind: "prose",
              title: { en: "Personal note", zh: "个人备忘" },
              body: {
                en: "Family vacation, 10 days. KT has been informed; she'll cover urgent issues via WhatsApp only. No scheduled calls. Reachable for genuine emergencies (lockout, fraud alert) at the usual numbers.",
                zh: "家庭度假，10 天。已通知 KT，期间仅紧急情况通过 WhatsApp 处理，不安排正式通话。账户冻结 / 欺诈警报等真正紧急事件仍可拨打常用联系方式。",
              },
            },
            {
              kind: "kvgrid",
              title: { en: "Trip facts", zh: "行程信息" },
              items: [
                { label: { en: "Destination", zh: "目的地" }, value: "Tokyo, Japan" },
                { label: { en: "Duration", zh: "时长" }, value: "10 days" },
                {
                  label: { en: "Advisor coverage", zh: "顾问覆盖" },
                  value: "WhatsApp only",
                  pill: { text: { en: "EMERGENCIES", zh: "仅紧急" }, tone: "warn" },
                },
              ],
            },
          ],
        },
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
