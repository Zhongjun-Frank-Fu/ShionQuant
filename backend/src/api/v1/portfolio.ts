/**
 * /api/v1/portfolio/* — read-only portfolio endpoints.
 *
 * Source of truth:
 *   - `daily_nav`     summary numbers (NAV, day P/L) for fast hero loads
 *   - `positions`     line items joined through `accounts` to the client
 *   - `cash_balances` per-currency cash + margin
 *   - `risk_metrics`  latest daily snapshot of risk stats
 *
 * Data freshness:
 *   These tables are populated by an out-of-band broker-sync job (M5+ —
 *   currently they're filled by `pnpm seed`). The API just reads them.
 *
 * Money on the wire:
 *   Postgres `numeric` round-trips through Drizzle as `string` to preserve
 *   precision. We forward strings for row-level fields and convert to JS
 *   `number` only for top-level summary scalars (NAV, day P/L) where 6-figure
 *   doubles are exact. The frontend can decide whether to `Number()` further.
 *
 * Auth posture:
 *   `authMiddleware` (no MFA gate) — these are read-only. Reads are NOT
 *   audited (would flood audit_log on every page refresh); the access log
 *   from `loggerMiddleware` is enough for forensics.
 */

import { and, asc, desc, eq, gte, inArray, isNull, lte, sql } from "drizzle-orm"
import { Hono } from "hono"

import {
  accounts,
  cashBalances,
  dailyNav,
  db,
  positions,
  riskMetrics,
} from "../../db/client.js"
import { forbidden } from "../../lib/errors.js"
import { authMiddleware } from "../../middleware/auth.js"
import { navQuerySchema, positionsQuerySchema, rangeToStart } from "../../schemas/portfolio.js"

const app = new Hono()

app.use("*", authMiddleware)

function requireClient(c: import("hono").Context) {
  const client = c.get("client")
  if (!client) throw forbidden("This endpoint is for client users only")
  return client
}

/**
 * Resolve all account IDs for a client. Cached per request only — most
 * portfolio routes share this lookup.
 */
async function getAccountIds(clientId: string): Promise<string[]> {
  const rows = await db
    .select({ id: accounts.id })
    .from(accounts)
    .where(and(eq(accounts.clientId, clientId), eq(accounts.isActive, true)))
  return rows.map((r) => r.id)
}

/**
 * Capital-deployed view of the portfolio: how much money sits in each asset
 * class. Used as the denominator for allocation %s and per-row weight %s.
 *
 * Aggregation rules:
 *   - equity / option / bond / crypto → Σ market_value
 *   - future                          → Σ (future_initial_margin × quantity)
 *     Futures notional dwarfs the actual capital tied up; we count margin so
 *     the allocation bar reflects "where the capital sits" instead of being
 *     pinned to notional. Per-row market_value is still emitted as notional
 *     for the line-item display in /positions and /other-assets.
 *   - cash                            → Σ cash_balances.amount_usd
 *
 * Returns 0 across the board if the client has no positions yet.
 */
async function getTotalNavUsd(accountIds: string[]): Promise<{
  totalUsd: number
  byAssetType: Record<string, number>
  cashUsd: number
}> {
  if (accountIds.length === 0) {
    return { totalUsd: 0, byAssetType: {}, cashUsd: 0 }
  }

  // Non-future positions: market_value sum.
  const nonFutureRows = await db
    .select({
      assetType: positions.assetType,
      valueUsd: sql<string>`coalesce(sum(${positions.marketValue}), 0)`.as("value_usd"),
    })
    .from(positions)
    .where(
      and(
        inArray(positions.accountId, accountIds),
        isNull(positions.closedAt),
        sql`${positions.assetType} <> 'future'`,
      ),
    )
    .groupBy(positions.assetType)

  // Future positions: Σ initial_margin × quantity (capital deployed).
  const futureRow = await db
    .select({
      valueUsd: sql<string>`coalesce(sum(${positions.futureInitialMargin} * ${positions.quantity}), 0)`.as(
        "value_usd",
      ),
    })
    .from(positions)
    .where(
      and(
        inArray(positions.accountId, accountIds),
        isNull(positions.closedAt),
        eq(positions.assetType, "future"),
      ),
    )

  const cashSumRow = await db
    .select({
      valueUsd: sql<string>`coalesce(sum(${cashBalances.amountUsd}), 0)`.as("value_usd"),
    })
    .from(cashBalances)
    .where(inArray(cashBalances.accountId, accountIds))

  const byAssetType: Record<string, number> = {}
  let total = 0
  for (const row of nonFutureRows) {
    const v = Number(row.valueUsd)
    byAssetType[row.assetType] = v
    total += v
  }
  const futureUsd = Number(futureRow[0]?.valueUsd ?? 0)
  if (futureUsd > 0) byAssetType.future = futureUsd
  total += futureUsd

  const cashUsd = Number(cashSumRow[0]?.valueUsd ?? 0)
  total += cashUsd

  return { totalUsd: total, byAssetType, cashUsd }
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/portfolio/overview
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Hero load for the Portfolio page:
 *   - latest NAV + day P/L (from daily_nav)
 *   - allocation breakdown by asset_type (live aggregate over open positions
 *     + cash, since daily_nav stores per-class subtotals but cash sits in a
 *     separate table)
 *   - 30-day NAV curve (sparkline)
 *   - latest beta-to-SPY (from daily_nav)
 *   - multi-period returns: YTD, 1-year, since-inception (from daily_nav)
 *   - per-asset-type position counts (for "X positions" sub-labels)
 */
app.get("/overview", async (c) => {
  const client = requireClient(c)

  // 1. Most-recent daily_nav row.
  const navRows = await db
    .select()
    .from(dailyNav)
    .where(eq(dailyNav.clientId, client.id))
    .orderBy(desc(dailyNav.asOf))
    .limit(1)
  const latestNav = navRows[0] ?? null

  // 2. 30-day sparkline.
  const navSeries = await db
    .select({
      asOf: dailyNav.asOf,
      navTotalUsd: dailyNav.navTotalUsd,
      dayPl: dailyNav.dayPl,
      dayPlPct: dailyNav.dayPlPct,
    })
    .from(dailyNav)
    .where(eq(dailyNav.clientId, client.id))
    .orderBy(desc(dailyNav.asOf))
    .limit(30)
  navSeries.reverse() // chart wants oldest → newest

  // 3. Allocation breakdown — group positions by asset_type, sum market_value.
  const accountIds = await getAccountIds(client.id)
  const totals = await getTotalNavUsd(accountIds)
  const allocation: Record<string, { valueUsd: number; pct: number }> = {}
  for (const [assetType, valueUsd] of Object.entries(totals.byAssetType)) {
    allocation[assetType] = { valueUsd, pct: 0 }
  }
  allocation.cash = { valueUsd: totals.cashUsd, pct: 0 }
  if (totals.totalUsd > 0) {
    for (const k of Object.keys(allocation)) {
      const entry = allocation[k]
      if (entry) entry.pct = round2((entry.valueUsd / totals.totalUsd) * 100)
    }
  }

  // 4. Position counts — one row per asset_type.
  const positionCounts: Record<string, number> = {
    equity: 0,
    option: 0,
    future: 0,
    bond: 0,
    crypto: 0,
  }
  if (accountIds.length > 0) {
    const countRows = await db
      .select({
        assetType: positions.assetType,
        n: sql<number>`count(*)::int`.as("n"),
      })
      .from(positions)
      .where(
        and(inArray(positions.accountId, accountIds), isNull(positions.closedAt)),
      )
      .groupBy(positions.assetType)
    for (const r of countRows) positionCounts[r.assetType] = r.n
  }

  // 5. Multi-period returns — first NAV row in window vs latest.
  const ytdPlPct = latestNav
    ? await computeReturnSinceDate(
        client.id,
        latestNav,
        `${new Date(latestNav.asOf).getFullYear()}-01-01`,
      )
    : null

  const oneYearPlPct = latestNav
    ? await computeReturnSinceDate(
        client.id,
        latestNav,
        addYears(latestNav.asOf, -1),
      )
    : null

  // Inception = oldest daily_nav row available for this client.
  let inceptionPlPct: number | null = null
  if (latestNav) {
    const inceptionRow = await db
      .select({ navTotalUsd: dailyNav.navTotalUsd })
      .from(dailyNav)
      .where(eq(dailyNav.clientId, client.id))
      .orderBy(asc(dailyNav.asOf))
      .limit(1)
    if (inceptionRow[0]) {
      const start = Number(inceptionRow[0].navTotalUsd)
      const end = Number(latestNav.navTotalUsd)
      if (start > 0) inceptionPlPct = round2(((end - start) / start) * 100)
    }
  }

  return c.json({
    ok: true,
    asOf: latestNav?.asOf ?? null,
    navTotalUsd: latestNav ? Number(latestNav.navTotalUsd) : 0,
    dayPlUsd: latestNav?.dayPl ? Number(latestNav.dayPl) : 0,
    dayPlPct: latestNav?.dayPlPct ? Number(latestNav.dayPlPct) : 0,
    ytdPlPct,
    oneYearPlPct,
    inceptionPlPct,
    betaToSpy: latestNav?.betaToSpy ? Number(latestNav.betaToSpy) : null,
    allocation,
    positionCounts,
    navHistory: navSeries,
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/portfolio/positions
// ═══════════════════════════════════════════════════════════════════════════

/**
 * `?assetType=equity|option|future|bond|crypto|cash` (optional)
 * `?closed=true` to include closed positions (default: open only)
 * `?limit=200&offset=0` (default 200, max 500)
 *
 * Sorted by market_value DESC — the largest line items first. Each row
 * carries a `weightPct` field (its market_value relative to total NAV).
 */
app.get("/positions", async (c) => {
  const client = requireClient(c)
  const query = positionsQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const accountIds = await getAccountIds(client.id)
  if (accountIds.length === 0) {
    return c.json({ ok: true, positions: [], total: 0, limit: query.limit, offset: query.offset })
  }

  const conditions = [inArray(positions.accountId, accountIds)]
  if (query.assetType) conditions.push(eq(positions.assetType, query.assetType))
  if (!query.closed) conditions.push(isNull(positions.closedAt))

  const where = and(...conditions)

  // Count for total — same WHERE as the page query.
  const [countRow] = await db
    .select({ count: sql<number>`count(*)::int`.as("count") })
    .from(positions)
    .where(where)

  const rows = await db
    .select()
    .from(positions)
    .where(where)
    .orderBy(desc(positions.marketValue))
    .limit(query.limit)
    .offset(query.offset)

  // Denominator for weight %: full NAV across asset types (matches the
  // allocation bar on the overview page).
  const totals = await getTotalNavUsd(accountIds)

  return c.json({
    ok: true,
    positions: rows.map((p) => shapePosition(p, totals.totalUsd)),
    total: countRow?.count ?? 0,
    limit: query.limit,
    offset: query.offset,
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/portfolio/cash
// ═══════════════════════════════════════════════════════════════════════════

app.get("/cash", async (c) => {
  const client = requireClient(c)
  const accountIds = await getAccountIds(client.id)
  if (accountIds.length === 0) {
    return c.json({
      ok: true,
      balances: [],
      totals: {
        amountUsd: 0,
        marginUsedUsd: 0,
        availableUsd: 0,
        buyingPowerUsd: 0,
        buyingPowerSource: "fallback-2x-equity" as const,
        futuresContractsCount: 0,
      },
    })
  }

  const rows = await db
    .select()
    .from(cashBalances)
    .where(inArray(cashBalances.accountId, accountIds))
    .orderBy(desc(cashBalances.amountUsd))

  // Totals — convert each row to USD via its own fx_rate_to_usd. (Margin and
  // available are stored as `amount_local`, not USD-equivalent, so we apply
  // the same fx rate per row.)
  let amountUsd = 0
  let marginUsedUsd = 0
  let availableUsd = 0
  for (const r of rows) {
    const fx = Number(r.fxRateToUsd)
    amountUsd += Number(r.amountUsd ?? 0)
    marginUsedUsd += Number(r.marginUsed) * fx
    availableUsd += Number(r.available) * fx
  }

  // Buying Power: prefer broker-precomputed sum across active accounts; if
  // every account has it null, fall back to the Reg-T-style heuristic.
  const accountRows = await db
    .select({ buyingPowerUsd: accounts.buyingPowerUsd })
    .from(accounts)
    .where(inArray(accounts.id, accountIds))

  let brokerBuyingPower = 0
  let hasBrokerBuyingPower = false
  for (const r of accountRows) {
    if (r.buyingPowerUsd !== null && r.buyingPowerUsd !== undefined) {
      brokerBuyingPower += Number(r.buyingPowerUsd)
      hasBrokerBuyingPower = true
    }
  }

  let buyingPowerUsd: number
  let buyingPowerSource: "broker" | "fallback-2x-equity"
  if (hasBrokerBuyingPower) {
    buyingPowerUsd = round2(brokerBuyingPower)
    buyingPowerSource = "broker"
  } else {
    // Fallback: available cash + 2× equity NAV (Reg-T flavor; excludes crypto).
    const equityRow = await db
      .select({
        valueUsd: sql<string>`coalesce(sum(${positions.marketValue}), 0)`.as("value_usd"),
      })
      .from(positions)
      .where(
        and(
          inArray(positions.accountId, accountIds),
          eq(positions.assetType, "equity"),
          isNull(positions.closedAt),
        ),
      )
    const equityNavUsd = Number(equityRow[0]?.valueUsd ?? 0)
    buyingPowerUsd = round2(availableUsd + 2 * equityNavUsd)
    buyingPowerSource = "fallback-2x-equity"
  }

  // Active futures contract count (for the "Reserved for X active futures
  // contracts" sub-label on the Margin Used card).
  const futuresCountRow = await db
    .select({ n: sql<number>`count(*)::int`.as("n") })
    .from(positions)
    .where(
      and(
        inArray(positions.accountId, accountIds),
        eq(positions.assetType, "future"),
        isNull(positions.closedAt),
      ),
    )
  const futuresContractsCount = futuresCountRow[0]?.n ?? 0

  return c.json({
    ok: true,
    balances: rows.map((r) => ({
      currency: r.currency,
      amountLocal: r.amountLocal,
      fxRateToUsd: r.fxRateToUsd,
      amountUsd: r.amountUsd,
      sharePct:
        amountUsd > 0
          ? round2((Number(r.amountUsd ?? 0) / amountUsd) * 100)
          : 0,
      available: r.available,
      marginUsed: r.marginUsed,
      lastSyncedAt: r.lastSyncedAt,
    })),
    totals: {
      amountUsd: round2(amountUsd),
      marginUsedUsd: round2(marginUsedUsd),
      availableUsd: round2(availableUsd),
      buyingPowerUsd,
      buyingPowerSource,
      futuresContractsCount,
    },
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/portfolio/nav
// ═══════════════════════════════════════════════════════════════════════════

app.get("/nav", async (c) => {
  const client = requireClient(c)
  const query = navQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const start = rangeToStart(query.range)
  const conditions = [eq(dailyNav.clientId, client.id)]
  if (start) {
    // Postgres `date` column compared to `YYYY-MM-DD` string.
    const isoDate = start.toISOString().slice(0, 10)
    conditions.push(gte(dailyNav.asOf, isoDate))
  }

  const rows = await db
    .select({
      asOf: dailyNav.asOf,
      navTotalUsd: dailyNav.navTotalUsd,
      dayPl: dailyNav.dayPl,
      dayPlPct: dailyNav.dayPlPct,
      betaToSpy: dailyNav.betaToSpy,
    })
    .from(dailyNav)
    .where(and(...conditions))
    .orderBy(asc(dailyNav.asOf))

  return c.json({
    ok: true,
    range: query.range,
    series: rows,
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/portfolio/risk
// ═══════════════════════════════════════════════════════════════════════════

app.get("/risk", async (c) => {
  const client = requireClient(c)

  const rows = await db
    .select()
    .from(riskMetrics)
    .where(eq(riskMetrics.clientId, client.id))
    .orderBy(desc(riskMetrics.asOf))
    .limit(1)

  if (rows.length === 0) {
    return c.json({ ok: true, asOf: null, metrics: null })
  }

  const r = rows[0]!
  return c.json({
    ok: true,
    asOf: r.asOf,
    metrics: {
      beta: r.beta,
      sharpe: r.sharpe,
      sortino: r.sortino,
      maxDrawdown: r.maxDrawdown,
      volAnnualized: r.volAnnualized,
    },
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/portfolio/other-assets
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Aggregated "Other Assets" payload for the Portal home page. Returns one
 * block per non-equity asset class, each with its own list of positions plus
 * a per-class aggregate. Aggregates are computed here (not on the client) so
 * the weighted-yield / Greek-sum / margin-sum logic stays server-side.
 *
 * Block shape:
 *   {
 *     count, marketValueUsd,
 *     positions: [...],            // shaped like /positions rows
 *     aggregate: { ...class-specific }
 *   }
 *
 * Class-specific aggregates:
 *   - option: { delta, gamma, theta, vega }      (Σ Greek × quantity)
 *   - future: { initialMarginUsd, dv01, totalPl, netBias, betaContrib }
 *   - bond:   { weightedYieldPct, weightedDurationYears, faceValueTotal,
 *               accruedInterestYtd, nextCouponAt, nextCouponAmountUsd }
 *   - crypto: { combinedUnrealizedPl, ytdReturnPct }
 */
app.get("/other-assets", async (c) => {
  const client = requireClient(c)
  const accountIds = await getAccountIds(client.id)
  const empty = {
    count: 0,
    marketValueUsd: 0,
    positions: [] as ReturnType<typeof shapePosition>[],
  }

  if (accountIds.length === 0) {
    return c.json({
      ok: true,
      options: { ...empty, aggregate: emptyOptionAggregate() },
      futures: { ...empty, aggregate: emptyFutureAggregate() },
      bonds: { ...empty, aggregate: emptyBondAggregate() },
      crypto: { ...empty, aggregate: emptyCryptoAggregate() },
    })
  }

  const totals = await getTotalNavUsd(accountIds)

  // Pull every non-equity, non-cash open position in one round-trip; bucket
  // in JS. Smaller payload than 4 separate queries and keeps the order
  // (market_value DESC) consistent across blocks.
  const rows = await db
    .select()
    .from(positions)
    .where(
      and(
        inArray(positions.accountId, accountIds),
        inArray(positions.assetType, ["option", "future", "bond", "crypto"]),
        isNull(positions.closedAt),
      ),
    )
    .orderBy(desc(positions.marketValue))

  const buckets: Record<"option" | "future" | "bond" | "crypto", typeof rows> = {
    option: [],
    future: [],
    bond: [],
    crypto: [],
  }
  for (const r of rows) {
    const t = r.assetType as keyof typeof buckets
    if (t in buckets) buckets[t].push(r)
  }

  // ── Options aggregate: sum of Greeks weighted by contract count. ──────────
  let oDelta = 0
  let oGamma = 0
  let oTheta = 0
  let oVega = 0
  let oMv = 0
  for (const p of buckets.option) {
    const qty = Number(p.quantity)
    if (p.optionDelta) oDelta += Number(p.optionDelta) * qty * 100
    if (p.optionGamma) oGamma += Number(p.optionGamma) * qty * 100
    if (p.optionTheta) oTheta += Number(p.optionTheta) * qty
    if (p.optionVega) oVega += Number(p.optionVega) * qty
    oMv += Number(p.marketValue ?? 0)
  }

  // ── Futures aggregate: margin sum, DV01 sum, P/L sum, long/short bias. ───
  let fMarginUsd = 0
  let fDv01 = 0
  let fTotalPl = 0
  let fLongMv = 0
  let fShortMv = 0
  let fMv = 0
  for (const p of buckets.future) {
    const qty = Number(p.quantity)
    fMarginUsd += Number(p.futureInitialMargin ?? 0) * qty
    fDv01 += Number(p.futureDv01 ?? 0) * qty
    fTotalPl += Number(p.unrealizedPl ?? 0)
    fMv += Number(p.marketValue ?? 0)
    if (p.side === "short") fShortMv += Number(p.marketValue ?? 0)
    else fLongMv += Number(p.marketValue ?? 0)
  }
  let netBias: "long" | "short" | "neutral"
  if (fLongMv === 0 && fShortMv === 0) netBias = "neutral"
  else if (fLongMv >= fShortMv * 1.05) netBias = "long"
  else if (fShortMv >= fLongMv * 1.05) netBias = "short"
  else netBias = "neutral"

  // ── Bonds aggregate: weighted YTM and duration by market_value. ──────────
  let bMvWeightSum = 0
  let bWeightedYtm = 0
  let bWeightedDur = 0
  let bFaceTotal = 0
  let bMv = 0
  let bNextCoupon: { date: string; amountUsd: number } | null = null
  for (const p of buckets.bond) {
    const mv = Number(p.marketValue ?? 0)
    bMvWeightSum += mv
    if (p.bondYtm) bWeightedYtm += Number(p.bondYtm) * mv
    if (p.bondDuration) bWeightedDur += Number(p.bondDuration) * mv
    if (p.bondFaceValue) bFaceTotal += Number(p.bondFaceValue)
    bMv += mv
  }
  // Pick the soonest upcoming bond_maturity (proxy for next coupon date).
  // True coupon scheduling lives in the events table; this is a sensible
  // lower bound for the "Next coupon" subtitle.
  const upcomingBond = buckets.bond
    .filter((p) => p.bondMaturity)
    .sort((a, b) => (a.bondMaturity! < b.bondMaturity! ? -1 : 1))[0]
  if (upcomingBond?.bondMaturity && upcomingBond.bondCouponPct && upcomingBond.bondFaceValue) {
    bNextCoupon = {
      date: upcomingBond.bondMaturity,
      // Semi-annual approximation: face × coupon% / 2.
      amountUsd: round2(
        (Number(upcomingBond.bondFaceValue) * Number(upcomingBond.bondCouponPct)) / 200,
      ),
    }
  }

  // ── Crypto aggregate: total unrealized P/L + YTD return from daily_nav. ─
  let cPl = 0
  let cMv = 0
  for (const p of buckets.crypto) {
    cPl += Number(p.unrealizedPl ?? 0)
    cMv += Number(p.marketValue ?? 0)
  }
  // YTD return on the crypto sleeve: first daily_nav.nav_crypto of the year
  // vs the latest. Returns null if we don't have data yet.
  let cYtdReturnPct: number | null = null
  const latestNavRow = await db
    .select({ asOf: dailyNav.asOf, navCrypto: dailyNav.navCrypto })
    .from(dailyNav)
    .where(eq(dailyNav.clientId, client.id))
    .orderBy(desc(dailyNav.asOf))
    .limit(1)
  const latestForCrypto = latestNavRow[0]
  if (latestForCrypto?.navCrypto) {
    const yearStart = `${new Date(latestForCrypto.asOf).getFullYear()}-01-01`
    const firstOfYear = await db
      .select({ navCrypto: dailyNav.navCrypto })
      .from(dailyNav)
      .where(
        and(eq(dailyNav.clientId, client.id), gte(dailyNav.asOf, yearStart)),
      )
      .orderBy(asc(dailyNav.asOf))
      .limit(1)
    if (firstOfYear[0]?.navCrypto) {
      const start = Number(firstOfYear[0].navCrypto)
      const end = Number(latestForCrypto.navCrypto)
      if (start > 0) cYtdReturnPct = round2(((end - start) / start) * 100)
    }
  }

  return c.json({
    ok: true,
    options: {
      count: buckets.option.length,
      marketValueUsd: round2(oMv),
      aggregate: {
        delta: round2(oDelta),
        gamma: round2(oGamma),
        thetaUsdPerDay: round2(oTheta),
        vegaUsd: round2(oVega),
      },
      positions: buckets.option.map((p) => shapePosition(p, totals.totalUsd)),
    },
    futures: {
      count: buckets.future.length,
      marketValueUsd: round2(fMv),
      aggregate: {
        initialMarginUsd: round2(fMarginUsd),
        dv01: round2(fDv01),
        totalPlUsd: round2(fTotalPl),
        netBias,
        // Per-position beta isn't tracked yet; emitted as null until a
        // futures-beta column lands.
        betaContrib: null as number | null,
      },
      positions: buckets.future.map((p) => shapePosition(p, totals.totalUsd)),
    },
    bonds: {
      count: buckets.bond.length,
      marketValueUsd: round2(bMv),
      aggregate: {
        weightedYieldPct: bMvWeightSum > 0 ? round2(bWeightedYtm / bMvWeightSum) : null,
        weightedDurationYears: bMvWeightSum > 0 ? round2(bWeightedDur / bMvWeightSum) : null,
        faceValueTotal: round2(bFaceTotal),
        // Accrued YTD is not yet tracked in the schema (would need a
        // bond_accrual table or YTD accumulator on positions). null = unknown.
        accruedInterestYtd: null as number | null,
        nextCoupon: bNextCoupon,
      },
      positions: buckets.bond.map((p) => shapePosition(p, totals.totalUsd)),
    },
    crypto: {
      count: buckets.crypto.length,
      marketValueUsd: round2(cMv),
      aggregate: {
        combinedUnrealizedPlUsd: round2(cPl),
        ytdReturnPct: cYtdReturnPct,
      },
      positions: buckets.crypto.map((p) => shapePosition(p, totals.totalUsd)),
    },
  })
})

export default app

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function round2(n: number): number {
  return Math.round(n * 100) / 100
}

function addYears(asOf: string, n: number): string {
  // `asOf` is a Postgres date string like "2026-05-09".
  const d = new Date(asOf)
  d.setUTCFullYear(d.getUTCFullYear() + n)
  return d.toISOString().slice(0, 10)
}

/**
 * Compute the % return between the first daily_nav row on/after `since` and
 * `latest`. Returns null if there's no data point in the window.
 */
async function computeReturnSinceDate(
  clientId: string,
  latest: typeof dailyNav.$inferSelect,
  since: string,
): Promise<number | null> {
  const start = await db
    .select({ navTotalUsd: dailyNav.navTotalUsd })
    .from(dailyNav)
    .where(and(eq(dailyNav.clientId, clientId), gte(dailyNav.asOf, since), lte(dailyNav.asOf, latest.asOf)))
    .orderBy(asc(dailyNav.asOf))
    .limit(1)
  if (!start[0]) return null
  const startVal = Number(start[0].navTotalUsd)
  const endVal = Number(latest.navTotalUsd)
  if (startVal <= 0) return null
  return round2(((endVal - startVal) / startVal) * 100)
}

function emptyOptionAggregate() {
  return { delta: 0, gamma: 0, thetaUsdPerDay: 0, vegaUsd: 0 }
}
function emptyFutureAggregate() {
  return {
    initialMarginUsd: 0,
    dv01: 0,
    totalPlUsd: 0,
    netBias: "neutral" as const,
    betaContrib: null as number | null,
  }
}
function emptyBondAggregate() {
  return {
    weightedYieldPct: null as number | null,
    weightedDurationYears: null as number | null,
    faceValueTotal: 0,
    accruedInterestYtd: null as number | null,
    nextCoupon: null as { date: string; amountUsd: number } | null,
  }
}
function emptyCryptoAggregate() {
  return { combinedUnrealizedPlUsd: 0, ytdReturnPct: null as number | null }
}

function shapePosition(p: typeof positions.$inferSelect, totalNavUsd: number) {
  // Strip nullable asset-class-specific fields where they don't apply, to
  // keep the JSON tidy. The frontend can branch on `assetType`.
  // Weight uses the capital-deployed view: market_value for everything except
  // futures, which use margin × quantity (matches getTotalNavUsd's denominator
  // so the equity-table weights and the allocation bar stay self-consistent).
  const capitalUsd =
    p.assetType === "future"
      ? Number(p.futureInitialMargin ?? 0) * Number(p.quantity ?? 0)
      : Number(p.marketValue ?? 0)
  const weightPct = totalNavUsd > 0 ? round2((capitalUsd / totalNavUsd) * 100) : null
  const base = {
    id: p.id,
    accountId: p.accountId,
    assetType: p.assetType,
    symbol: p.symbol,
    displayName: p.displayName,
    isin: p.isin,
    cusip: p.cusip,
    quantity: p.quantity,
    side: p.side,
    costBasisTotal: p.costBasisTotal,
    costBasisAvg: p.costBasisAvg,
    markPrice: p.markPrice,
    marketValue: p.marketValue,
    unrealizedPl: p.unrealizedPl,
    unrealizedPlPct: p.unrealizedPlPct,
    dayChange: p.dayChange,
    dayChangePct: p.dayChangePct,
    weightPct,
    openedAt: p.openedAt,
    lastSyncedAt: p.lastSyncedAt,
  }

  switch (p.assetType) {
    case "option":
      return {
        ...base,
        option: {
          underlying: p.optionUnderlying,
          strike: p.optionStrike,
          expiry: p.optionExpiry,
          type: p.optionType,
          delta: p.optionDelta,
          gamma: p.optionGamma,
          theta: p.optionTheta,
          vega: p.optionVega,
          iv: p.optionIv,
        },
      }
    case "future":
      return {
        ...base,
        future: {
          underlying: p.futureUnderlying,
          expiry: p.futureExpiry,
          initialMargin: p.futureInitialMargin,
          dv01: p.futureDv01,
        },
      }
    case "bond":
      return {
        ...base,
        bond: {
          couponPct: p.bondCouponPct,
          maturity: p.bondMaturity,
          ytm: p.bondYtm,
          duration: p.bondDuration,
          faceValue: p.bondFaceValue,
        },
      }
    default:
      return base
  }
}
