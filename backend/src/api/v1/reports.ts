/**
 * /api/v1/reports/* — research library + custom-research requests.
 *
 * Visibility model:
 *   A report is visible to a client if it's published AND either:
 *     - firm-wide (`reports.client_id IS NULL`)  — all clients see it
 *     - or scoped to this client (`reports.client_id = $myClient`)
 *
 *   `is_draft = true` is never visible (advisor-side WIP).
 *
 * Read tracking:
 *   `report_access` is one row per (reportId, clientId). On detail load we
 *   upsert: insert if missing, otherwise bump `read_count` + `last_read_at`.
 *   Bookmarks live on the same row.
 *
 * Subscriptions:
 *   `report_subscriptions` is one row per (clientId, reportType). PATCH does
 *   a per-row upsert; channels: [] silences a type.
 *
 * Custom research requests:
 *   POST creates a row with `status="submitted"`. Advisor-side workflow
 *   (scoping → proposed → active) is out-of-scope here; client just submits
 *   and watches the status field via GET.
 *
 * Auth posture:
 *   `authMiddleware` for reads + bookmarks + subscriptions (low stakes).
 *   `mfaAuthMiddleware` for POST /custom-requests (could trigger material
 *   project work; want a 2FA-gated trail).
 */

import { and, desc, eq, isNull, or, sql, type SQL } from "drizzle-orm"
import { Hono } from "hono"

import {
  customResearchRequests,
  db,
  reportAccess,
  reportSubscriptions,
  reports,
} from "../../db/client.js"
import { audit } from "../../lib/audit.js"
import { forbidden, notFound } from "../../lib/errors.js"
import { extractIp } from "../../lib/ip.js"
import { authMiddleware, mfaAuthMiddleware } from "../../middleware/auth.js"
import {
  customRequestCreateSchema,
  listQuerySchema,
  subscriptionsPatchSchema,
} from "../../schemas/reports.js"

const app = new Hono()

function requireClient(c: import("hono").Context) {
  const client = c.get("client")
  if (!client) throw forbidden("This endpoint is for client users only")
  return client
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/reports
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Paginated, filterable list. Joined to `report_access` so the response
 * includes per-row `isBookmarked` + `readCount`.
 *
 * NB: order is `published_at DESC` — drafts are filtered out at the WHERE.
 */
app.get("/", authMiddleware, async (c) => {
  const client = requireClient(c)
  const query = listQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const conditions: SQL[] = [
    eq(reports.isDraft, false),
    sql`${reports.publishedAt} is not null`,
  ]
  // Visibility: firm-wide OR mine.
  const scopeCondition = or(
    isNull(reports.clientId),
    eq(reports.clientId, client.id),
  )
  if (scopeCondition) conditions.push(scopeCondition)

  if (query.type) conditions.push(eq(reports.reportType, query.type))
  if (query.scope === "mine") conditions.push(eq(reports.clientId, client.id))
  if (query.scope === "firm") conditions.push(isNull(reports.clientId))

  // Subquery joined for read state. Drizzle's leftJoin keeps things explicit.
  const rows = await db
    .select({
      r: reports,
      access: reportAccess,
    })
    .from(reports)
    .leftJoin(
      reportAccess,
      and(
        eq(reportAccess.reportId, reports.id),
        eq(reportAccess.clientId, client.id),
      ),
    )
    .where(and(...conditions))
    .orderBy(desc(reports.publishedAt))
    .limit(query.limit)
    .offset(query.offset)

  // bookmarked filter is post-join (would need a CTE to do as WHERE; cheap on
  // pages of 50–200).
  const filtered = query.bookmarked
    ? rows.filter((row) => row.access?.isBookmarked === true)
    : rows

  return c.json({
    ok: true,
    reports: filtered.map((row) => ({
      ...shapeReport(row.r),
      readCount: row.access?.readCount ?? 0,
      isBookmarked: row.access?.isBookmarked ?? false,
      lastReadAt: row.access?.lastReadAt ?? null,
    })),
    limit: query.limit,
    offset: query.offset,
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/reports/subscriptions
// PATCH /api/v1/reports/subscriptions
// ═══════════════════════════════════════════════════════════════════════════
//
// IMPORTANT: register these BEFORE `/:id` so Hono's static-segment routing
// doesn't treat "subscriptions" as an :id. Same applies to custom-requests.

app.get("/subscriptions", authMiddleware, async (c) => {
  const client = requireClient(c)
  const rows = await db
    .select()
    .from(reportSubscriptions)
    .where(eq(reportSubscriptions.clientId, client.id))
  return c.json({ ok: true, subscriptions: rows })
})

app.patch("/subscriptions", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = subscriptionsPatchSchema.parse(await c.req.json())

  // Per-entry upsert. We could batch into a single ON CONFLICT, but the
  // input is bounded (5 report types max) so a sequential loop is fine.
  for (const entry of body.subscriptions) {
    await db
      .insert(reportSubscriptions)
      .values({
        clientId: client.id,
        reportType: entry.reportType,
        channels: entry.channels,
      })
      .onConflictDoUpdate({
        target: [reportSubscriptions.clientId, reportSubscriptions.reportType],
        set: { channels: entry.channels },
      })
  }

  await audit({
    action: "reports.subscriptions.update",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    metadata: { entries: body.subscriptions.length },
  })

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/reports/custom-requests
// POST /api/v1/reports/custom-requests
// ═══════════════════════════════════════════════════════════════════════════

app.get("/custom-requests", authMiddleware, async (c) => {
  const client = requireClient(c)
  const rows = await db
    .select()
    .from(customResearchRequests)
    .where(eq(customResearchRequests.clientId, client.id))
    .orderBy(desc(customResearchRequests.submittedAt))
  return c.json({ ok: true, requests: rows })
})

app.post("/custom-requests", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = customRequestCreateSchema.parse(await c.req.json())

  const [created] = await db
    .insert(customResearchRequests)
    .values({
      clientId: client.id,
      userId: user.id,
      projectType: body.projectType,
      workingTitle: body.workingTitle ?? null,
      question: body.question,
      linkedTickers: body.linkedTickers ?? null,
      capitalAtStake: body.capitalAtStake?.toString() ?? null,
      timelinePref: body.timelinePref ?? null,
      referenceMaterials: body.referenceMaterials ?? null,
    })
    .returning({ id: customResearchRequests.id })

  await audit({
    action: "reports.custom_request.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "custom_research_request",
    resourceId: created!.id,
    metadata: {
      projectType: body.projectType,
      capitalAtStake: body.capitalAtStake ?? null,
      timelinePref: body.timelinePref ?? null,
    },
  })

  return c.json({ ok: true, id: created!.id }, 201)
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/reports/:id
// ═══════════════════════════════════════════════════════════════════════════

app.get("/:id", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const id = c.req.param("id")

  const report = await loadVisibleReport(id, client.id)

  // Upsert read state. ON CONFLICT (report_id, client_id) → bump count + ts.
  await db
    .insert(reportAccess)
    .values({
      reportId: report.id,
      clientId: client.id,
      userId: user.id,
      readCount: 1,
    })
    .onConflictDoUpdate({
      target: [reportAccess.reportId, reportAccess.clientId],
      set: {
        lastReadAt: new Date(),
        readCount: sql`${reportAccess.readCount} + 1`,
        userId: user.id,
      },
    })

  // Re-fetch the access row so we can include its current state (cheaper
  // than parsing the upsert return).
  const access = await db.query.reportAccess.findFirst({
    where: and(
      eq(reportAccess.reportId, report.id),
      eq(reportAccess.clientId, client.id),
    ),
  })

  return c.json({
    ok: true,
    report: shapeReport(report, /* includeBody */ true),
    access: access
      ? {
          firstReadAt: access.firstReadAt,
          lastReadAt: access.lastReadAt,
          readCount: access.readCount,
          isBookmarked: access.isBookmarked,
          bookmarkedAt: access.bookmarkedAt,
        }
      : null,
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// POST/DELETE /api/v1/reports/:id/bookmark
// ═══════════════════════════════════════════════════════════════════════════

app.post("/:id/bookmark", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const id = c.req.param("id")

  const report = await loadVisibleReport(id, client.id)

  await db
    .insert(reportAccess)
    .values({
      reportId: report.id,
      clientId: client.id,
      userId: user.id,
      isBookmarked: true,
      bookmarkedAt: new Date(),
    })
    .onConflictDoUpdate({
      target: [reportAccess.reportId, reportAccess.clientId],
      set: { isBookmarked: true, bookmarkedAt: new Date() },
    })

  return c.json({ ok: true, bookmarked: true })
})

app.delete("/:id/bookmark", authMiddleware, async (c) => {
  const client = requireClient(c)
  const id = c.req.param("id")

  // Don't fail if no row exists — the user just isn't bookmarked, that's fine.
  const report = await loadVisibleReport(id, client.id)

  await db
    .update(reportAccess)
    .set({ isBookmarked: false, bookmarkedAt: null })
    .where(
      and(
        eq(reportAccess.reportId, report.id),
        eq(reportAccess.clientId, client.id),
      ),
    )

  return c.json({ ok: true, bookmarked: false })
})

export default app

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Load a report and verify the caller can see it. Returns 404 for any of
 * "not found", "draft", "scoped to a different client" — never differentiates,
 * to avoid leaking the existence of other clients' reports.
 */
async function loadVisibleReport(id: string, clientId: string) {
  const report = await db.query.reports.findFirst({
    where: eq(reports.id, id),
  })
  if (!report) throw notFound("Report not found")
  if (report.isDraft || !report.publishedAt) {
    throw notFound("Report not found")
  }
  if (report.clientId !== null && report.clientId !== clientId) {
    throw notFound("Report not found")
  }
  return report
}

function shapeReport(
  r: typeof reports.$inferSelect,
  includeBody = false,
) {
  const base = {
    id: r.id,
    reportType: r.reportType,
    title: r.title,
    subtitle: r.subtitle,
    authorAdvisorId: r.authorAdvisorId,
    clientId: r.clientId,
    pages: r.pages,
    chartsCount: r.chartsCount,
    tablesCount: r.tablesCount,
    readTimeMin: r.readTimeMin,
    attachments: r.attachments,
    pdfUrl: r.pdfUrl,
    pdfSha256: r.pdfSha256,
    publishedAt: r.publishedAt,
    isFirmWide: r.clientId === null,
  }
  return includeBody
    ? { ...base, bodyMd: r.bodyMd, bodyFormat: r.bodyFormat }
    : base
}
