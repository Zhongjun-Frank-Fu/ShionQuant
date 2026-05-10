/**
 * /api/v1/schedules/* — events + ICS feed.
 *
 * Routes:
 *   GET    /events                 list (date range, type filter, ticker)
 *   GET    /events/:id             single event detail
 *   POST   /events                 create personal event (forces source=personal)
 *   PATCH  /events/:id             edit personal event (rejects non-personal)
 *   DELETE /events/:id             soft-archive personal event
 *   GET    /settings               reminder defaults from `profiles`
 *   PATCH  /settings               update them
 *   POST   /ics/rotate             new icsToken — invalidates old feed URL
 *   GET    /ics/:token             public ICS feed (NO auth — token-gated)
 *
 * Auth posture:
 *   Per-route `authMiddleware`. The ICS feed bypasses it because calendar
 *   apps subscribe with a URL alone — token IS the auth.
 *
 * Why personal-only mutations:
 *   Broker / advisor / macro events come from out-of-band sources (M5+ jobs).
 *   Letting users edit them would create reconciliation headaches when the
 *   source pushes a refresh. Users CAN soft-archive these via DELETE, which
 *   hides them from their view without touching the canonical row.
 *
 * NB: Soft-archive uses `is_archived = true`. Reminders attached to archived
 *   events stay queued (the dispatcher checks the parent's `is_archived`).
 */

import { randomBytes } from "node:crypto"
import { and, asc, eq, gte, inArray, lte, type SQL } from "drizzle-orm"
import { Hono } from "hono"

import {
  calendarSubscriptions,
  db,
  eventReminders,
  events,
  positions,
  profiles,
} from "../../db/client.js"
import { audit } from "../../lib/audit.js"
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
} from "../../lib/errors.js"
import { buildIcsCalendar, type IcsEvent } from "../../lib/ics.js"
import { extractIp } from "../../lib/ip.js"
import { authMiddleware } from "../../middleware/auth.js"
import {
  eventCreateSchema,
  eventPatchSchema,
  eventsListQuerySchema,
  scheduleSettingsPatchSchema,
} from "../../schemas/schedules.js"

const app = new Hono()

function requireClient(c: import("hono").Context) {
  const client = c.get("client")
  if (!client) throw forbidden("This endpoint is for client users only")
  return client
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/schedules/events
// ═══════════════════════════════════════════════════════════════════════════

app.get("/events", authMiddleware, async (c) => {
  const client = requireClient(c)
  const query = eventsListQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  // Sensible defaults so the calendar view doesn't load every event ever.
  const from = query.from
    ? new Date(query.from)
    : new Date(Date.now() - 30 * 24 * 60 * 60_000)
  const to = query.to
    ? new Date(query.to)
    : new Date(Date.now() + 365 * 24 * 60 * 60_000)

  const conditions: SQL[] = [
    eq(events.clientId, client.id),
    gte(events.startsAt, from),
    lte(events.startsAt, to),
  ]
  if (!query.archived) conditions.push(eq(events.isArchived, false))
  if (query.types && query.types.length > 0) {
    conditions.push(inArray(events.eventType, query.types))
  }
  if (query.ticker) conditions.push(eq(events.ticker, query.ticker.toUpperCase()))

  const rows = await db
    .select()
    .from(events)
    .where(and(...conditions))
    .orderBy(asc(events.startsAt))
    .limit(query.limit)
    .offset(query.offset)

  return c.json({
    ok: true,
    from: from.toISOString(),
    to: to.toISOString(),
    events: rows.map(shapeEvent),
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/schedules/events/:id
// ═══════════════════════════════════════════════════════════════════════════

app.get("/events/:id", authMiddleware, async (c) => {
  const client = requireClient(c)
  const id = c.req.param("id")
  const ev = await loadOwnedEvent(id, client.id)

  // Pull reminders + linked position context for the detail page.
  const [reminderRows, positionRow] = await Promise.all([
    db.select().from(eventReminders).where(eq(eventReminders.eventId, id)),
    ev.positionId
      ? db.select().from(positions).where(eq(positions.id, ev.positionId)).limit(1)
      : Promise.resolve([]),
  ])

  return c.json({
    ok: true,
    event: shapeEvent(ev),
    reminders: reminderRows,
    position: positionRow[0] ?? null,
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/schedules/events  — personal events only
// ═══════════════════════════════════════════════════════════════════════════

app.post("/events", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = eventCreateSchema.parse(await c.req.json())

  const [created] = await db
    .insert(events)
    .values({
      clientId: client.id,
      eventType: "personal",
      source: "personal",
      title: body.title,
      description: body.description ?? null,
      startsAt: new Date(body.startsAt),
      endsAt: body.endsAt ? new Date(body.endsAt) : null,
      isAllDay: body.isAllDay,
      displayTz: body.displayTz ?? null,
      isCritical: body.isCritical,
      rrule: body.rrule ?? null,
    })
    .returning({ id: events.id })

  // Reminders — best-effort; failures don't block the event.
  if (body.reminders && body.reminders.length > 0) {
    await db.insert(eventReminders).values(
      body.reminders.map((r) => ({
        eventId: created!.id,
        channel: r.channel,
        leadMinutes: r.leadMinutes,
      })),
    )
  }

  await audit({
    action: "schedules.event.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "event",
    resourceId: created!.id,
  })

  return c.json({ ok: true, id: created!.id }, 201)
})

// ═══════════════════════════════════════════════════════════════════════════
// PATCH /api/v1/schedules/events/:id  — personal events only
// ═══════════════════════════════════════════════════════════════════════════

app.patch("/events/:id", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const ev = await loadOwnedEvent(id, client.id)
  if (ev.source !== "personal") {
    throw conflict(
      `Cannot edit ${ev.source}-sourced event. Personal events only.`,
    )
  }

  const body = eventPatchSchema.parse(await c.req.json())

  const update: Record<string, unknown> = { updatedAt: new Date() }
  if ("title" in body && body.title !== undefined) update.title = body.title
  if ("description" in body) update.description = body.description ?? null
  if ("startsAt" in body && body.startsAt !== undefined) update.startsAt = new Date(body.startsAt)
  if ("endsAt" in body) update.endsAt = body.endsAt ? new Date(body.endsAt) : null
  if ("isAllDay" in body && body.isAllDay !== undefined) update.isAllDay = body.isAllDay
  if ("displayTz" in body) update.displayTz = body.displayTz ?? null
  if ("isCritical" in body && body.isCritical !== undefined) update.isCritical = body.isCritical
  if ("rrule" in body) update.rrule = body.rrule ?? null

  if (Object.keys(update).length === 1) {
    throw badRequest("No fields to update")
  }

  await db.update(events).set(update).where(eq(events.id, id))

  await audit({
    action: "schedules.event.update",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "event",
    resourceId: id,
    metadata: { changedFields: Object.keys(update).filter((k) => k !== "updatedAt") },
  })

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// DELETE /api/v1/schedules/events/:id  — soft archive
// ═══════════════════════════════════════════════════════════════════════════

app.delete("/events/:id", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const ev = await loadOwnedEvent(id, client.id)
  if (ev.isArchived) {
    return c.json({ ok: true, alreadyArchived: true })
  }

  await db
    .update(events)
    .set({ isArchived: true, updatedAt: new Date() })
    .where(eq(events.id, id))

  await audit({
    action: "schedules.event.archive",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "event",
    resourceId: id,
    metadata: { source: ev.source, eventType: ev.eventType },
  })

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET / PATCH /api/v1/schedules/settings
// ═══════════════════════════════════════════════════════════════════════════

const DEFAULT_LEAD_MINUTES = 60
const DEFAULT_CHANNELS = ["email"] as const

app.get("/settings", authMiddleware, async (c) => {
  const client = requireClient(c)

  const profile = await db.query.profiles.findFirst({
    where: eq(profiles.clientId, client.id),
  })
  const sub = await db.query.calendarSubscriptions.findFirst({
    where: eq(calendarSubscriptions.clientId, client.id),
  })

  return c.json({
    ok: true,
    settings: {
      preferredChannel: profile?.preferredChannel ?? "email",
      quietHours: profile?.quietHoursLocal ?? null,
      defaultLeadMinutes: DEFAULT_LEAD_MINUTES,
      defaultChannels: DEFAULT_CHANNELS,
    },
    icsSubscription: sub
      ? {
          // Build the URL so the frontend has it ready for "Copy" buttons.
          // Don't expose the token in the GET — only when freshly rotated.
          hasToken: true,
          lastFetchedAt: sub.lastFetchedAt,
          fetchCount: sub.fetchCount,
          createdAt: sub.createdAt,
        }
      : { hasToken: false },
  })
})

app.patch("/settings", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = scheduleSettingsPatchSchema.parse(await c.req.json())

  const profile = await db.query.profiles.findFirst({
    where: eq(profiles.clientId, client.id),
  })
  if (!profile) {
    throw conflict("Profile required before updating schedule settings")
  }

  const update: Record<string, unknown> = { updatedAt: new Date() }
  if ("preferredChannel" in body && body.preferredChannel) {
    update.preferredChannel = body.preferredChannel
  }
  if ("quietHours" in body) {
    update.quietHoursLocal = body.quietHours ?? null
  }

  if (Object.keys(update).length === 1) {
    throw badRequest("No fields to update")
  }

  await db.update(profiles).set(update).where(eq(profiles.clientId, client.id))

  await audit({
    action: "schedules.settings.update",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    metadata: { changedFields: Object.keys(update).filter((k) => k !== "updatedAt") },
  })

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/schedules/ics/rotate
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Rotate the ICS token — invalidates any previously-issued feed URL.
 * Returns the new token + a ready-to-paste URL ONCE; the GET /settings
 * endpoint never exposes it again. The user should store it.
 */
app.post("/ics/rotate", authMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const newToken = randomBytes(24).toString("base64url")

  // Upsert — first-time callers create the row, repeat callers rotate.
  const existing = await db.query.calendarSubscriptions.findFirst({
    where: eq(calendarSubscriptions.clientId, client.id),
  })
  if (existing) {
    await db
      .update(calendarSubscriptions)
      .set({ icsToken: newToken })
      .where(eq(calendarSubscriptions.clientId, client.id))
  } else {
    await db.insert(calendarSubscriptions).values({
      clientId: client.id,
      icsToken: newToken,
    })
  }

  await audit({
    action: "schedules.ics.rotate",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "calendar_subscription",
    resourceId: client.id,
  })

  // Build absolute URL using the request's host. Frontend can override.
  const url = new URL(c.req.url)
  const feedUrl = `${url.protocol}//${url.host}/api/v1/schedules/ics/${newToken}`

  return c.json({ ok: true, token: newToken, feedUrl })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/schedules/ics/:token  — PUBLIC, no auth
// ═══════════════════════════════════════════════════════════════════════════

app.get("/ics/:token", async (c) => {
  const token = c.req.param("token")
  if (!token || token.length < 16) {
    // Don't 404 — calendar apps may probe; return an empty calendar to keep
    // them happy without leaking whether the token format is valid.
    return emptyCalendar(c)
  }

  const sub = await db.query.calendarSubscriptions.findFirst({
    where: eq(calendarSubscriptions.icsToken, token),
  })
  if (!sub) {
    return emptyCalendar(c)
  }

  // Pull events for this client. Use a wide window so calendar apps see past
  // (within 1 yr) and future (within 2 yrs) events.
  const lower = new Date(Date.now() - 365 * 24 * 60 * 60_000)
  const upper = new Date(Date.now() + 2 * 365 * 24 * 60 * 60_000)

  const rows = await db
    .select()
    .from(events)
    .where(
      and(
        eq(events.clientId, sub.clientId),
        eq(events.isArchived, false),
        gte(events.startsAt, lower),
        lte(events.startsAt, upper),
      ),
    )
    .orderBy(asc(events.startsAt))

  const ics = buildIcsCalendar({
    calendarName: "Shion Quant Schedule",
    timezone: "UTC",
    events: rows.map((r): IcsEvent => ({
      id: r.id,
      title: r.title,
      description: r.description,
      location:
        (r.metadata as { location?: string } | null)?.location ?? null,
      startsAt: r.startsAt,
      endsAt: r.endsAt,
      isAllDay: r.isAllDay,
      eventType: r.eventType,
      rrule: r.rrule,
      isCritical: r.isCritical,
    })),
  })

  // Bump usage counters — fire-and-forget, don't slow the feed.
  void db
    .update(calendarSubscriptions)
    .set({
      lastFetchedAt: new Date(),
      fetchCount: (sub.fetchCount ?? 0) + 1,
    })
    .where(eq(calendarSubscriptions.clientId, sub.clientId))
    .catch((err: unknown) =>
      console.error("[schedules] failed to bump fetch counters", err),
    )

  c.header("Content-Type", "text/calendar; charset=utf-8")
  c.header("Cache-Control", "private, max-age=300") // 5-min cache
  return c.body(ics)
})

export default app

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

async function loadOwnedEvent(id: string, clientId: string) {
  const ev = await db.query.events.findFirst({
    where: and(eq(events.id, id), eq(events.clientId, clientId)),
  })
  if (!ev) throw notFound("Event not found")
  return ev
}

function shapeEvent(e: typeof events.$inferSelect) {
  return {
    id: e.id,
    eventType: e.eventType,
    source: e.source,
    title: e.title,
    description: e.description,
    ticker: e.ticker,
    positionId: e.positionId,
    startsAt: e.startsAt,
    endsAt: e.endsAt,
    isAllDay: e.isAllDay,
    displayTz: e.displayTz,
    isCritical: e.isCritical,
    isArchived: e.isArchived,
    rrule: e.rrule,
    metadata: e.metadata,
  }
}

function emptyCalendar(c: import("hono").Context) {
  const ics = buildIcsCalendar({ calendarName: "Shion Quant Schedule", events: [] })
  c.header("Content-Type", "text/calendar; charset=utf-8")
  c.header("Cache-Control", "private, max-age=60")
  return c.body(ics)
}
