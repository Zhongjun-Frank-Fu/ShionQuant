/**
 * /api/v1/communication/* — secure messaging + advisor meeting booking.
 *
 * Threads:
 *   - One thread per (clientId, advisorId, subject) — but no UNIQUE constraint;
 *     re-using a subject just makes a new thread.
 *   - `unread_count_client` is what the user sees as "you have N unread".
 *     Bumped when an advisor message lands, zeroed by POST /:id/read.
 *   - `unread_count_advisor` is the mirror — bumped when client sends, zeroed
 *     by the advisor side (out-of-scope here).
 *
 * Messages:
 *   - `senderUserId` set when the client sends, `senderAdvisorId` when an
 *     advisor sends. They're mutually exclusive.
 *   - Message ordering: `sent_at` (server-stamped). Display oldest-first.
 *
 * Meetings:
 *   - Auto-link to a calendar event of `eventType="advisor_call"`,
 *     `source="advisor"`. The event is the canonical place schedules show up,
 *     including the ICS feed.
 *   - Cancellation policy: ≥24h ahead (returns 409 closer than that — call
 *     the advisor instead).
 *   - Race-prone: two clients booking the same slot at the same instant could
 *     both succeed (we don't lock). For a small advisor count this is fine;
 *     enforce later via a UNIQUE on (advisorId, scheduledAt) if it bites.
 *
 * Auth posture:
 *   `authMiddleware` everywhere — these are routine reads/writes.
 *   Considered MFA-gating meeting booking, but it's a low-stakes operation
 *   compared to the things gated by mfaAuthMiddleware (KYC, custom requests).
 */

import { and, asc, count, desc, eq, gte, lte, or, sql, type SQL } from "drizzle-orm"
import { Hono } from "hono"

import {
  advisors,
  db,
  events,
  meetingBookings,
  messageThreads,
  messages,
} from "../../db/client.js"
import { audit } from "../../lib/audit.js"
import {
  generateSlots,
  type BusyMeeting,
} from "../../lib/availability.js"
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
} from "../../lib/errors.js"
import { extractIp } from "../../lib/ip.js"
import { authMiddleware } from "../../middleware/auth.js"
import {
  availabilityQuerySchema,
  meetingCreateSchema,
  messageCreateSchema,
  threadCreateSchema,
  threadDetailQuerySchema,
  threadsListQuerySchema,
} from "../../schemas/communication.js"

const app = new Hono()

app.use("*", authMiddleware)

function requireClient(c: import("hono").Context) {
  const client = c.get("client")
  if (!client) throw forbidden("This endpoint is for client users only")
  return client
}

// ═══════════════════════════════════════════════════════════════════════════
// THREADS
// ═══════════════════════════════════════════════════════════════════════════

app.get("/threads", async (c) => {
  const client = requireClient(c)
  const query = threadsListQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const conditions: SQL[] = [eq(messageThreads.clientId, client.id)]
  if (!query.archived) conditions.push(eq(messageThreads.isArchived, false))
  if (query.advisorId) conditions.push(eq(messageThreads.advisorId, query.advisorId))

  const rows = await db
    .select({
      thread: messageThreads,
      advisor: advisors,
    })
    .from(messageThreads)
    .leftJoin(advisors, eq(advisors.id, messageThreads.advisorId))
    .where(and(...conditions))
    .orderBy(desc(messageThreads.lastMessageAt))
    .limit(query.limit)
    .offset(query.offset)

  return c.json({
    ok: true,
    threads: rows.map(({ thread, advisor }) => ({
      id: thread.id,
      subject: thread.subject,
      lastMessageAt: thread.lastMessageAt,
      unreadCountClient: thread.unreadCountClient,
      isArchived: thread.isArchived,
      advisor: advisor
        ? {
            id: advisor.id,
            fullName: advisor.fullName,
            initials: advisor.initials,
            role: advisor.role,
          }
        : null,
      createdAt: thread.createdAt,
    })),
  })
})

app.get("/threads/:id", async (c) => {
  const client = requireClient(c)
  const id = c.req.param("id")
  const query = threadDetailQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const thread = await loadOwnedThread(id, client.id)

  const order = query.order === "desc" ? desc(messages.sentAt) : asc(messages.sentAt)
  const [messageRows, [countRow]] = await Promise.all([
    db
      .select()
      .from(messages)
      .where(eq(messages.threadId, id))
      .orderBy(order)
      .limit(query.limit)
      .offset(query.offset),
    db
      .select({ value: count() })
      .from(messages)
      .where(eq(messages.threadId, id)),
  ])

  return c.json({
    ok: true,
    thread: shapeThread(thread),
    messages: messageRows.map(shapeMessage),
    total: countRow?.value ?? 0,
    limit: query.limit,
    offset: query.offset,
  })
})

app.post("/threads", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = threadCreateSchema.parse(await c.req.json())

  // Pick advisor: explicit > primaryAdvisor. 400 if neither present.
  const advisorId = body.advisorId ?? client.primaryAdvisorId
  if (!advisorId) {
    throw badRequest(
      "No advisor specified and client has no primaryAdvisor set",
    )
  }
  // Validate the advisor exists and is active.
  const advisor = await db.query.advisors.findFirst({
    where: and(eq(advisors.id, advisorId), eq(advisors.isActive, true)),
  })
  if (!advisor) throw notFound("Advisor not found")

  const now = new Date()
  const [thread] = await db
    .insert(messageThreads)
    .values({
      clientId: client.id,
      advisorId: advisor.id,
      subject: body.subject,
      lastMessageAt: now,
      unreadCountClient: 0,
      unreadCountAdvisor: 1,
    })
    .returning()
  if (!thread) throw conflict("Thread insert returned no row")

  await db.insert(messages).values({
    threadId: thread.id,
    senderUserId: user.id,
    senderAdvisorId: null,
    body: body.body,
    urgency: body.urgency,
    sentAt: now,
  })

  await audit({
    action: "communication.thread.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "message_thread",
    resourceId: thread.id,
    metadata: { advisorId: advisor.id, urgency: body.urgency },
  })

  return c.json({ ok: true, id: thread.id }, 201)
})

app.post("/threads/:id/messages", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const thread = await loadOwnedThread(id, client.id)
  if (thread.isArchived) {
    throw conflict("Thread is archived; start a new one")
  }
  const body = messageCreateSchema.parse(await c.req.json())

  const now = new Date()
  const [created] = await db
    .insert(messages)
    .values({
      threadId: thread.id,
      senderUserId: user.id,
      senderAdvisorId: null,
      body: body.body,
      urgency: body.urgency,
      attachments: body.attachments ?? null,
      sentAt: now,
    })
    .returning({ id: messages.id })

  // Bump the advisor's unread counter + lastMessageAt — single UPDATE.
  await db
    .update(messageThreads)
    .set({
      lastMessageAt: now,
      unreadCountAdvisor: sql`${messageThreads.unreadCountAdvisor} + 1`,
    })
    .where(eq(messageThreads.id, thread.id))

  await audit({
    action: "communication.message.send",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "message",
    resourceId: created!.id,
    metadata: {
      threadId: thread.id,
      urgency: body.urgency,
      attachmentCount: body.attachments?.length ?? 0,
    },
  })

  return c.json({ ok: true, id: created!.id }, 201)
})

app.post("/threads/:id/read", async (c) => {
  const client = requireClient(c)
  const id = c.req.param("id")

  const thread = await loadOwnedThread(id, client.id)
  if (thread.unreadCountClient === 0) {
    return c.json({ ok: true, alreadyRead: true })
  }

  // Mark unread advisor messages as read AND zero the counter.
  const now = new Date()
  await db
    .update(messages)
    .set({ readAt: now })
    .where(
      and(
        eq(messages.threadId, thread.id),
        sql`${messages.senderAdvisorId} is not null`,
        sql`${messages.readAt} is null`,
      ),
    )
  await db
    .update(messageThreads)
    .set({ unreadCountClient: 0 })
    .where(eq(messageThreads.id, thread.id))

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// MEETINGS
// ═══════════════════════════════════════════════════════════════════════════

app.get("/advisor/availability", async (c) => {
  const client = requireClient(c)
  const query = availabilityQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const advisorId = query.advisorId ?? client.primaryAdvisorId
  if (!advisorId) {
    throw badRequest("No advisor specified and client has no primaryAdvisor set")
  }
  const advisor = await db.query.advisors.findFirst({
    where: and(eq(advisors.id, advisorId), eq(advisors.isActive, true)),
  })
  if (!advisor) throw notFound("Advisor not found")

  const from = query.from ? new Date(query.from) : new Date()
  const to = query.to
    ? new Date(query.to)
    : new Date(Date.now() + 14 * 24 * 60 * 60_000)

  // Pull existing meetings for this advisor in the window. Include 1 hour
  // of slack on either side to catch overlapping meetings.
  const slack = 60 * 60_000
  const lower = new Date(from.getTime() - slack)
  const upper = new Date(to.getTime() + slack)

  const busyRows = await db
    .select({
      scheduledAt: meetingBookings.scheduledAt,
      durationMin: meetingBookings.durationMin,
    })
    .from(meetingBookings)
    .where(
      and(
        eq(meetingBookings.advisorId, advisorId),
        or(
          eq(meetingBookings.status, "confirmed"),
          eq(meetingBookings.status, "pending"),
        ),
        gte(meetingBookings.scheduledAt, lower),
        lte(meetingBookings.scheduledAt, upper),
      ),
    )

  const busy: BusyMeeting[] = busyRows.map((r) => ({
    scheduledAt: r.scheduledAt,
    durationMin: r.durationMin,
  }))

  const slots = generateSlots({
    from,
    to,
    advisorTimezone: advisor.timezone,
    slotMinutes: query.slotMinutes,
    busy,
  })

  return c.json({
    ok: true,
    advisor: {
      id: advisor.id,
      fullName: advisor.fullName,
      timezone: advisor.timezone,
    },
    from: from.toISOString(),
    to: to.toISOString(),
    slots,
  })
})

app.post("/meetings", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = meetingCreateSchema.parse(await c.req.json())

  const advisorId = body.advisorId ?? client.primaryAdvisorId
  if (!advisorId) {
    throw badRequest("No advisor specified and client has no primaryAdvisor set")
  }
  const advisor = await db.query.advisors.findFirst({
    where: and(eq(advisors.id, advisorId), eq(advisors.isActive, true)),
  })
  if (!advisor) throw notFound("Advisor not found")

  const scheduledAt = new Date(body.scheduledAt)
  if (scheduledAt.getTime() <= Date.now() + 60 * 60_000) {
    throw badRequest("Meeting must be at least 1 hour in the future")
  }
  const endsAt = new Date(scheduledAt.getTime() + body.durationMin * 60_000)

  // Soft conflict check — race-prone but cheap. The advisor has the source
  // of truth on their canonical calendar; client UI can recover gracefully.
  const conflicts = await db
    .select({ id: meetingBookings.id })
    .from(meetingBookings)
    .where(
      and(
        eq(meetingBookings.advisorId, advisorId),
        or(
          eq(meetingBookings.status, "confirmed"),
          eq(meetingBookings.status, "pending"),
        ),
        // Overlap: existing.scheduledAt < endsAt AND existing.endsAt > scheduledAt.
        // We don't have endsAt as a column; approximate with a date range on
        // scheduledAt and rely on the small slot grid.
        gte(meetingBookings.scheduledAt, new Date(scheduledAt.getTime() - 2 * 60 * 60_000)),
        lte(meetingBookings.scheduledAt, endsAt),
      ),
    )
    .limit(1)
  if (conflicts.length > 0) {
    throw conflict("That slot is no longer available")
  }

  // Create the calendar event first so we can reference it.
  const [eventRow] = await db
    .insert(events)
    .values({
      clientId: client.id,
      eventType: "advisor_call",
      source: "advisor",
      title: `Meeting with ${advisor.fullName}`,
      description: body.agenda ?? null,
      startsAt: scheduledAt,
      endsAt,
      isAllDay: false,
      displayTz: advisor.timezone,
      isCritical: false,
      metadata: { meetingType: body.meetingType },
    })
    .returning({ id: events.id })

  const [meeting] = await db
    .insert(meetingBookings)
    .values({
      clientId: client.id,
      advisorId: advisor.id,
      scheduledAt,
      durationMin: body.durationMin,
      meetingType: body.meetingType,
      agenda: body.agenda ?? null,
      status: "confirmed",
      relatedEventId: eventRow!.id,
    })
    .returning({ id: meetingBookings.id })

  await audit({
    action: "communication.meeting.book",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "meeting_booking",
    resourceId: meeting!.id,
    metadata: {
      advisorId: advisor.id,
      scheduledAt: scheduledAt.toISOString(),
      durationMin: body.durationMin,
      meetingType: body.meetingType,
      eventId: eventRow!.id,
    },
  })

  return c.json(
    {
      ok: true,
      id: meeting!.id,
      eventId: eventRow!.id,
      scheduledAt,
      endsAt,
      advisorId: advisor.id,
    },
    201,
  )
})

app.delete("/meetings/:id", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const meeting = await db.query.meetingBookings.findFirst({
    where: and(
      eq(meetingBookings.id, id),
      eq(meetingBookings.clientId, client.id),
    ),
  })
  if (!meeting) throw notFound("Meeting not found")
  if (meeting.status === "cancelled") {
    return c.json({ ok: true, alreadyCancelled: true })
  }

  // Cancellation window: must be ≥24h ahead.
  const HOURS_NOTICE = 24
  if (
    meeting.scheduledAt.getTime() - Date.now() <
    HOURS_NOTICE * 60 * 60_000
  ) {
    throw conflict(
      `Meetings within ${HOURS_NOTICE}h cannot be cancelled online — please contact your advisor directly`,
    )
  }

  await db
    .update(meetingBookings)
    .set({ status: "cancelled" })
    .where(eq(meetingBookings.id, id))

  // Soft-archive the linked calendar event so it disappears from /events.
  if (meeting.relatedEventId) {
    await db
      .update(events)
      .set({ isArchived: true, updatedAt: new Date() })
      .where(eq(events.id, meeting.relatedEventId))
  }

  await audit({
    action: "communication.meeting.cancel",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "meeting_booking",
    resourceId: id,
    metadata: {
      scheduledAt: meeting.scheduledAt.toISOString(),
      hoursAhead:
        (meeting.scheduledAt.getTime() - Date.now()) / (60 * 60_000),
    },
  })

  return c.json({ ok: true })
})

export default app

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

async function loadOwnedThread(id: string, clientId: string) {
  const thread = await db.query.messageThreads.findFirst({
    where: and(eq(messageThreads.id, id), eq(messageThreads.clientId, clientId)),
  })
  if (!thread) throw notFound("Thread not found")
  return thread
}

function shapeThread(t: typeof messageThreads.$inferSelect) {
  return {
    id: t.id,
    advisorId: t.advisorId,
    subject: t.subject,
    isArchived: t.isArchived,
    lastMessageAt: t.lastMessageAt,
    unreadCountClient: t.unreadCountClient,
    createdAt: t.createdAt,
  }
}

function shapeMessage(m: typeof messages.$inferSelect) {
  return {
    id: m.id,
    threadId: m.threadId,
    senderUserId: m.senderUserId,
    senderAdvisorId: m.senderAdvisorId,
    body: m.body,
    urgency: m.urgency,
    attachments: m.attachments,
    sentAt: m.sentAt,
    readAt: m.readAt,
    /** Convenience flag the frontend uses to align bubbles left/right. */
    fromAdvisor: m.senderAdvisorId !== null,
  }
}
