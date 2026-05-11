/**
 * Zod schemas for /api/v1/communication/*.
 */

import { z } from "zod"

const URGENCY = ["routine", "soon", "urgent"] as const
const MEETING_TYPE = ["video", "phone", "in_person"] as const

// ─── Threads ──────────────────────────────────────────────────────────────

export const threadsListQuerySchema = z.object({
  archived: z
    .enum(["true", "false"])
    .optional()
    .default("false")
    .transform((v) => v === "true"),
  advisorId: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
})

export const threadDetailQuerySchema = z.object({
  /** Pagination over messages, oldest-first by default. */
  limit: z.coerce.number().int().min(1).max(200).default(100),
  offset: z.coerce.number().int().min(0).default(0),
  /** "asc" (oldest-first, default — natural reading order)
   *  or "desc" (newest-first, faster initial load on huge threads). */
  order: z.enum(["asc", "desc"]).optional().default("asc"),
})

export const threadCreateSchema = z
  .object({
    subject: z.string().min(1).max(200).trim(),
    /** First message body. Required — no empty threads. */
    body: z.string().min(1).max(20_000).trim(),
    urgency: z.enum(URGENCY).default("routine"),
    /** Defaults to client's primaryAdvisorId. */
    advisorId: z.string().uuid().optional(),
  })
  .strict()

export const messageCreateSchema = z
  .object({
    body: z.string().min(1).max(20_000).trim(),
    urgency: z.enum(URGENCY).default("routine"),
    /** Optional file attachments — list of {url, name, sizeBytes}. */
    attachments: z
      .array(
        z
          .object({
            url: z.string().url().max(500),
            name: z.string().min(1).max(200),
            sizeBytes: z.number().int().nonnegative().max(100 * 1024 * 1024),
          })
          .strict(),
      )
      .max(8)
      .optional(),
  })
  .strict()

// ─── Meetings ─────────────────────────────────────────────────────────────

export const availabilityQuerySchema = z.object({
  /** Inclusive ISO start. Default: now. */
  from: z.string().datetime({ offset: true }).optional(),
  /** Exclusive ISO end. Default: now + 14 days. */
  to: z.string().datetime({ offset: true }).optional(),
  /** Override default 60 min slot length. */
  slotMinutes: z.coerce.number().int().min(15).max(120).default(60),
  advisorId: z.string().uuid().optional(),
})

export const meetingCreateSchema = z
  .object({
    scheduledAt: z.string().datetime({ offset: true }),
    durationMin: z.number().int().min(15).max(180).default(60),
    meetingType: z.enum(MEETING_TYPE).default("video"),
    agenda: z.string().max(2000).optional(),
    advisorId: z.string().uuid().optional(),
  })
  .strict()

// ─── Contact Advisor — requests + slots ──────────────────────────────────
// New 2026-05. Lives in /communication/contact/* — see schema.ts admin
// section for the table shape (advisor_time_slots + advisor_contact_requests).

const REQUEST_TYPE = ["message", "call", "in_person"] as const
const SLOT_TYPE = ["call", "in_person"] as const

export const slotsQuerySchema = z.object({
  type: z.enum(SLOT_TYPE).optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  advisorId: z.string().uuid().optional(),
})

export const contactRequestCreateSchema = z
  .object({
    requestType: z.enum(REQUEST_TYPE),
    /** Free-form location. Required for in_person, optional for call (defaults
     *  to the linked slot's location), null for message. */
    location: z.string().min(1).max(200).nullable().optional(),
    /** ISO instant (call w/o slot, or in_person window start). */
    preferredStartsAt: z.string().datetime({ offset: true }).nullable().optional(),
    /** ISO instant (in_person window end). */
    preferredEndsAt: z.string().datetime({ offset: true }).nullable().optional(),
    /** Minutes. */
    durationMinutes: z.number().int().min(15).max(60 * 24 * 3).nullable().optional(),
    /** Subject + body for messages; agenda for call/in_person. */
    reason: z.string().min(1).max(4000),
    urgency: z.enum(URGENCY).nullable().optional(),
    /** When picking a specific call slot, link it here. */
    linkedSlotId: z.string().uuid().nullable().optional(),
    /** Co-submitters by display name (joint accounts). */
    submitters: z.array(z.string().min(1).max(120)).max(6).optional(),
    /** Free-form: { template?: string; videoTool?: string; attachments?: [...] }. */
    metadata: z.record(z.unknown()).optional(),
  })
  .strict()
  .refine(
    (v) => v.requestType !== "message" || (v.preferredStartsAt == null && v.linkedSlotId == null),
    { message: "Message requests cannot have preferredStartsAt or linkedSlotId", path: ["preferredStartsAt"] },
  )
  .refine(
    (v) => v.requestType !== "in_person" || v.preferredStartsAt != null,
    { message: "In-person requests must include preferredStartsAt", path: ["preferredStartsAt"] },
  )

export const contactRequestsListQuerySchema = z.object({
  status: z
    .enum(["pending", "acknowledged", "confirmed", "declined", "completed", "cancelled"])
    .optional(),
  type: z.enum(REQUEST_TYPE).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
})
