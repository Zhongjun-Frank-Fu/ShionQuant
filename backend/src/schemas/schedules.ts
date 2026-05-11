/**
 * Zod schemas for /api/v1/schedules/*.
 */

import { z } from "zod"

// Mirror schema.ts unions — keep these in lockstep.
const EVENT_TYPE = [
  "option_expiry",
  "bond_coupon",
  "earnings",
  "dividend",
  "macro",
  "advisor_call",
  "report_delivery",
  "rebalance",
  "compliance_renewal",
  "personal",
] as const

const REMINDER_CHANNEL = ["email", "push", "sms"] as const

// ─── Events list query ────────────────────────────────────────────────────

const isoDateTime = z.string().datetime({ offset: true })

export const eventsListQuerySchema = z.object({
  /** Inclusive start, ISO-8601 with offset. Default: 30 days ago. */
  from: isoDateTime.optional(),
  /** Exclusive end. Default: 1 year from now. */
  to: isoDateTime.optional(),
  /** Comma-separated event types to filter to. */
  types: z
    .string()
    .optional()
    .transform((s) => (s ? s.split(",").map((t) => t.trim()).filter(Boolean) : null))
    .pipe(z.array(z.enum(EVENT_TYPE)).nullable())
    .optional(),
  ticker: z.string().min(1).max(20).optional(),
  archived: z
    .enum(["true", "false"])
    .optional()
    .default("false")
    .transform((v) => v === "true"),
  limit: z.coerce.number().int().min(1).max(500).default(200),
  offset: z.coerce.number().int().min(0).default(0),
})

// ─── Personal event create / patch ────────────────────────────────────────

export const eventCreateSchema = z
  .object({
    title: z.string().min(1).max(200).trim(),
    description: z.string().max(4000).optional(),
    startsAt: isoDateTime,
    endsAt: isoDateTime.optional(),
    isAllDay: z.boolean().default(false),
    /** IANA tz for display in clients that respect floating-time hints. */
    displayTz: z.string().min(1).max(64).optional(),
    isCritical: z.boolean().default(false),
    /** Free-form RRULE body (without the `RRULE:` prefix). */
    rrule: z.string().max(500).optional(),
    /** Array of `{channel, leadMinutes}` reminders to attach. */
    reminders: z
      .array(
        z.object({
          channel: z.enum(REMINDER_CHANNEL),
          leadMinutes: z.number().int().min(0).max(60 * 24 * 14),
        }),
      )
      .max(8)
      .optional(),
  })
  .strict()
  .refine(
    (v) => !v.endsAt || new Date(v.endsAt) > new Date(v.startsAt),
    { message: "endsAt must be after startsAt", path: ["endsAt"] },
  )

export const eventPatchSchema = z
  .object({
    title: z.string().min(1).max(200).trim().optional(),
    description: z.string().max(4000).nullable().optional(),
    startsAt: isoDateTime.optional(),
    endsAt: isoDateTime.nullable().optional(),
    isAllDay: z.boolean().optional(),
    displayTz: z.string().min(1).max(64).nullable().optional(),
    isCritical: z.boolean().optional(),
    rrule: z.string().max(500).nullable().optional(),
  })
  .strict()

// ─── Schedule settings ────────────────────────────────────────────────────
// Settings are surfaced from `profiles` (no extra table). Adding more
// schedule-only knobs (default lead minutes, etc.) should land as a single
// jsonb column on `calendar_subscriptions` rather than a new table.

const PREFERRED_CHANNEL = ["email", "portal", "whatsapp", "phone"] as const

export const scheduleSettingsPatchSchema = z
  .object({
    /** Reminder channel used for non-critical events (matches profiles.preferred_channel). */
    preferredChannel: z.enum(PREFERRED_CHANNEL).optional(),
    /** Quiet-hours window — reminders within this range are deferred to next morning. */
    quietHours: z
      .object({
        start: z.string().regex(/^\d{2}:\d{2}$/, "must be HH:MM"),
        end: z.string().regex(/^\d{2}:\d{2}$/, "must be HH:MM"),
        timezone: z.string().min(1).max(64),
      })
      .nullable()
      .optional(),
  })
  .strict()

// ─── Calendar preferences ────────────────────────────────────────────────
// Persisted as a jsonb blob on calendar_subscriptions.preferences. Each
// section is optional in the PATCH payload so the page can save incremental
// changes without re-sending the whole object.

const REMINDER_KEY = [
  "critical",
  "optionsEarnings",
  "advisorCalls",
  "personalEvents",
] as const

const reminderConfigSchema = z
  .object({
    leadMinutes: z.array(z.number().int().min(0).max(60 * 24 * 30)).max(8),
    email: z.boolean(),
    push: z.boolean(),
    sms: z.boolean(),
  })
  .strict()

export const calendarPreferencesPatchSchema = z
  .object({
    positionDerivedEvents: z
      .object({
        macroCalendar: z.boolean(),
        earnings: z.boolean(),
        heldPositions: z.boolean(),
        advisorTouchpoints: z.boolean(),
        reportDeliveries: z.boolean(),
        complianceRenewals: z.boolean(),
      })
      .partial()
      .strict()
      .optional(),
    reminders: z
      .record(z.enum(REMINDER_KEY), reminderConfigSchema)
      .optional(),
    display: z
      .object({
        timezone: z.string().min(1).max(64),
        weekStart: z.enum(["monday", "sunday"]),
        showPast14Days: z.boolean(),
        compactMode: z.boolean(),
      })
      .partial()
      .strict()
      .optional(),
  })
  .strict()
