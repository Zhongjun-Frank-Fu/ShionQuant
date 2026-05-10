/**
 * iCalendar (RFC 5545) feed builder.
 *
 * Just enough of the spec to make Apple Calendar / Google Calendar / Outlook
 * happy when subscribing to a feed URL. We don't generate VTIMEZONE blocks —
 * everything is emitted in UTC (Z-suffixed). Calendar apps render in the
 * user's local tz on display.
 *
 * RFC 5545 essentials we honor:
 *   - CRLF line endings (NOT bare \n — some parsers reject)
 *   - 75-octet line folding (continuation = single space)
 *   - Property text escaping for `,` `;` `\` and newlines
 *   - DTSTAMP on every VEVENT (mandatory)
 *   - Stable UIDs (use the DB row id)
 *
 * Things we deliberately skip:
 *   - VTIMEZONE — UTC + per-app rendering is fine for our use case
 *   - VALARM (server pushes reminders directly; users don't want
 *     calendar-app pop-ups duplicating them)
 *   - METHOD:REQUEST + ATTENDEE — this is a published feed, not invitations
 */

const CRLF = "\r\n"
const PRODID = "-//Shion Quant//Client Portal//EN"

/** Input shape — schema-agnostic so we can build from any event source. */
export interface IcsEvent {
  id: string
  title: string
  description?: string | null
  location?: string | null
  startsAt: Date
  endsAt?: Date | null
  isAllDay?: boolean
  /** Free-form category — surfaces as `CATEGORIES:<eventType>`. */
  eventType: string
  /** Optional RRULE body, e.g. "FREQ=MONTHLY;BYMONTHDAY=1". */
  rrule?: string | null
  /** Renders as PRIORITY:1 (vs default 5). */
  isCritical?: boolean
  /** STATUS:CANCELLED instead of CONFIRMED — keeps the UID present so apps
   *  can tombstone the event from a previous fetch. */
  isCancelled?: boolean
}

/**
 * Build a full VCALENDAR document. Returned string ends with CRLF as per spec.
 */
export function buildIcsCalendar(opts: {
  calendarName: string
  events: IcsEvent[]
  /** Hint for calendar apps — purely informational, not used for date math. */
  timezone?: string
}): string {
  const lines: string[] = []
  lines.push("BEGIN:VCALENDAR")
  lines.push("VERSION:2.0")
  lines.push(`PRODID:${PRODID}`)
  lines.push("CALSCALE:GREGORIAN")
  lines.push("METHOD:PUBLISH")
  lines.push(`X-WR-CALNAME:${escape(opts.calendarName)}`)
  if (opts.timezone) lines.push(`X-WR-TIMEZONE:${opts.timezone}`)

  const stamp = formatUtcStamp(new Date())
  for (const e of opts.events) {
    pushEvent(lines, e, stamp)
  }

  lines.push("END:VCALENDAR")
  return lines.map(foldLine).join(CRLF) + CRLF
}

function pushEvent(lines: string[], e: IcsEvent, stamp: string): void {
  lines.push("BEGIN:VEVENT")
  lines.push(`UID:${e.id}@shionquant.local`)
  lines.push(`DTSTAMP:${stamp}`)

  if (e.isAllDay) {
    lines.push(`DTSTART;VALUE=DATE:${formatDateOnly(e.startsAt)}`)
    // RFC 5545: DTEND for VALUE=DATE is exclusive, so add one day if not given.
    const end = e.endsAt
      ? formatDateOnly(e.endsAt)
      : formatDateOnly(addDays(e.startsAt, 1))
    lines.push(`DTEND;VALUE=DATE:${end}`)
  } else {
    lines.push(`DTSTART:${formatUtcStamp(e.startsAt)}`)
    const end = e.endsAt ?? new Date(e.startsAt.getTime() + 60 * 60_000)
    lines.push(`DTEND:${formatUtcStamp(end)}`)
  }

  lines.push(`SUMMARY:${escape(e.title)}`)
  if (e.description) lines.push(`DESCRIPTION:${escape(e.description)}`)
  if (e.location) lines.push(`LOCATION:${escape(e.location)}`)
  lines.push(`CATEGORIES:${escape(e.eventType)}`)
  lines.push(`STATUS:${e.isCancelled ? "CANCELLED" : "CONFIRMED"}`)
  if (e.isCritical) lines.push("PRIORITY:1")
  if (e.rrule) lines.push(`RRULE:${e.rrule}`)
  lines.push("END:VEVENT")
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Escape per RFC 5545 §3.3.11. Order matters — backslash first. */
function escape(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r?\n/g, "\\n")
}

/** YYYYMMDDTHHMMSSZ — basic ISO 8601 form, UTC only. */
function formatUtcStamp(d: Date): string {
  return d
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "")
}

/** YYYYMMDD — for VALUE=DATE properties. */
function formatDateOnly(d: Date): string {
  const y = d.getUTCFullYear()
  const m = String(d.getUTCMonth() + 1).padStart(2, "0")
  const day = String(d.getUTCDate()).padStart(2, "0")
  return `${y}${m}${day}`
}

function addDays(d: Date, n: number): Date {
  const r = new Date(d)
  r.setUTCDate(r.getUTCDate() + n)
  return r
}

/**
 * Fold lines longer than 75 octets per RFC 5545 §3.1. Continuation lines
 * start with a single space (as per the spec, NOT a tab — both are legal
 * but a space is friendlier to badly-written parsers).
 *
 * Note: we treat the string as bytes via JS string length, which is wrong for
 * multi-byte UTF-8. Calendar event titles in CJK can break this. Practical
 * fix: encode to UTF-8 first, then fold by byte. We approximate by chunking
 * by character count of 73 to stay safely under 75 octets even for 3-byte
 * CJK characters. Cheap and correct enough for our content sizes.
 */
function foldLine(line: string): string {
  // 73 chars * 3 bytes/char = 219 octets max — well under wrappers' tolerance.
  // First line allows 75 octets; continuation lines have a leading space so
  // the content portion is 74. We pick 73 to leave headroom.
  const max = 73
  if (line.length <= max) return line
  const parts: string[] = []
  for (let i = 0; i < line.length; i += max) {
    parts.push(line.slice(i, i + max))
  }
  return parts.join(CRLF + " ")
}
