/**
 * Advisor availability slot generation.
 *
 * Given a window + the advisor's existing meetings, return the bookable
 * slots. Working hours are hard-coded (9–17 in the advisor's tz, weekdays
 * only) — when an advisor wants different hours, this becomes a per-advisor
 * `working_hours` table. Today's posture: keep it simple.
 *
 * Timezone handling:
 *   - `from` / `to` come in as UTC instants
 *   - working-hours filter is applied in the advisor's tz (Asia/Hong_Kong, etc.)
 *   - slot start/end are returned as UTC instants — the frontend renders in
 *     the user's tz
 *
 * Algorithm:
 *   1. Walk hour-by-hour through the [from, to) window
 *   2. Skip slots whose advisor-tz hour is outside [9, 17) or weekend
 *   3. Skip slots that overlap any pending/confirmed meeting
 *   4. Skip slots in the past (where `startsAt < now`)
 */

const WORK_START_HOUR = 9 // inclusive
const WORK_END_HOUR = 17 // exclusive

/** Meeting that we should AVOID double-booking around. */
export interface BusyMeeting {
  scheduledAt: Date
  durationMin: number
}

export interface SlotInput {
  from: Date
  to: Date
  /** IANA tz of the advisor, e.g. "Asia/Hong_Kong". */
  advisorTimezone: string
  slotMinutes: number
  busy: BusyMeeting[]
  /** "now" for the past-slot filter. Tests can inject this. */
  now?: Date
}

export interface Slot {
  startsAt: Date
  endsAt: Date
}

export function generateSlots(input: SlotInput): Slot[] {
  const now = input.now ?? new Date()
  const slots: Slot[] = []
  const stepMs = input.slotMinutes * 60_000

  // Round `from` UP to the next slot boundary in the advisor's tz. Simpler:
  // round to the next exact hour in UTC. A slotMinutes that doesn't divide
  // 60 (e.g. 45) will still produce hourly-aligned slots — fine for the
  // current 60-min default.
  const start = new Date(input.from)
  start.setUTCMinutes(0, 0, 0)
  if (start < input.from) start.setUTCHours(start.getUTCHours() + 1)

  for (let t = start.getTime(); t + stepMs <= input.to.getTime(); t += stepMs) {
    const slotStart = new Date(t)
    const slotEnd = new Date(t + stepMs)

    if (slotStart < now) continue
    if (!isWithinWorkingHours(slotStart, input.advisorTimezone)) continue
    if (overlapsBusy(slotStart, slotEnd, input.busy)) continue

    slots.push({ startsAt: slotStart, endsAt: slotEnd })
  }

  return slots
}

function isWithinWorkingHours(d: Date, tz: string): boolean {
  // Use Intl.DateTimeFormat to extract the local hour + weekday in the tz.
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    hour: "numeric",
    hour12: false,
    weekday: "short",
  })
  const parts = fmt.formatToParts(d)
  const hourPart = parts.find((p) => p.type === "hour")?.value
  const weekdayPart = parts.find((p) => p.type === "weekday")?.value
  if (!hourPart || !weekdayPart) return false

  const hour = Number.parseInt(hourPart, 10)
  if (Number.isNaN(hour)) return false
  if (hour < WORK_START_HOUR || hour >= WORK_END_HOUR) return false

  // Mon–Fri only.
  if (weekdayPart === "Sat" || weekdayPart === "Sun") return false

  return true
}

function overlapsBusy(start: Date, end: Date, busy: BusyMeeting[]): boolean {
  for (const m of busy) {
    const mStart = m.scheduledAt
    const mEnd = new Date(m.scheduledAt.getTime() + m.durationMin * 60_000)
    // Overlap if NOT (slot ends before busy starts OR slot starts after busy ends).
    if (!(end <= mStart || start >= mEnd)) return true
  }
  return false
}
