/**
 * Time helpers.
 *
 * Rule of thumb: every timestamp is UTC in storage; display conversion happens
 * at the API boundary using the user's preferred TZ. The DB always stores
 * `timestamptz`, the app always uses `Date` (which is implicitly UTC ms).
 */

export const minutes = (n: number) => n * 60 * 1000
export const hours = (n: number) => n * 60 * 60 * 1000
export const days = (n: number) => n * 24 * 60 * 60 * 1000

/** Add a duration to a Date and return a fresh Date. */
export function addMs(d: Date, ms: number): Date {
  return new Date(d.getTime() + ms)
}

/** ISO 8601 UTC, ms precision. Use for log lines, audit metadata, etc. */
export function toIsoUtc(d: Date): string {
  return d.toISOString()
}
