/**
 * Account lockout policy.
 *
 * After MAX_LOGIN_FAILURES (default 5) failed password attempts in
 * LOCKOUT_MINUTES (default 15) → set `users.locked_until = now + LOCKOUT_MINUTES`.
 *
 * Counting is sourced from `login_events` (status="bad_password" OR "mfa_failed")
 * within the rolling window — this gives us:
 *   - automatic decay (old failures drop off)
 *   - audit trail (every failure was already being recorded)
 *   - resilience to process restart (state lives in DB, not memory)
 *
 * Don't store a counter on `users` — too easy to forget to reset, and it
 * conflates "currently flailing on the password" with the audit history.
 *
 * On successful login: NOT clearing `users.locked_until` is fine; it's a
 * timestamp, not a flag, and it's `< now()` after lockout expires.
 *
 * The IP-keyed rate limiter (`middleware/ratelimit.ts`) is a separate layer
 * that defends against attackers who don't have a single email yet. This
 * module defends a single account from credential stuffing.
 */

import { and, eq, gte, inArray } from "drizzle-orm"

import { db, loginEvents, users } from "../db/client.js"
import { env } from "../env.js"
import { addMs, minutes } from "./time.js"

/**
 * Count recent login failures for a user. Window = LOCKOUT_MINUTES.
 *
 * Includes both bad-password and MFA-failed events — they're both "someone
 * is guessing", and we don't want a TOTP-protected account to be more
 * brute-forceable via the MFA endpoint.
 */
export async function countRecentFailures(userId: string): Promise<number> {
  const since = new Date(Date.now() - minutes(env.LOCKOUT_MINUTES))
  const rows = await db
    .select({ id: loginEvents.id })
    .from(loginEvents)
    .where(
      and(
        eq(loginEvents.userId, userId),
        inArray(loginEvents.status, ["bad_password", "mfa_failed"]),
        gte(loginEvents.occurredAt, since),
      ),
    )
  return rows.length
}

/**
 * Set `users.locked_until` to now + LOCKOUT_MINUTES.
 *
 * Called by the login route after recording a `bad_password` event when
 * the count reaches MAX_LOGIN_FAILURES.
 *
 * Returns the new `lockedUntil` timestamp so the caller can include it in
 * the 423 response (`Retry-After`).
 */
export async function lockUser(userId: string): Promise<Date> {
  const lockedUntil = addMs(new Date(), minutes(env.LOCKOUT_MINUTES))
  await db.update(users).set({ lockedUntil }).where(eq(users.id, userId))
  return lockedUntil
}

/**
 * Check if a user is currently locked. Returns the `lockedUntil` Date if so,
 * or null. Use for the early-out branch in /auth/login.
 */
export function isLocked(user: { lockedUntil: Date | null }): Date | null {
  if (!user.lockedUntil) return null
  if (user.lockedUntil <= new Date()) return null
  return user.lockedUntil
}

/**
 * After a successful, complete login (password + MFA both passed), explicitly
 * clear the lock. This isn't strictly required (the timestamp expires anyway)
 * but it's tidier and makes the table easier to read in support cases.
 */
export async function clearLock(userId: string): Promise<void> {
  await db.update(users).set({ lockedUntil: null }).where(eq(users.id, userId))
}

/**
 * The window threshold — exposed so the login route can branch:
 *   "did THIS failure cross the line?"
 */
export const LOCKOUT_THRESHOLD = (): number => env.MAX_LOGIN_FAILURES
export const LOCKOUT_WINDOW_MIN = (): number => env.LOCKOUT_MINUTES
