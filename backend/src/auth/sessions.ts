/**
 * Session token issue / verify.
 *
 * Wire format (cookie value):
 *
 *     <sessionId (uuid v4)>.<sig (hex of HMAC-SHA256)>
 *
 * - sessionId is the primary key into `sessions` table
 * - sig is HMAC(sessionId, SESSION_SECRET) — defeats cookie forgery without
 *   needing to encrypt
 * - Token rotation: cookie value is the same every request; rotation happens
 *   server-side by issuing a new sessionId on privilege change (login, MFA
 *   completion, password change)
 *
 * Why not JWT:
 *   - Not stateless: we want server-side revocation (`sessions.revoked_at`)
 *   - Not signed identity claims: we want the row, not encoded claims
 *   - Cookie + DB lookup is one indexed lookup per request — fine
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto"

import { eq } from "drizzle-orm"
import { db, sessions } from "../db/client.js"
import { env } from "../env.js"
import { addMs, hours } from "../lib/time.js"

// ─── Token serialization ──────────────────────────────────────────────────

function sign(sessionId: string): string {
  return createHmac("sha256", env.SESSION_SECRET).update(sessionId).digest("hex")
}

export function serializeToken(sessionId: string): string {
  return `${sessionId}.${sign(sessionId)}`
}

/**
 * Parse a token and verify its signature in constant time.
 * Returns the sessionId on success, null on any failure.
 *
 * The DB lookup happens upstream in `authMiddleware` — this only validates
 * structural integrity.
 */
export async function verifySessionToken(token: string): Promise<string | null> {
  const dot = token.indexOf(".")
  if (dot === -1) return null

  const sessionId = token.slice(0, dot)
  const sigHex = token.slice(dot + 1)

  // UUID quick check — saves a hash if obviously malformed
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
    return null
  }

  const expected = sign(sessionId)

  // Both sides are hex strings of the same length → timing-safe compare.
  if (sigHex.length !== expected.length) return null
  try {
    const a = Buffer.from(sigHex, "hex")
    const b = Buffer.from(expected, "hex")
    if (a.length !== b.length) return null
    if (!timingSafeEqual(a, b)) return null
  } catch {
    return null
  }

  return sessionId
}

// ─── Issue / revoke (called from login + logout routes) ───────────────────

export interface IssueSessionInput {
  userId: string
  clientId?: string | null
  ip: string
  userAgent: string | null
  deviceLabel?: string | null
  is2faVerified?: boolean
  ttlMs?: number
}

export interface IssuedSession {
  sessionId: string
  cookieValue: string
  expiresAt: Date
}

/**
 * Insert a new `sessions` row and return the cookie value to set.
 *
 * Stores HMAC(sessionId) as a "token_hash" column for backwards-compat with
 * any future token format that needs lookup-by-token.
 */
export async function issueSession(input: IssueSessionInput): Promise<IssuedSession> {
  const sessionId = randomUUID()
  const ttlMs = input.ttlMs ?? hours(env.SESSION_TTL_HOURS)
  const expiresAt = addMs(new Date(), ttlMs)

  // Note: the `token_hash` column is a forward-looking field; with our
  // current cookie format we can lookup by `id` directly, but storing a hash
  // makes future opaque-token rotation cheap.
  const tokenHash = createHmac("sha256", env.SESSION_SECRET)
    .update(sessionId)
    .digest()

  await db.insert(sessions).values({
    id: sessionId,
    userId: input.userId,
    clientId: input.clientId ?? null,
    tokenHash,
    ip: input.ip,
    userAgent: input.userAgent,
    deviceLabel: input.deviceLabel ?? null,
    is2faVerified: input.is2faVerified ?? false,
    expiresAt,
  })

  return {
    sessionId,
    cookieValue: serializeToken(sessionId),
    expiresAt,
  }
}

export async function revokeSession(sessionId: string): Promise<void> {
  await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(eq(sessions.id, sessionId))
}

/**
 * Generate a short-lived MFA challenge token. Stateless; signed JWT-lite.
 * Format: `mfa.<userId>.<expiresAtMs>.<sig>`
 *
 * Used between /auth/login (password OK, 2FA pending) and /auth/mfa.
 * Caller verifies via `verifyMfaChallenge`.
 */
export function issueMfaChallenge(userId: string, ttlMs = 5 * 60_000): string {
  const expiresAt = Date.now() + ttlMs
  const payload = `mfa.${userId}.${expiresAt}`
  const sig = createHmac("sha256", env.SESSION_SECRET).update(payload).digest("hex")
  return `${payload}.${sig}`
}

export function verifyMfaChallenge(token: string): { userId: string } | null {
  const parts = token.split(".")
  if (parts.length !== 4 || parts[0] !== "mfa") return null
  const [, userId, expStr, sigHex] = parts as [string, string, string, string]
  const exp = Number(expStr)
  if (!Number.isFinite(exp) || exp < Date.now()) return null

  const payload = `mfa.${userId}.${exp}`
  const expected = createHmac("sha256", env.SESSION_SECRET).update(payload).digest("hex")
  if (sigHex.length !== expected.length) return null
  const a = Buffer.from(sigHex, "hex")
  const b = Buffer.from(expected, "hex")
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  return { userId }
}

/** A few-byte random label for new device entries (helps users recognize sessions). */
export function suggestDeviceLabel(userAgent: string | null): string {
  if (!userAgent) return "Unknown device"
  // Crude UA → device class. Replace with `ua-parser-js` if you need accuracy.
  const ua = userAgent.toLowerCase()
  if (ua.includes("iphone")) return "iPhone"
  if (ua.includes("ipad")) return "iPad"
  if (ua.includes("android")) return "Android device"
  if (ua.includes("macintosh")) return "Mac"
  if (ua.includes("windows")) return "Windows PC"
  if (ua.includes("linux")) return "Linux"
  return "Browser"
}

/** Helper for tests / scripts that need a random opaque secret string. */
export function randomOpaqueSecret(bytes = 32): string {
  return randomBytes(bytes).toString("base64url")
}
