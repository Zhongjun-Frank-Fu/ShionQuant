/**
 * Session-based auth middleware.
 *
 * Reads the session cookie, verifies the signed token, looks up the row
 * in `sessions`, and attaches `user` / `client` / `session` to the context.
 *
 * Two flavours:
 *   - `requireAuth`     — 401 if no valid session
 *   - `requireMfaAuth`  — 401 + MFA_REQUIRED if session isn't 2FA-verified
 *
 * Use `requireAuth` for read-only endpoints, `requireMfaAuth` for any
 * mutating action that touches money / KYC / settings.
 */

import { eq } from "drizzle-orm"
import type { MiddlewareHandler } from "hono"
import { getCookie } from "hono/cookie"

import { db, clients, sessions, users } from "../db/client.js"
import { env } from "../env.js"
import { mfaRequired, unauthenticated } from "../lib/errors.js"
import { verifySessionToken } from "../auth/sessions.js"

export const authMiddleware: MiddlewareHandler = async (c, next) => {
  const cookie = getCookie(c, env.SESSION_COOKIE_NAME)
  if (!cookie) throw unauthenticated()

  const sessionId = await verifySessionToken(cookie)
  if (!sessionId) throw unauthenticated("Invalid or expired session")

  const session = await db.query.sessions.findFirst({
    where: eq(sessions.id, sessionId),
  })
  if (!session) throw unauthenticated("Session not found")
  if (session.revokedAt) throw unauthenticated("Session revoked")
  if (session.expiresAt < new Date()) throw unauthenticated("Session expired")

  const user = await db.query.users.findFirst({ where: eq(users.id, session.userId) })
  if (!user || !user.isActive || user.deletedAt) throw unauthenticated("User unavailable")

  const client = session.clientId
    ? (await db.query.clients.findFirst({ where: eq(clients.id, session.clientId) })) ?? null
    : null

  // Update last_seen_at — fire-and-forget; don't block the request.
  void db
    .update(sessions)
    .set({ lastSeenAt: new Date() })
    .where(eq(sessions.id, sessionId))
    .catch((err: unknown) =>
      console.error("[auth] failed to update last_seen_at", err),
    )

  c.set("session", session)
  c.set("user", user)
  c.set("client", client)
  c.set("is2faVerified", session.is2faVerified)

  await next()
}

/** Stricter variant — requires the session to have completed MFA. */
export const mfaAuthMiddleware: MiddlewareHandler = async (c, next) => {
  await authMiddleware(c, async () => {
    if (!c.get("is2faVerified")) throw mfaRequired()
    await next()
  })
}
