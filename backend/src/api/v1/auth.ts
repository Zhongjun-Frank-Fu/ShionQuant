/**
 * /api/v1/auth/* — full auth flow.
 *
 *   POST /login   → password (and optional MFA challenge)
 *   POST /mfa     → TOTP code or recovery code
 *   POST /logout  → revoke session(s)
 *   GET  /session → who-am-i
 *
 * Threat model & defenses:
 *   - User enumeration via timing → `dummyVerify()` on unknown email
 *   - Credential stuffing → IP + email rate limit, plus account lockout
 *   - Session fixation → new sessionId issued on every login + on MFA upgrade
 *   - Cookie theft over network → `Secure` + `HttpOnly` + `SameSite=Strict`
 *   - CSRF → cookie SameSite=Strict + origin check (csrfMiddleware globally)
 *   - Side-channel on hash → Argon2id has constant-time `verify`
 *   - Audit gap → every attempt (success / bad_password / mfa_failed / locked /
 *     unknown_user) writes to `login_events`
 *
 * Cookie value format:    `<sessionId>.<HMAC-SHA256(sessionId, SESSION_SECRET)>`
 * MFA challenge format:   `mfa.<userId>.<expiresMs>.<HMAC>`  (5 min TTL, stateless)
 */

import { and, eq, isNull } from "drizzle-orm"
import { Hono } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"

import { dummyVerify, verifyPassword } from "../../auth/argon2.js"
import { consumeRecoveryCode } from "../../auth/recovery.js"
import {
  issueMfaChallenge,
  issueSession,
  revokeSession,
  suggestDeviceLabel,
  verifyMfaChallenge,
  verifySessionToken,
} from "../../auth/sessions.js"
import { verifyCode as verifyTotpCode } from "../../auth/totp.js"
import {
  authFactors,
  clients,
  db,
  loginEvents,
  sessions,
  users,
} from "../../db/client.js"
import { env, isProduction } from "../../env.js"
import { audit } from "../../lib/audit.js"
import { decryptSecret } from "../../lib/crypto.js"
import { locked, unauthenticated } from "../../lib/errors.js"
import { extractIp } from "../../lib/ip.js"
import {
  clearLock,
  countRecentFailures,
  isLocked,
  lockUser,
  LOCKOUT_THRESHOLD,
} from "../../lib/lockout.js"
import { authMiddleware } from "../../middleware/auth.js"
import {
  loginIpLimiter,
  mfaIpLimiter,
  rateLimitByIp,
  rateLimitLoginByEmail,
} from "../../middleware/ratelimit.js"
import {
  loginSchema,
  logoutSchema,
  mfaSchema,
} from "../../schemas/auth.js"

const app = new Hono()

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/auth/login
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Body: { email, password, rememberDevice? }
 *
 * Responses:
 *   200 { ok: true, mfaRequired: false, user, client }     fully logged in, cookie set
 *   200 { ok: true, mfaRequired: true,  challengeToken }   password OK, 2FA pending
 *   401 { ok: false, code: "UNAUTHENTICATED" }             bad email/password
 *   423 { ok: false, code: "LOCKED", retryAfter }          too many failures
 *   422 { ok: false, code: "VALIDATION_ERROR", details }
 *   429 { ok: false, code: "RATE_LIMITED" }
 */
app.post(
  "/login",
  rateLimitByIp(loginIpLimiter),
  rateLimitLoginByEmail,
  async (c) => {
    const ip = extractIp(c)
    const userAgent = c.req.header("user-agent") ?? null

    // The rate-limit middleware already buffered + parsed the JSON body and
    // stashed it in context — re-using it avoids the "body already read" error.
    const stashed = c.get("__loginBody")
    const body = loginSchema.parse(stashed)

    // 1. Lookup user (single-account scope; deleted users invisible)
    const user = await db.query.users.findFirst({
      where: and(eq(users.email, body.email), isNull(users.deletedAt)),
    })

    // 2. Unknown user — dummy verify to normalize timing, log, return generic 401
    if (!user) {
      await dummyVerify()
      await recordLoginEvent({
        userId: null,
        emailAttempted: body.email,
        ip,
        userAgent,
        method: "password",
        status: "unknown_user",
      })
      throw unauthenticated("Invalid email or password")
    }

    // 3. Locked? Hard stop before doing the verify (prevents DB-CPU exhaustion
    //    via repeated lockout-state attempts).
    const lockedUntil = isLocked(user)
    if (lockedUntil) {
      await recordLoginEvent({
        userId: user.id,
        emailAttempted: body.email,
        ip,
        userAgent,
        method: "password",
        status: "locked",
      })
      const retrySec = Math.ceil((lockedUntil.getTime() - Date.now()) / 1000)
      c.header("Retry-After", String(retrySec))
      throw locked(
        `Account temporarily locked due to repeated failures. Try again in ${retrySec}s.`,
      )
    }

    // 4. Inactive user (admin-disabled, etc.)
    if (!user.isActive) {
      await dummyVerify() // normalize timing
      await recordLoginEvent({
        userId: user.id,
        emailAttempted: body.email,
        ip,
        userAgent,
        method: "password",
        status: "bad_password",
      })
      throw unauthenticated("Invalid email or password")
    }

    // 5. Verify password
    const result = await verifyPassword(user.passwordHash, body.password)
    if (!result.ok) {
      await recordLoginEvent({
        userId: user.id,
        emailAttempted: body.email,
        ip,
        userAgent,
        method: "password",
        status: "bad_password",
      })
      // After this failure, do we cross the lockout threshold?
      const failures = await countRecentFailures(user.id)
      if (failures >= LOCKOUT_THRESHOLD()) {
        const newLock = await lockUser(user.id)
        await audit({
          action: "auth.lockout_triggered",
          userId: user.id,
          ip,
          userAgent,
          metadata: { failures, lockedUntil: newLock.toISOString() },
        })
      }
      throw unauthenticated("Invalid email or password")
    }

    // 6. Password OK. Rotate hash if Argon2 params have moved.
    if (result.newHash) {
      await db
        .update(users)
        .set({ passwordHash: result.newHash, updatedAt: new Date() })
        .where(eq(users.id, user.id))
    }

    // 7. Find primary client record (if any; some users are pure staff).
    const client = await db.query.clients.findFirst({
      where: and(eq(clients.userId, user.id), isNull(clients.deletedAt)),
    })

    // 8. Does this user have an active TOTP factor? If so, branch to MFA.
    const totpFactor = await db.query.authFactors.findFirst({
      where: and(
        eq(authFactors.userId, user.id),
        eq(authFactors.factorType, "totp"),
        isNull(authFactors.revokedAt),
      ),
    })

    if (totpFactor) {
      // Issue stateless 5-min challenge token; user proves TOTP next.
      const challengeToken = issueMfaChallenge(user.id)
      await recordLoginEvent({
        userId: user.id,
        emailAttempted: body.email,
        ip,
        userAgent,
        method: "password",
        status: "success",
      })
      await audit({
        action: "auth.login_password_ok_mfa_pending",
        userId: user.id,
        clientId: client?.id ?? null,
        ip,
        userAgent,
      })
      return c.json({
        ok: true,
        mfaRequired: true,
        challengeToken,
        // The frontend can render a hint like "Enter code from Authenticator".
        factorLabel: totpFactor.label ?? "Authenticator app",
      })
    }

    // 9. No TOTP factor → issue a complete session immediately.
    const issued = await issueSession({
      userId: user.id,
      clientId: client?.id ?? null,
      ip,
      userAgent,
      deviceLabel: suggestDeviceLabel(userAgent),
      is2faVerified: true, // password-only: there's no second factor to verify
      // ttlMs default; rememberDevice could shorten/extend this in future
    })
    setSessionCookie(c, issued.cookieValue, issued.expiresAt)

    await clearLock(user.id) // a successful login resets the timer
    await recordLoginEvent({
      userId: user.id,
      emailAttempted: body.email,
      ip,
      userAgent,
      method: "password",
      status: "success",
    })
    await audit({
      action: "auth.login_success",
      userId: user.id,
      clientId: client?.id ?? null,
      ip,
      userAgent,
      resourceType: "session",
      resourceId: issued.sessionId,
    })

    return c.json({
      ok: true,
      mfaRequired: false,
      user: shapeUser(user),
      client: shapeClient(client ?? null),
    })
  },
)

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/auth/mfa
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Body: { challengeToken, code }
 *
 * `code` is either:
 *   - 6 digits (TOTP)
 *   - XXXXX-XXXXX (recovery code; case-insensitive)
 *
 * Responses:
 *   200 { ok: true, user, client }
 *   401 { ok: false, code: "UNAUTHENTICATED" }
 *   422 { ok: false, code: "VALIDATION_ERROR" }
 */
app.post("/mfa", rateLimitByIp(mfaIpLimiter), async (c) => {
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const body = mfaSchema.parse(await c.req.json())

  // 1. Validate challenge — stateless; HMAC + 5 min TTL.
  const challenge = verifyMfaChallenge(body.challengeToken)
  if (!challenge) {
    await recordLoginEvent({
      userId: null,
      ip,
      userAgent,
      method: "totp",
      status: "mfa_failed",
    })
    throw unauthenticated("MFA challenge expired or invalid. Sign in again.")
  }

  // 2. Lookup user. They could have been disabled between login and mfa.
  const user = await db.query.users.findFirst({
    where: and(eq(users.id, challenge.userId), isNull(users.deletedAt)),
  })
  if (!user || !user.isActive) {
    throw unauthenticated("MFA challenge expired or invalid. Sign in again.")
  }

  const lockedUntil = isLocked(user)
  if (lockedUntil) {
    const retrySec = Math.ceil((lockedUntil.getTime() - Date.now()) / 1000)
    c.header("Retry-After", String(retrySec))
    throw locked(`Account locked. Try again in ${retrySec}s.`)
  }

  // 3. Branch on code shape.
  const code = body.code.trim()
  let methodUsed: "totp" | "recovery" = "totp"
  let mfaOk = false

  if (/^\d{6}$/.test(code)) {
    // TOTP
    const factor = await db.query.authFactors.findFirst({
      where: and(
        eq(authFactors.userId, user.id),
        eq(authFactors.factorType, "totp"),
        isNull(authFactors.revokedAt),
      ),
    })
    if (factor && factor.secretEncrypted) {
      const secretBase32 = await decryptSecret(factor.secretEncrypted)
      mfaOk = verifyTotpCode(secretBase32, code)
      if (mfaOk) {
        // Update last-used timestamp on the factor.
        await db
          .update(authFactors)
          .set({ lastUsedAt: new Date() })
          .where(eq(authFactors.id, factor.id))
      }
    }
  } else if (/^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/.test(code)) {
    // Recovery code
    methodUsed = "recovery"
    const consumed = await consumeRecoveryCode(user.id, code.toUpperCase(), ip)
    mfaOk = consumed.ok
  } else {
    // Malformed shape — treat as failure but don't reveal which form it should have been.
    mfaOk = false
  }

  if (!mfaOk) {
    await recordLoginEvent({
      userId: user.id,
      ip,
      userAgent,
      // login_events.method enum doesn't separate "recovery"; both MFA paths
      // record as "totp" — the audit log captures the actual method used.
      method: "totp",
      status: "mfa_failed",
    })
    // Lockout policy applies to MFA failures too.
    const failures = await countRecentFailures(user.id)
    if (failures >= LOCKOUT_THRESHOLD()) {
      const newLock = await lockUser(user.id)
      await audit({
        action: "auth.lockout_triggered",
        userId: user.id,
        ip,
        userAgent,
        metadata: {
          failures,
          via: "mfa",
          lockedUntil: newLock.toISOString(),
        },
      })
    }
    throw unauthenticated("Invalid verification code")
  }

  // 4. Success: issue full session.
  const client = await db.query.clients.findFirst({
    where: and(eq(clients.userId, user.id), isNull(clients.deletedAt)),
  })

  const issued = await issueSession({
    userId: user.id,
    clientId: client?.id ?? null,
    ip,
    userAgent,
    deviceLabel: suggestDeviceLabel(userAgent),
    is2faVerified: true,
  })
  setSessionCookie(c, issued.cookieValue, issued.expiresAt)

  await clearLock(user.id)
  await recordLoginEvent({
    userId: user.id,
    ip,
    userAgent,
    method: "totp", // see comment above; recovery and totp share this enum slot
    status: "success",
  })
  await audit({
    action:
      methodUsed === "recovery"
        ? "auth.mfa_recovery_success"
        : "auth.mfa_totp_success",
    userId: user.id,
    clientId: client?.id ?? null,
    ip,
    userAgent,
    resourceType: "session",
    resourceId: issued.sessionId,
  })

  return c.json({
    ok: true,
    user: shapeUser(user),
    client: shapeClient(client ?? null),
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/auth/logout
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Body: { allDevices?: boolean }
 *
 * Idempotent — returns 200 even if there's no current session. The cookie is
 * always cleared.
 */
app.post("/logout", async (c) => {
  // Lenient body parse — empty body is fine.
  const raw = await c.req.json().catch(() => ({}))
  const body = logoutSchema.parse(raw)

  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  // Try to identify the current session via cookie.
  const cookie = getCookie(c, env.SESSION_COOKIE_NAME)
  let sessionId: string | null = null
  let userId: string | null = null
  if (cookie) {
    sessionId = await verifySessionToken(cookie)
    if (sessionId) {
      const session = await db.query.sessions.findFirst({
        where: eq(sessions.id, sessionId),
      })
      if (session) userId = session.userId
    }
  }

  if (sessionId) {
    if (body.allDevices && userId) {
      // Revoke ALL non-revoked sessions for this user (including current).
      await db
        .update(sessions)
        .set({ revokedAt: new Date() })
        .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
    } else {
      await revokeSession(sessionId)
    }
    await audit({
      action: body.allDevices ? "auth.logout_all_devices" : "auth.logout",
      userId,
      ip,
      userAgent,
      resourceType: "session",
      resourceId: sessionId,
    })
  }

  // Always clear the cookie, even if we found nothing — ensures a confused
  // client (e.g., stale cookie) ends up in a clean state.
  deleteCookie(c, env.SESSION_COOKIE_NAME, {
    path: "/",
    secure: isProduction(),
  })

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/auth/session
// ═══════════════════════════════════════════════════════════════════════════

app.get("/session", authMiddleware, async (c) => {
  const user = c.get("user")
  const session = c.get("session")
  const client = c.get("client")
  const is2faVerified = c.get("is2faVerified")

  return c.json({
    ok: true,
    user: shapeUser(user),
    client: shapeClient(client),
    session: {
      id: session.id,
      is2faVerified,
      expiresAt: session.expiresAt,
      lastSeenAt: session.lastSeenAt,
    },
  })
})

export default app

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function setSessionCookie(
  c: import("hono").Context,
  value: string,
  expiresAt: Date,
): void {
  setCookie(c, env.SESSION_COOKIE_NAME, value, {
    httpOnly: true,
    secure: isProduction(),
    sameSite: "Strict",
    path: "/",
    expires: expiresAt,
  })
}

interface LoginEventInput {
  userId: string | null
  emailAttempted?: string
  ip: string
  userAgent: string | null
  method: "password" | "passkey" | "totp" | "magic-link"
  status: "success" | "bad_password" | "mfa_failed" | "locked" | "unknown_user"
}

async function recordLoginEvent(input: LoginEventInput): Promise<void> {
  try {
    await db.insert(loginEvents).values({
      userId: input.userId,
      emailAttempted: input.emailAttempted ?? null,
      ip: input.ip,
      userAgent: input.userAgent,
      method: input.method,
      status: input.status,
    })
  } catch (err) {
    // Don't block the response — security audit gap is recoverable;
    // letting an attacker through because of a write failure is not.
    console.error("[auth] failed to record login_events", err)
    if (input.userId) {
      // Re-raise the audit gap into the audit_log if we can.
      void audit({
        action: "auth.login_event_write_failed",
        userId: input.userId,
        ip: input.ip,
        userAgent: input.userAgent,
        metadata: { method: input.method, status: input.status },
      })
    }
  }
}

function shapeUser(user: typeof users.$inferSelect) {
  return {
    id: user.id,
    email: user.email,
    preferredName: user.preferredName,
    preferredLang: user.preferredLang,
  }
}

function shapeClient(client: typeof clients.$inferSelect | null) {
  if (!client) return null
  return {
    id: client.id,
    clientNumber: client.clientNumber,
    tier: client.tier,
    jurisdiction: client.jurisdiction,
  }
}
