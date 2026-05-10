/**
 * Rate-limit middleware factories.
 *
 * Three keying strategies, each with its own bucket:
 *   - by IP       → defeats anonymous flooding from one host
 *   - by email    → defeats credential stuffing on a known account
 *   - by userId   → for authenticated routes (e.g., MFA challenge re-issue)
 *
 * Buckets live in-process (token bucket from `lib/ratelimit.ts`). On
 * Cloudflare Workers, "in-process" means "in this isolate" — buckets aren't
 * shared across isolates, so an attacker spread across N isolates effectively
 * gets N×capacity. At our scale this is acceptable; for stricter limits,
 * upgrade to Cloudflare's Rate Limiting binding (10-line swap; see TODO).
 *
 * TODO (post-MVP): replace in-isolate token buckets with Cloudflare's
 * Rate Limiting binding (`[[unsafe.bindings]] type = "ratelimit"`). It's
 * free, edge-coordinated, and accurate — but requires a wrangler.jsonc
 * change + threading `c.env.LIMITER` into each call site.
 *
 * Construction is LAZY because the limiters read env (capacity / refill rate)
 * which isn't available at module-load time on Workers. First request
 * initializes; subsequent requests reuse.
 */

import type { MiddlewareHandler } from "hono"

import { env } from "../env.js"
import { rateLimited } from "../lib/errors.js"
import { extractIp } from "../lib/ip.js"
import { RateLimiter } from "../lib/ratelimit.js"

// ─── Lazy singleton limiters ──────────────────────────────────────────────

let _loginIpLimiter: RateLimiter | null = null
let _loginEmailLimiter: RateLimiter | null = null
let _mfaIpLimiter: RateLimiter | null = null

/** IP-keyed limiter for /auth/login. Lazy to defer env access until request time. */
export function loginIpLimiter(): RateLimiter {
  return (_loginIpLimiter ??= new RateLimiter({
    capacity: env.RATE_LIMIT_LOGIN_PER_MIN,
    perMinute: env.RATE_LIMIT_LOGIN_PER_MIN,
  }))
}

/** Email-keyed limiter for /auth/login. Tighter than IP. */
export function loginEmailLimiter(): RateLimiter {
  return (_loginEmailLimiter ??= new RateLimiter({
    capacity: 5,
    perMinute: 5,
  }))
}

/** IP-keyed limiter for /auth/mfa. */
export function mfaIpLimiter(): RateLimiter {
  return (_mfaIpLimiter ??= new RateLimiter({
    capacity: env.RATE_LIMIT_LOGIN_PER_MIN,
    perMinute: env.RATE_LIMIT_LOGIN_PER_MIN,
  }))
}

// NOTE: Workers don't have setInterval; we used to prune buckets on a
// schedule on Node. Without periodic pruning the buckets accumulate keys
// indefinitely. In practice each isolate is short-lived (Workers GCs them
// after ~30s of idle for free plan, longer for paid), so memory pressure
// is bounded by isolate lifetime. If isolate longevity becomes a problem,
// switch to the Cloudflare Rate Limiting binding (TODO above).

// ─── Middleware factories ─────────────────────────────────────────────────

/**
 * Reject if the IP has exhausted its bucket.
 *
 * The argument is a getter (not the limiter directly) so we don't read env
 * at route-definition time. Call as: `rateLimitByIp(loginIpLimiter)`.
 */
export function rateLimitByIp(getLimiter: () => RateLimiter): MiddlewareHandler {
  return async (c, next) => {
    const ip = extractIp(c)
    const { allowed, retryAfterMs } = getLimiter().consume(ip)
    if (!allowed) {
      const retryAfterSec = Math.ceil(retryAfterMs / 1000)
      c.header("Retry-After", String(retryAfterSec))
      throw rateLimited(`Too many requests from this IP. Try again in ${retryAfterSec}s.`)
    }
    await next()
  }
}

/**
 * Reject if the `email` body field has exhausted its bucket.
 *
 * Buffers the body, parses JSON, sets `c.set("__loginBody", body)` so the
 * handler doesn't have to re-read it. (Hono's request body is a one-shot
 * stream.) Specific to /auth/login because the field name is `email`.
 */
export const rateLimitLoginByEmail: MiddlewareHandler = async (c, next) => {
  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    // Malformed JSON — pass through; the route's Zod parse will return 422.
    await next()
    return
  }

  const email =
    body && typeof body === "object" && "email" in body && typeof body.email === "string"
      ? body.email.toLowerCase().trim()
      : null

  if (email) {
    const { allowed, retryAfterMs } = loginEmailLimiter().consume(email)
    if (!allowed) {
      const retryAfterSec = Math.ceil(retryAfterMs / 1000)
      c.header("Retry-After", String(retryAfterSec))
      throw rateLimited(
        `Too many login attempts on this account. Try again in ${retryAfterSec}s.`,
      )
    }
  }

  // Stash the parsed body so the handler can use it without re-reading.
  c.set("__loginBody", body)
  await next()
}
