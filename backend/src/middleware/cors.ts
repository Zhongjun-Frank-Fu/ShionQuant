/**
 * CORS — strict allowlist from env, credentials enabled.
 *
 * Same-origin in production (portal.shionquant.com → api.shionquant.com on
 * the same registrable domain) means cookies work without CORS. Cross-origin
 * still needed for local dev (`http://localhost:5173` → `:8787`).
 *
 * Why we wrap `cors({...})` lazily:
 *   `hono/cors` reads its options at the time it's CALLED. We can't pass
 *   `env.ALLOWED_ORIGINS` at module-load (env is a Proxy that throws before
 *   initEnv() runs in the fetch handler). Inline-deferring to first invocation
 *   is the cheapest fix — no behavior change, just the construction moves
 *   into the request lifetime.
 */

import { cors } from "hono/cors"
import type { MiddlewareHandler } from "hono"

import { env } from "../env.js"

let _impl: MiddlewareHandler | null = null

export const corsMiddleware: MiddlewareHandler = (c, next) => {
  if (!_impl) {
    _impl = cors({
      origin: env.ALLOWED_ORIGINS,
      credentials: true,
      allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
      exposeHeaders: ["X-Request-Id"],
      maxAge: 600,
    })
  }
  return _impl(c, next)
}
