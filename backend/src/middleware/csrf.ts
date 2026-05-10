/**
 * CSRF protection for cookie-authenticated state-changing requests.
 *
 * Strategy: origin/referer check (the simple, modern approach).
 *   - For requests that mutate state (POST/PUT/PATCH/DELETE), require the
 *     `Origin` (or `Referer` fallback) header to match an allowed origin.
 *   - GET / HEAD / OPTIONS pass through (per RFC, they should be safe).
 *   - Same-site cookie + `Origin` check is the W3C-recommended pattern;
 *     we don't need a separate CSRF token because:
 *       (a) `SameSite=Strict` on the session cookie blocks cross-site sends
 *       (b) the `Origin` header is set by browsers on all cross-origin POSTs
 *       (c) credentials-mode CORS already requires explicit origin allowlisting
 *
 * Mounted globally in `index.ts` BEFORE the route handlers. Position in the
 * middleware stack does NOT matter relative to `authMiddleware` — both
 * checks must pass; order between them is cosmetic.
 *
 * Lazy construction: same rationale as cors.ts. Reading `env.ALLOWED_ORIGINS`
 * at module-load throws (env Proxy isn't initialized yet on Workers). Defer
 * to first invocation.
 */

import { csrf } from "hono/csrf"
import type { MiddlewareHandler } from "hono"

import { env } from "../env.js"

let _impl: MiddlewareHandler | null = null

export const csrfMiddleware: MiddlewareHandler = (c, next) => {
  if (!_impl) {
    _impl = csrf({
      origin: env.ALLOWED_ORIGINS,
    })
  }
  return _impl(c, next)
}
