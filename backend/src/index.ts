/**
 * Cloudflare Worker entrypoint.
 *
 * Replaces the old Node.js `serve()` boot. The Hono app + middleware stack +
 * routes are unchanged from the Node version — only the runtime adapter
 * differs.
 *
 * Boot order (per request, after first cold start the env init is cached):
 *   1. initEnv(env)              ← validates secrets via Zod, populates lazy proxy
 *   2. middleware stack runs     ← logger → secureHeaders → cors → csrf
 *   3. routes
 *   4. error handler converts AppError / ZodError to stable JSON
 *
 * Run locally:    pnpm dev      (wrangler dev — miniflare, no Docker)
 * Deploy:         pnpm deploy   (wrangler deploy)
 *
 * Why no `dotenv/config` here:
 *   In Workers, env vars come from `wrangler.jsonc` `vars` and `wrangler
 *   secret put …`. They reach the fetch handler as the second arg. Node's
 *   `process.env` is irrelevant. Standalone scripts (seed.ts / retention.ts)
 *   still import dotenv — they run on Node, locally.
 */

import { Hono } from "hono"
import { compress } from "hono/compress"
import { secureHeaders } from "hono/secure-headers"

import v1 from "./api/v1/index.js"
import { initEnv, isProduction, type Env as RuntimeEnv } from "./env.js"
import { corsMiddleware } from "./middleware/cors.js"
import { csrfMiddleware } from "./middleware/csrf.js"
import { errorMiddleware } from "./middleware/error.js"
import { loggerMiddleware } from "./middleware/logger.js"

// Hono on Workers takes the env type as a generic so c.env is typed.
const app = new Hono<{ Bindings: RuntimeEnv }>()

// ─── Middleware (order matters) ────────────────────────────────────────────

// 1. Request ID + structured logging — first so every line has a request ID.
app.use("*", loggerMiddleware)

// 2. Security headers — helmet-equivalent.
app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
    // HSTS only matters in production where the FE makes us serve from HTTPS.
    // Workers serve HTTPS by default; add the header only when env is loaded.
    strictTransportSecurity:
      isProduction() && "max-age=31536000; includeSubDomains; preload",
    referrerPolicy: "strict-origin-when-cross-origin",
  }),
)

// 3. Compression — gzip/deflate for responses > 1 KB. Workers also auto-
//    compresses outbound; this is belt-and-braces for older clients.
app.use("*", compress())

// 4. CORS — strict origin allowlist + credentials.
app.use("*", corsMiddleware)

// 5. CSRF — Origin/Referer check for state-changing requests.
app.use("*", csrfMiddleware)

// ─── Routes ────────────────────────────────────────────────────────────────

app.get("/health", (c) =>
  c.json({
    ok: true,
    service: "shion-quant-api",
    env: c.env.NODE_ENV,
    runtime: "cloudflare-workers",
    now: new Date().toISOString(),
  }),
)

app.route("/api/v1", v1)

app.notFound((c) =>
  c.json(
    {
      ok: false,
      code: "NOT_FOUND",
      message: `${c.req.method} ${new URL(c.req.url).pathname} is not a registered route`,
      requestId: c.get("requestId"),
    },
    404,
  ),
)

app.onError(errorMiddleware)

// ─── Workers fetch handler ────────────────────────────────────────────────

export default {
  /**
   * Per-request entrypoint. Initializes env once per cold start, then
   * delegates to Hono. Subsequent requests on the same isolate skip
   * re-validation (initEnv is idempotent and caches).
   */
  async fetch(
    request: Request,
    workerEnv: RuntimeEnv,
    ctx: ExecutionContext,
  ): Promise<Response> {
    try {
      initEnv(workerEnv as unknown as Record<string, unknown>)
    } catch (err) {
      // Misconfigured Worker (missing secret, bad KEK encoding, etc.).
      // Return a clear 500 instead of letting the runtime show a generic
      // error page — production debugging is much easier this way.
      console.error("[boot] env init failed", err)
      return new Response(
        JSON.stringify({
          ok: false,
          code: "INTERNAL",
          message: "Worker is misconfigured. Check secrets via `wrangler secret list`.",
          detail: isProduction() ? undefined : String(err),
        }),
        {
          status: 500,
          headers: { "content-type": "application/json" },
        },
      )
    }
    return app.fetch(request, workerEnv, ctx)
  },
} satisfies ExportedHandler<RuntimeEnv>
