/**
 * Structured request logging + request ID propagation.
 *
 * Each line is a single JSON object — easy to grep, easy to ship to a
 * log aggregator (Better Stack, Axiom, etc) later.
 *
 * Never log request bodies, headers, or query params containing PII.
 * For sensitive routes (login, etc), the route handler should explicitly
 * decide what to record via `audit()`.
 */

import { randomUUID } from "node:crypto"
import type { MiddlewareHandler } from "hono"

import { isDevelopment } from "../env.js"
import { extractIp } from "../lib/ip.js"

export const loggerMiddleware: MiddlewareHandler = async (c, next) => {
  const requestId = c.req.header("x-request-id") ?? randomUUID()
  c.set("requestId", requestId)
  c.header("x-request-id", requestId)

  const startedAt = performance.now()
  const ip = extractIp(c)
  const { method } = c.req
  const path = new URL(c.req.url).pathname

  await next()

  const durationMs = Math.round(performance.now() - startedAt)
  const status = c.res.status

  const line = {
    ts: new Date().toISOString(),
    level: status >= 500 ? "error" : status >= 400 ? "warn" : "info",
    requestId,
    method,
    path,
    status,
    durationMs,
    ip,
    ua: c.req.header("user-agent") ?? null,
  }

  // Pretty in dev, single-line JSON in production.
  if (isDevelopment()) {
    const colour = status >= 500 ? "\x1b[31m" : status >= 400 ? "\x1b[33m" : "\x1b[32m"
    const reset = "\x1b[0m"
    console.log(
      `${colour}${status}${reset} ${method.padEnd(6)} ${path.padEnd(40)} ${durationMs}ms  rid=${requestId.slice(0, 8)}`,
    )
  } else {
    console.log(JSON.stringify(line))
  }
}
