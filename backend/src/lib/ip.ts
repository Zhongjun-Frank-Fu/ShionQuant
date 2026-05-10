/**
 * Real-IP extraction.
 *
 * In production we sit behind Cloudflare / a load balancer, so Hono's
 * connection IP is useless. Trust headers in this priority order, falling
 * back to a placeholder for local dev.
 *
 *   CF-Connecting-IP    (Cloudflare)
 *   X-Real-IP           (nginx)
 *   X-Forwarded-For     (most proxies; take leftmost = original client)
 *
 * IMPORTANT: only trust these if you ACTUALLY have a proxy in front. Otherwise
 * a malicious client can spoof their IP. In production, configure your proxy
 * to strip / overwrite these on ingress.
 */

import type { Context } from "hono"

export function extractIp(c: Context): string {
  const cfIp = c.req.header("cf-connecting-ip")
  if (cfIp) return cfIp.trim()

  const realIp = c.req.header("x-real-ip")
  if (realIp) return realIp.trim()

  const xff = c.req.header("x-forwarded-for")
  if (xff) {
    const first = xff.split(",")[0]
    if (first) return first.trim()
  }

  // Hono on Node: try to access the raw socket. The shape of `c.env` is
  // runtime-specific (Bun / Node / edge differ), so cast through unknown.
  const env = c.env as
    | { incoming?: { socket?: { remoteAddress?: string } } }
    | undefined
  const remote = env?.incoming?.socket?.remoteAddress
  if (typeof remote === "string") return remote

  return "0.0.0.0"
}
