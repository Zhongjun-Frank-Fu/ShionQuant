/**
 * In-memory token-bucket rate limiter.
 *
 * Good enough for single-process v1. When the app moves to multiple instances,
 * swap the implementation for Redis (e.g. ioredis + a Lua script) — the
 * `consume()` API stays the same.
 *
 * Two distinct buckets per route:
 *   - by IP (defeats anonymous flooding)
 *   - by email / userId (defeats credential stuffing on a known account)
 *
 * Don't reuse the same `RateLimiter` for both; create one per concern.
 */

interface Bucket {
  tokens: number
  lastRefill: number
}

export class RateLimiter {
  readonly capacity: number
  readonly refillPerMs: number
  private readonly buckets = new Map<string, Bucket>()

  constructor(opts: { capacity: number; perMinute: number }) {
    this.capacity = opts.capacity
    this.refillPerMs = opts.perMinute / 60_000
  }

  /**
   * Attempt to consume one token. Returns true if allowed, false if rejected.
   */
  consume(key: string): { allowed: boolean; retryAfterMs: number } {
    const now = Date.now()
    let b = this.buckets.get(key)
    if (!b) {
      b = { tokens: this.capacity, lastRefill: now }
      this.buckets.set(key, b)
    }

    // Refill
    const elapsed = now - b.lastRefill
    if (elapsed > 0) {
      b.tokens = Math.min(this.capacity, b.tokens + elapsed * this.refillPerMs)
      b.lastRefill = now
    }

    if (b.tokens >= 1) {
      b.tokens -= 1
      return { allowed: true, retryAfterMs: 0 }
    }
    const retryAfterMs = Math.ceil((1 - b.tokens) / this.refillPerMs)
    return { allowed: false, retryAfterMs }
  }

  /** Periodic cleanup to keep memory bounded. Call from a setInterval. */
  prune(maxAgeMs = 30 * 60_000): void {
    const cutoff = Date.now() - maxAgeMs
    for (const [k, b] of this.buckets) {
      if (b.lastRefill < cutoff) this.buckets.delete(k)
    }
  }
}
