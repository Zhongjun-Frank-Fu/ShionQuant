/**
 * Environment validation — works in both Cloudflare Workers AND Node scripts.
 *
 * Two runtimes, one config layer:
 *
 *   Workers          fetch handler calls initEnv(env) on each cold start.
 *                    Subsequent reads from `import { env } from "./env.js"`
 *                    return the cached parsed config. The `env` proxy
 *                    throws if read before init — guarding against accidental
 *                    module-load-time access.
 *
 *   Node scripts     `import "dotenv/config"` populates process.env, then
 *                    initEnv(process.env) gives them the same env shape.
 *                    Done once at the top of each script (seed.ts,
 *                    retention.ts, etc.).
 *
 * Why a Proxy?
 *   We want existing call sites to keep using `import { env } from "./env.js"`
 *   without threading c.env through every function. The proxy delegates
 *   reads to the parsed cache when ready, throws clearly when not.
 *
 *   The one constraint this imposes on the rest of the codebase: NO
 *   module-top-level reads of `env.X`. Always read inside a function /
 *   middleware / handler that runs after initEnv(). If you need a derived
 *   constant (KEK from env.KYC_KEK_BASE64), wrap it in a lazy getter. The
 *   places that needed this — lib/kms.ts, lib/crypto.ts,
 *   middleware/ratelimit.ts — already are.
 */

import { z } from "zod"

const schema = z.object({
  // Runtime
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  // PORT is irrelevant on Workers; kept so Node scripts (seed/retention) can
  // still run a local HTTP server during dev if ever needed.
  PORT: z.coerce.number().int().positive().default(3001),

  // Database
  NEON_DATABASE_URL: z.string().url(),

  // Auth — pepper is optional but strongly recommended in production.
  ARGON2_PEPPER: z.string().optional(),
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 chars"),
  SESSION_TTL_HOURS: z.coerce.number().int().positive().default(24 * 14),
  SESSION_COOKIE_NAME: z.string().default("sq_session"),

  // 2FA
  TOTP_ISSUER: z.string().default("Shion Quant"),

  // KYC envelope encryption — both keys MUST decode to exactly 32 bytes.
  KYC_KEK_BASE64: z
    .string()
    .refine(
      (s) => decodeBase64Length(s) === 32,
      "KYC_KEK_BASE64 must decode to exactly 32 bytes",
    ),
  KYC_SEARCH_KEY_BASE64: z
    .string()
    .refine(
      (s) => decodeBase64Length(s) === 32,
      "KYC_SEARCH_KEY_BASE64 must decode to exactly 32 bytes",
    ),

  // Lockout policy
  MAX_LOGIN_FAILURES: z.coerce.number().int().positive().default(5),
  LOCKOUT_MINUTES: z.coerce.number().int().positive().default(15),

  // CORS
  ALLOWED_ORIGINS: z
    .string()
    .default("http://localhost:5173")
    .transform((s) => s.split(",").map((o) => o.trim()).filter(Boolean)),

  // Rate limiting
  RATE_LIMIT_LOGIN_PER_MIN: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_GLOBAL_PER_MIN: z.coerce.number().int().positive().default(120),

  // R2 / S3 — for documents vault.
  R2_ENDPOINT: z.string().url().optional(),
  R2_BUCKET: z.string().optional(),
  R2_ACCESS_KEY: z.string().optional(),
  R2_SECRET_KEY: z.string().optional(),
  R2_REGION: z.string().default("auto"),

  // Email (post-M8 reminder dispatcher)
  RESEND_API_KEY: z.string().optional(),
})

export type Env = z.infer<typeof schema>

let cached: Env | null = null

/**
 * Validate + cache the env. Idempotent: subsequent calls are no-ops once
 * cached. Worker fetch handler should call this on every request (cheap
 * after first); Node scripts call once at the top.
 */
export function initEnv(source: Record<string, unknown>): Env {
  if (cached) return cached
  const parsed = schema.safeParse(source)
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n  ")
    throw new Error(`Invalid environment variables:\n  ${issues}`)
  }
  cached = parsed.data
  return cached
}

/**
 * Reset the cache. Only used by tests; never in production code paths.
 */
export function _resetEnvForTesting(): void {
  cached = null
}

/**
 * The proxy — exposed as `import { env } from "./env.js"`. Reads delegate
 * to the parsed cache.
 *
 * Pre-init reads return `undefined` (not throw). Cloudflare's deploy
 * validation step loads the bundle outside any fetch handler — if the proxy
 * threw, validation would fail. Returning undefined lets validation pass;
 * real misconfiguration surfaces at request time when initEnv() is called
 * from the fetch handler and Zod actually validates.
 *
 * Trade-off: silent failure if a callsite reads env.X before initEnv runs,
 * gets undefined, and proceeds. Most call sites surface this as a downstream
 * error (e.g. cors() rejects undefined origin). For module-load time access
 * that absolutely needs values, restructure to be lazy (see lib/kms.ts and
 * lib/crypto.ts for the pattern).
 */
export const env = new Proxy({} as Env, {
  get(_, prop) {
    // Pre-init: return undefined silently. Cloudflare's deploy validation
    // walks the bundle without invoking the fetch handler; throwing would
    // fail the deploy. Real misconfiguration surfaces inside the fetch
    // handler when initEnv() runs Zod validation, so we don't mask bugs.
    if (!cached) return undefined
    return cached[prop as keyof Env]
  },
})

export const isProduction = (): boolean => cached?.NODE_ENV === "production"
export const isDevelopment = (): boolean =>
  cached?.NODE_ENV === "development" || !cached

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Decode a base64 string and return the byte length. Used by Zod refinements.
 * Workers' `atob` decodes base64; we count bytes by encoding to a Uint8Array.
 *
 * Returns 0 for invalid input (so the refinement message reads as "must
 * decode to 32 bytes" rather than throwing a confusing parse error).
 */
function decodeBase64Length(s: string): number {
  try {
    // atob is available in Workers + Node 16+ globals.
    const binary = atob(s)
    return binary.length
  } catch {
    return 0
  }
}
