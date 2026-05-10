/**
 * Argon2id password hashing — Workers-compatible implementation via hash-wasm.
 *
 * The native @node-rs/argon2 binding doesn't run on Cloudflare Workers
 * (V8 isolates have no Node native module support). hash-wasm ships a pure
 * WebAssembly Argon2 that's CPU-time-comparable to the native version and
 * runs identically on Node + Workers + Bun + Deno.
 *
 * Parameters (OWASP 2024 — m=19 MiB, t=2, p=1):
 *   We've moved DOWN from the native build's 64 MiB / t=3 / p=4 because:
 *     - Workers cap each invocation at 128 MiB total, so 64 MiB hash memory
 *       leaves no headroom for the Hono stack + AWS SDK + Drizzle.
 *     - 19 MiB / t=2 / p=1 is OWASP's middle-tier recommendation; still
 *       strong against modern GPU/ASIC attackers.
 *     - On a Workers Paid CPU (~50 ms per request budget), this configuration
 *       hashes in ~30-50 ms — well within the 30 s cap.
 *
 * Pepper handling — the BIG difference vs the native build:
 *   @node-rs/argon2 supported the RFC 9106 `secret` parameter natively.
 *   hash-wasm doesn't expose it. We approximate by concatenating the pepper
 *   to the password BEFORE hashing — security-equivalent in practice (an
 *   attacker who steals the DB still needs the pepper to test guesses) but
 *   slightly different from the spec. Pepper rotation requires re-hashing.
 *
 * Hash format on the wire:
 *   `$argon2id$v=19$m=19456,t=2,p=1$<salt-base64>$<hash-base64>`
 *   Compatible with anything else that reads PHC strings. Self-describing —
 *   the params are encoded in the string, so verify() doesn't need
 *   parameters supplied separately.
 */

import { argon2id, argon2Verify } from "hash-wasm"

import { env } from "../env.js"

// ─── Configuration ─────────────────────────────────────────────────────────

// OWASP 2024 middle-tier params. Tune `iterations` upward as hardware
// improves; `verifyPassword()` returns a fresh hash via `newHash` whenever
// the stored params are below current targets, so caller can transparently
// UPDATE on next successful login.
const PARALLELISM = 1
const ITERATIONS = 2
const MEMORY_KIB = 19456 // 19 MiB
const HASH_LENGTH = 32
const SALT_LENGTH = 16

// Minimum password length policy (also enforced at API layer).
const MIN_PASSWORD_LENGTH = 12

/**
 * Apply the optional pepper (RFC 9106 §3.1 spec calls it `secret`).
 * hash-wasm doesn't take a separate secret arg, so we prefix the password
 * with the pepper. An attacker with the DB but not the pepper can't verify
 * candidate passwords, which is the security property we wanted.
 */
function withPepper(password: string): string {
  const pepper = env.ARGON2_PEPPER ?? ""
  return pepper.length > 0 ? `${pepper}\x00${password}` : password
}

/** Generate a random salt using Web Crypto (works on Workers + Node 16+). */
function randomSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_LENGTH)
  crypto.getRandomValues(salt)
  return salt
}

// ─── Public API ───────────────────────────────────────────────────────────

/**
 * Hash a plaintext password.
 *
 * Returns the encoded hash string (~96 chars), e.g.:
 *     $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
 *
 * Store this in `users.password_hash` (TEXT column).
 */
export async function hashPassword(password: string): Promise<string> {
  if (!password) throw new Error("password must not be empty")
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }
  return argon2id({
    password: withPepper(password),
    salt: randomSalt(),
    parallelism: PARALLELISM,
    iterations: ITERATIONS,
    memorySize: MEMORY_KIB,
    hashLength: HASH_LENGTH,
    outputType: "encoded",
  })
}

/**
 * Hash a system-generated secret (recovery code, API token, etc.) — same
 * Argon2id parameters as `hashPassword`, but skips the password-length
 * policy. Use for inputs you control the entropy of (10-char recovery codes
 * from a 32-symbol alphabet have ~50 bits, plenty without the user-password
 * minimum).
 */
export async function hashSecret(secret: string): Promise<string> {
  if (!secret) throw new Error("secret must not be empty")
  return argon2id({
    password: withPepper(secret),
    salt: randomSalt(),
    parallelism: PARALLELISM,
    iterations: ITERATIONS,
    memorySize: MEMORY_KIB,
    hashLength: HASH_LENGTH,
    outputType: "encoded",
  })
}

/**
 * Verify a password against a stored hash. Constant-time inside hash-wasm.
 *
 * Returns:
 *   { ok: true }                       — password matches, no rehash needed
 *   { ok: true, newHash: "..." }       — matches; stored hash uses outdated
 *                                         params and SHOULD be UPDATEd
 *   { ok: false }                      — wrong password OR malformed hash
 *
 * IMPORTANT: collapse both wrong-password and malformed-hash to `{ ok: false }`
 * — never let the difference leak to callers / logs / responses.
 */
export async function verifyPassword(
  storedHash: string,
  password: string,
): Promise<{ ok: boolean; newHash?: string }> {
  let ok = false
  try {
    ok = await argon2Verify({
      password: withPepper(password),
      hash: storedHash,
    })
  } catch {
    return { ok: false }
  }
  if (!ok) return { ok: false }

  if (needsRehash(storedHash)) {
    return { ok: true, newHash: await hashPassword(password) }
  }
  return { ok: true }
}

/**
 * Run a hash verification against a known-bad input, to normalize response
 * time when a login email doesn't exist in the DB. Prevents user enumeration
 * via timing side-channel.
 *
 * Usage in /api/v1/auth/login:
 *
 *     const user = await db.query.users.findFirst({ where: ... })
 *     if (!user) {
 *       await dummyVerify()              // ~30-50 ms
 *       return c.json({ ok: false }, 401)
 *     }
 *     const result = await verifyPassword(user.passwordHash, password)
 */
export async function dummyVerify(): Promise<void> {
  // A pre-computed throwaway hash with our current params. The verify will
  // fail; the time spent is what matters. The salt is fixed; that's fine
  // for a sentinel — it's never compared to real user data.
  const sentinelHash =
    "$argon2id$v=19$m=19456,t=2,p=1$" +
    "YWFhYWFhYWFhYWFhYWFhYQ$" + // 'aaaaaaaaaaaaaaaa' base64
    "TZGvFQOHPYDi+0bMJ5fEW7L/3i80yLkUBgWgu0+pmkY"
  try {
    await argon2Verify({
      password: "definitely-not-the-password",
      hash: sentinelHash,
    })
  } catch {
    /* expected; timing-only */
  }
}

/**
 * Generate one-time-use recovery codes for 2FA bypass.
 * Format: XXXXX-XXXXX (10 chars from a confusables-free alphabet, ~50 bits).
 *
 * Caller responsibilities:
 *   1. Show the codes ONCE to the user (download / print)
 *   2. Hash each with `hashSecret()` and store in `recovery_codes` table
 *   3. On consumption, mark the row as used (do NOT delete; audit trail)
 */
export function generateRecoveryCodes(n = 10): string[] {
  // No I, O, 0, 1 — avoids handwritten confusion.
  const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
  const codes: string[] = []
  // Use Web Crypto for cross-runtime randomness (Workers + Node).
  const buf = new Uint8Array(n * 10)
  crypto.getRandomValues(buf)
  for (let i = 0; i < n; i++) {
    let body = ""
    for (let j = 0; j < 10; j++) {
      const r = buf[i * 10 + j]
      // Modulo bias is fine here — 256 % 32 = 0, perfectly uniform.
      body += ALPHABET[r! % ALPHABET.length]
    }
    codes.push(`${body.slice(0, 5)}-${body.slice(5)}`)
  }
  return codes
}

// ─── Internal ─────────────────────────────────────────────────────────────

/**
 * Check whether the stored hash uses parameters below current targets.
 * Returns true → caller should rehash + UPDATE on next successful login.
 */
function needsRehash(stored: string): boolean {
  const m = stored.match(/^\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)/)
  if (!m || m.length < 4) return true
  const mem = m[1] ?? ""
  const time = m[2] ?? ""
  const par = m[3] ?? ""
  return (
    Number.parseInt(mem, 10) < MEMORY_KIB ||
    Number.parseInt(time, 10) < ITERATIONS ||
    Number.parseInt(par, 10) < PARALLELISM
  )
}
