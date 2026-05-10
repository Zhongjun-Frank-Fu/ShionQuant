/**
 * Argon2id password hashing — pure-JS implementation via @noble/hashes.
 *
 * Why not hash-wasm:
 *   hash-wasm needs runtime `WebAssembly.compile(buffer)` which Cloudflare
 *   Workers blocks in production ("Wasm code generation disallowed by
 *   embedder"). All WASM in Workers must be bound at deploy time via
 *   wrangler.toml `[[wasm_modules]]`, and hash-wasm's API doesn't support
 *   external module injection. Switched to @noble/hashes/argon2 which is
 *   pure JS — slower than WASM but works identically across Node, Workers,
 *   browsers, Bun, and Deno.
 *
 * Why not @node-rs/argon2:
 *   Native Node bindings won't run in V8 isolates either.
 *
 * Performance note:
 *   Pure-JS argon2id with m=19456 (19 MiB), t=2, p=1 takes roughly 100–300 ms
 *   on a Workers Paid CPU — within the 30 s limit and acceptable for an auth
 *   endpoint where we already pay 50–100 ms in DB round-trips. If hashing
 *   becomes a bottleneck, the right move is to bind the WASM module via
 *   wrangler config (more invasive but ~3× faster) rather than to revert.
 *
 * Parameters (OWASP 2024 — m=19 MiB, t=2, p=1):
 *   See ITERATIONS / MEMORY_KIB constants below. Tune `iterations` upward
 *   as hardware improves; `verifyPassword()` returns a fresh hash via
 *   `newHash` whenever the stored params are below current targets, so
 *   callers can transparently UPDATE on next successful login.
 *
 * Pepper handling — same strategy as the previous hash-wasm impl:
 *   noble's argon2 doesn't accept the RFC 9106 `secret` parameter either
 *   (it isn't part of the basic API), so we approximate by concatenating
 *   the pepper to the password BEFORE hashing. Security-equivalent in
 *   practice. Pepper rotation requires re-hashing on next login.
 *
 * Hash format on the wire:
 *   `$argon2id$v=19$m=19456,t=2,p=1$<salt-base64>$<hash-base64>`
 *   Compatible with anything else that reads PHC strings (verify across
 *   any argon2 implementation that follows the spec). The `<base64>` here
 *   is "PHC base64" — standard base64 alphabet but WITHOUT trailing `=`
 *   padding. We strip on encode and accept either form on parse.
 */

import { argon2id } from "@noble/hashes/argon2.js"

import { env } from "../env.js"

// ─── Configuration ─────────────────────────────────────────────────────────

const PARALLELISM = 1
const ITERATIONS = 2
const MEMORY_KIB = 19456 // 19 MiB
const HASH_LENGTH = 32
const SALT_LENGTH = 16

// Minimum password length policy (also enforced at API layer).
const MIN_PASSWORD_LENGTH = 12

/**
 * Apply the optional pepper. We prefix the password with the pepper +
 * a NUL separator (avoids ambiguity if a future pepper happens to be a
 * valid prefix of a password). An attacker with the DB but not the pepper
 * can't verify candidate passwords — the security property we wanted.
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

// ─── PHC string encoder / parser ──────────────────────────────────────────

/**
 * Encode raw argon2 output as a PHC-format string.
 * Format: `$argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt-b64>$<hash-b64>`
 * "PHC base64" = standard base64 with `=` padding stripped.
 */
function encodePhc(salt: Uint8Array, hash: Uint8Array, params: {
  m: number
  t: number
  p: number
}): string {
  const saltB64 = base64NoPad(salt)
  const hashB64 = base64NoPad(hash)
  return `$argon2id$v=19$m=${params.m},t=${params.t},p=${params.p}$${saltB64}$${hashB64}`
}

interface ParsedPhc {
  v: number
  m: number
  t: number
  p: number
  salt: Uint8Array
  hash: Uint8Array
}

/**
 * Parse a PHC string into params + salt + hash bytes. Throws if the format
 * doesn't match. Caller (verifyPassword) maps any throw to `{ok: false}` so
 * malformed hashes don't leak as a different response code.
 */
function parsePhc(stored: string): ParsedPhc {
  // Anchored regex — anything off-spec rejects.
  const m = stored.match(
    /^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/,
  )
  if (!m) throw new Error("malformed argon2 PHC string")
  return {
    v: Number.parseInt(m[1]!, 10),
    m: Number.parseInt(m[2]!, 10),
    t: Number.parseInt(m[3]!, 10),
    p: Number.parseInt(m[4]!, 10),
    salt: base64Decode(m[5]!),
    hash: base64Decode(m[6]!),
  }
}

function base64NoPad(bytes: Uint8Array): string {
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  // btoa exists on Workers + modern Node (>=16).
  return btoa(bin).replace(/=+$/, "")
}

function base64Decode(str: string): Uint8Array {
  // Re-pad if caller stripped `=`. atob requires padding to multiple of 4.
  const padding = (4 - (str.length % 4)) % 4
  const padded = str + "=".repeat(padding)
  const bin = atob(padded)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/**
 * Constant-time byte-array comparison. Returns true iff the arrays are
 * equal. NEVER use `===` or `Buffer.compare()` on hash output — timing leaks
 * via early-exit comparison can let an attacker recover the hash.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
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
  const salt = randomSalt()
  const raw = argon2id(withPepper(password), salt, {
    t: ITERATIONS,
    m: MEMORY_KIB,
    p: PARALLELISM,
    dkLen: HASH_LENGTH,
  })
  return encodePhc(salt, raw, { m: MEMORY_KIB, t: ITERATIONS, p: PARALLELISM })
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
  const salt = randomSalt()
  const raw = argon2id(withPepper(secret), salt, {
    t: ITERATIONS,
    m: MEMORY_KIB,
    p: PARALLELISM,
    dkLen: HASH_LENGTH,
  })
  return encodePhc(salt, raw, { m: MEMORY_KIB, t: ITERATIONS, p: PARALLELISM })
}

/**
 * Verify a password against a stored hash. Constant-time comparison on the
 * derived hash bytes; argon2 itself is intrinsically constant-time per
 * fixed parameters.
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
  let parsed: ParsedPhc
  try {
    parsed = parsePhc(storedHash)
  } catch {
    return { ok: false }
  }

  let recomputed: Uint8Array
  try {
    recomputed = argon2id(withPepper(password), parsed.salt, {
      t: parsed.t,
      m: parsed.m,
      p: parsed.p,
      dkLen: parsed.hash.length,
    })
  } catch {
    return { ok: false }
  }

  if (!constantTimeEqual(recomputed, parsed.hash)) return { ok: false }

  if (
    parsed.m < MEMORY_KIB ||
    parsed.t < ITERATIONS ||
    parsed.p < PARALLELISM
  ) {
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
 *       await dummyVerify()              // ~100-300 ms
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
    await verifyPassword(sentinelHash, "definitely-not-the-password")
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
