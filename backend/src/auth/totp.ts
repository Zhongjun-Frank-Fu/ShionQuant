/**
 * TOTP (RFC 6238) wrapper around `otpauth`.
 *
 * Usage flow:
 *
 *   Setup:
 *     1. `generateSecret()` → store ENCRYPTED in `auth_factors.secret_encrypted`
 *     2. `provisioningUri(secret, email)` → display as QR for the user to scan
 *     3. User enters first code → call `verifyCode(secret, code)`; if valid,
 *        commit the auth_factor (mark as verified)
 *
 *   Login:
 *     1. After password OK, find user's TOTP factor
 *     2. Decrypt `secret_encrypted` → `verifyCode(secret, code)`
 *     3. On success, complete the session (`is_2fa_verified = true`)
 *
 * Window: ±1 step (30s) — defends against clock skew without weakening
 * security materially.
 */

import { Secret, TOTP } from "otpauth"

import { env } from "../env.js"

/**
 * Generate a fresh 160-bit secret. Returns the base32 string format that
 * goes into the QR code; it's also what you store (encrypted) in the DB.
 */
export function generateSecret(): string {
  return new Secret({ size: 20 }).base32
}

/**
 * Build an `otpauth://totp/...` URI suitable for QR encoding.
 * `accountName` should be the user's email or some stable identifier.
 */
export function provisioningUri(secretBase32: string, accountName: string): string {
  const totp = new TOTP({
    issuer: env.TOTP_ISSUER,
    label: accountName,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32),
  })
  return totp.toString()
}

/**
 * Verify a 6-digit code against a stored secret. Allows ±1 step of clock skew.
 *
 * Returns true on match, false on miss. Constant-time inside `otpauth`.
 */
export function verifyCode(secretBase32: string, code: string): boolean {
  const cleaned = code.replace(/\s+/g, "")
  if (!/^\d{6}$/.test(cleaned)) return false

  const totp = new TOTP({
    issuer: env.TOTP_ISSUER,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32),
  })

  // delta = null → no match; delta of -1, 0, +1 acceptable.
  const delta = totp.validate({ token: cleaned, window: 1 })
  return delta !== null
}
