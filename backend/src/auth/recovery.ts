/**
 * Recovery code helpers — generation + hashing + single-use consumption.
 *
 * Codes are generated client-side via `generateRecoveryCodes` (in argon2.ts),
 * shown ONCE to the user, and stored hashed (Argon2id) in `recovery_codes`.
 *
 * On consumption: scan all of the user's unused codes, verify against each.
 * Mark the matching row as used; do NOT delete (audit trail). One-use only.
 *
 * For a small N (typically 10), linear scan is fine. With more codes
 * a stored deterministic hash prefix could narrow the candidate set first.
 */

import { and, eq, isNull } from "drizzle-orm"

import { hashSecret, verifyPassword } from "./argon2.js"
import { db, recoveryCodes } from "../db/client.js"

/**
 * Hash the codes for storage. Caller inserts them as `recovery_codes` rows.
 * Uses `hashSecret` (not `hashPassword`) — recovery codes are 11 chars and
 * shouldn't go through the user-password length policy.
 */
export async function hashRecoveryCodes(codes: string[]): Promise<string[]> {
  return Promise.all(codes.map((c) => hashSecret(c)))
}

/**
 * Try to consume a recovery code for a user.
 *
 * Returns:
 *   { ok: true,  remaining: N }  — code matched, marked used; N codes still unused
 *   { ok: false }                 — no unused code matched
 */
export async function consumeRecoveryCode(
  userId: string,
  candidate: string,
  ip: string,
): Promise<{ ok: boolean; remaining?: number }> {
  const candidates = await db.query.recoveryCodes.findMany({
    where: and(eq(recoveryCodes.userId, userId), isNull(recoveryCodes.usedAt)),
  })
  if (candidates.length === 0) return { ok: false }

  for (const row of candidates) {
    const result = await verifyPassword(row.codeHash, candidate)
    if (result.ok) {
      await db
        .update(recoveryCodes)
        .set({ usedAt: new Date(), usedIp: ip })
        .where(eq(recoveryCodes.id, row.id))
      return { ok: true, remaining: candidates.length - 1 }
    }
  }
  return { ok: false }
}
