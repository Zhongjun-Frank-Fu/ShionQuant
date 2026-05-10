/**
 * Zod schemas for /api/v1/account/security/*.
 */

import { z } from "zod"

// ─── Password change ──────────────────────────────────────────────────────

export const passwordChangeSchema = z
  .object({
    currentPassword: z.string().min(1).max(1024),
    newPassword: z.string().min(12).max(1024),
  })
  .strict()
  .refine((v) => v.currentPassword !== v.newPassword, {
    message: "newPassword must differ from currentPassword",
    path: ["newPassword"],
  })

// ─── TOTP self-service ────────────────────────────────────────────────────

/**
 * /security/2fa/totp/setup — server returns a freshly-generated secret +
 * provisioning URI. The factor is created with `revokedAt = NULL` but does
 * NOT get the user MFA-verified for the current session — that requires
 * /verify with a real TOTP code.
 *
 * No body is needed; the request is authenticated and that's enough.
 */
export const totpVerifySchema = z
  .object({
    /** 6-digit code from the user's authenticator app. */
    code: z.string().regex(/^\d{6}$/, "must be 6 digits"),
    /** The factorId returned by /setup (so /verify is bound to that secret). */
    factorId: z.string().uuid(),
    /** Optional human label for the factor (shown on the security page). */
    label: z.string().min(1).max(80).optional(),
  })
  .strict()

export const totpDisableSchema = z
  .object({
    /** Re-prove identity before disabling a factor — same model as password
     *  change. Catches "lost device + still logged in elsewhere" attacks. */
    currentPassword: z.string().min(1).max(1024),
  })
  .strict()

// ─── API tokens ───────────────────────────────────────────────────────────

const SCOPE = ["read:portfolio", "read:reports", "read:documents"] as const

export const tokenCreateSchema = z
  .object({
    name: z.string().min(1).max(80).trim(),
    scopes: z.array(z.enum(SCOPE)).min(1).max(SCOPE.length),
  })
  .strict()

// ─── Login history query ──────────────────────────────────────────────────

export const loginHistoryQuerySchema = z.object({
  /** Inclusive ISO start. Default: 90 days ago. Max range: 365 days. */
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
  offset: z.coerce.number().int().min(0).default(0),
})
