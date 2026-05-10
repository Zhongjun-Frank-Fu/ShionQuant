/**
 * Zod schemas for /api/v1/account/profile + KYC sub-resources.
 *
 * Schemas accept PLAINTEXT — the route handler is responsible for envelope
 * encryption before insertion. Likewise, on read, the handler decrypts and
 * returns plaintext to the (authenticated, MFA-verified) client.
 *
 * Some KYC fields are write-once-and-locked: once a verified `legal_name`
 * exists, it can't be changed via the API; the user must contact compliance.
 * That policy is enforced in the route, not the schema (so we can still
 * accept it on first creation).
 */

import { z } from "zod"

// ─── Profile ──────────────────────────────────────────────────────────────

const isoDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "must be YYYY-MM-DD")
const isoCountry = z.string().length(2).toUpperCase()

const quietHoursSchema = z
  .object({
    start: z.string().regex(/^\d{2}:\d{2}$/, "must be HH:MM"),
    end: z.string().regex(/^\d{2}:\d{2}$/, "must be HH:MM"),
    timezone: z.string().min(1).max(64),
  })
  .strict()

/**
 * Fields any profile owner can patch. Locked KYC fields (legal_name, DOB,
 * HKID, passport) are excluded — the route allows them only in the initial
 * create flow.
 */
export const profilePatchSchema = z
  .object({
    primaryEmail: z.string().email().max(254).toLowerCase().trim().optional(),
    primaryPhone: z
      .string()
      .min(1)
      .max(40)
      .regex(/^[+0-9 \-()]+$/, "invalid phone characters")
      .optional(),
    preferredChannel: z
      .enum(["email", "portal", "whatsapp", "phone"])
      .optional(),
    quietHoursLocal: quietHoursSchema.nullable().optional(),
    marketingConsent: z.boolean().optional(),
    caseStudyConsent: z.boolean().optional(),
  })
  .strict()

/**
 * The first time a profile row is created (no existing profile for this
 * client), require the locked KYC fields.
 */
export const profileCreateSchema = profilePatchSchema.extend({
  legalName: z.string().min(1).max(200).trim(),
  dateOfBirth: isoDate.optional(),
  nationality: isoCountry.optional(),
  hkid: z.string().min(1).max(20).optional(),
  passport: z.string().min(1).max(50).optional(),
})

// ─── Beneficiaries ────────────────────────────────────────────────────────

const RELATION = ["spouse", "daughter", "son", "accountant", "other"] as const
const PERMISSIONS = ["none", "read", "read_trade", "tax_only", "limited"] as const

export const beneficiaryCreateSchema = z
  .object({
    fullName: z.string().min(1).max(200).trim(),
    displayLabel: z.string().max(80).optional(),
    relation: z.enum(RELATION),
    sharePct: z.number().min(0).max(100).optional(),
    permissions: z.enum(PERMISSIONS).default("none"),
    contact: z
      .object({
        email: z.string().email().max(254).optional(),
        phone: z.string().max(40).optional(),
        notes: z.string().max(500).optional(),
      })
      .strict()
      .optional(),
    revisitAt: isoDate.optional(),
  })
  .strict()

export const beneficiaryPatchSchema = beneficiaryCreateSchema.partial()

// ─── Addresses ────────────────────────────────────────────────────────────

export const addressCreateSchema = z
  .object({
    kind: z.enum(["residential", "mailing", "office"]),
    line1: z.string().min(1).max(200),
    line2: z.string().max(200).optional(),
    city: z.string().max(100).optional(),
    region: z.string().max(100).optional(),
    countryIso: isoCountry,
    postalCode: z.string().max(20).optional(),
    isPrimary: z.boolean().default(false),
  })
  .strict()

export const addressPatchSchema = addressCreateSchema.partial()

// ─── Tax residency ────────────────────────────────────────────────────────

export const taxResidencyCreateSchema = z
  .object({
    countryIso: isoCountry,
    taxId: z.string().min(1).max(50).optional(),
    isPrimary: z.boolean().default(false),
    treatyForm: z.string().max(20).optional(),
    treatyFormSignedAt: z.string().datetime().optional(),
    treatyFormRenewsAt: z.string().datetime().optional(),
    establishedAt: z.string().datetime().optional(),
  })
  .strict()

export const taxResidencyPatchSchema = taxResidencyCreateSchema.partial()
