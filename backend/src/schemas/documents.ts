/**
 * Zod schemas for /api/v1/documents/*.
 */

import { z } from "zod"

// ─── Enum mirrors of schema.ts ────────────────────────────────────────────

const CATEGORY = [
  "statement",
  "tax",
  "custody",
  "engagement",
  "compliance",
  "banking",
  "misc",
] as const

const FILE_FORMAT = ["pdf", "xlsx", "docx", "jpg", "png", "csv", "txt"] as const

const STATUS = ["active", "pending_signature", "expired", "superseded"] as const

const SIGNATURE_METHOD = ["drawn", "typed", "docusign"] as const

const REQUEST_TYPE = [
  "bank_ref",
  "asset_confirm",
  "reconstruct",
  "cost_basis",
  "tax_pkg",
  "custom",
] as const

const REQUEST_FORMAT = ["pdf_digital", "pdf_wet", "hardcopy", "notarized"] as const

// ─── List query ───────────────────────────────────────────────────────────

export const listQuerySchema = z.object({
  category: z.enum(CATEGORY).optional(),
  status: z.enum(STATUS).optional(),
  taxYear: z.coerce.number().int().min(2000).max(2099).optional(),
  archived: z
    .enum(["true", "false"])
    .optional()
    .default("false")
    .transform((v) => v === "true"),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
})

// ─── Upload-URL request ───────────────────────────────────────────────────

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024 // 100 MB

export const uploadUrlSchema = z
  .object({
    title: z.string().min(1).max(200).trim(),
    category: z.enum(CATEGORY),
    fileFormat: z.enum(FILE_FORMAT),
    fileSizeBytes: z.number().int().positive().max(MAX_UPLOAD_BYTES),
    description: z.string().max(2000).optional(),
    sourceLabel: z.string().max(100).optional(),
    sourceParty: z.string().max(100).optional(),
    tags: z.array(z.string().min(1).max(40)).max(10).optional(),
    taxYear: z.number().int().min(2000).max(2099).optional(),
    issuedAt: z.string().datetime().optional(),
  })
  .strict()

// ─── Finalize (after R2 PUT succeeds) ─────────────────────────────────────

export const finalizeUploadSchema = z
  .object({
    /** Hex-encoded SHA-256 of the uploaded bytes. Compared against R2 HEAD. */
    sha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/i, "must be 64-char lowercase hex"),
  })
  .strict()

// ─── Sign ─────────────────────────────────────────────────────────────────

export const signSchema = z
  .object({
    signatureMethod: z.enum(SIGNATURE_METHOD),
    /** For "drawn" or "typed" — URL of a signature image stored elsewhere
     *  (M4 stores the URL string only; image upload is a separate flow). */
    signatureImageUrl: z.string().url().max(500).optional(),
    /** For "typed" — the signer's typed legal name. */
    typedName: z.string().min(1).max(200).optional(),
    /** For "docusign" — the envelope ref returned by DocuSign. */
    envelopeRef: z.string().max(200).optional(),
  })
  .strict()
  .refine(
    (v) => {
      if (v.signatureMethod === "typed" && !v.typedName) return false
      if (v.signatureMethod === "docusign" && !v.envelopeRef) return false
      return true
    },
    { message: "missing required field for the chosen signatureMethod" },
  )

// ─── Document request ─────────────────────────────────────────────────────

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "must be YYYY-MM-DD")

export const documentRequestCreateSchema = z
  .object({
    requestType: z.enum(REQUEST_TYPE),
    purpose: z.string().max(2000).optional(),
    recipient: z.string().max(200).optional(),
    asOfDate: isoDate.optional(),
    neededByDate: isoDate.optional(),
    format: z.enum(REQUEST_FORMAT),
    notes: z.string().max(2000).optional(),
  })
  .strict()
