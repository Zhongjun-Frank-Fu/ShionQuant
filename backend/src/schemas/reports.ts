/**
 * Zod schemas for /api/v1/reports/*.
 */

import { z } from "zod"

// Mirror schema.ts unions.
const REPORT_TYPE = [
  "risk_attribution",
  "performance",
  "strategy_memo",
  "macro",
  "custom",
] as const

const SUBSCRIPTION_CHANNEL = ["email", "push", "portal"] as const

const PROJECT_TYPE = [
  "strategy",
  "deepdive",
  "backtest",
  "taxopt",
  "automation",
  "other",
] as const

const TIMELINE = ["rush", "standard", "flexible"] as const

// ─── List query ───────────────────────────────────────────────────────────

export const listQuerySchema = z.object({
  type: z.enum(REPORT_TYPE).optional(),
  bookmarked: z
    .enum(["true", "false"])
    .optional()
    .transform((v) => v === "true"),
  /** "mine" = client-specific reports only; "firm" = firm-wide only; default = both. */
  scope: z.enum(["mine", "firm", "all"]).optional().default("all"),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
})

// ─── Subscriptions ────────────────────────────────────────────────────────

/**
 * Bulk-set channel preferences across report types. Each entry replaces the
 * channel list for that `reportType`. Pass `channels: []` to silence a type.
 */
export const subscriptionsPatchSchema = z
  .object({
    subscriptions: z
      .array(
        z
          .object({
            reportType: z.enum(REPORT_TYPE),
            channels: z.array(z.enum(SUBSCRIPTION_CHANNEL)).max(3),
          })
          .strict(),
      )
      .min(1)
      .max(REPORT_TYPE.length),
  })
  .strict()

// ─── Custom research requests ─────────────────────────────────────────────

export const customRequestCreateSchema = z
  .object({
    projectType: z.enum(PROJECT_TYPE),
    workingTitle: z.string().min(1).max(200).trim().optional(),
    question: z.string().min(20).max(4000).trim(),
    linkedTickers: z
      .array(z.string().toUpperCase().min(1).max(20))
      .max(20)
      .optional(),
    capitalAtStake: z.number().nonnegative().max(1e12).optional(),
    timelinePref: z.enum(TIMELINE).optional(),
    referenceMaterials: z.string().max(4000).optional(),
  })
  .strict()
