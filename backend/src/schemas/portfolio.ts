/**
 * Zod schemas for /api/v1/portfolio/* query strings.
 *
 * All endpoints are read-only, so there are no body schemas — just query
 * parsing for filters / ranges. Hono's `c.req.query()` returns `Record<string,
 * string>`, so we use `z.coerce.*` for numbers and `z.string()` for enums.
 */

import { z } from "zod"

// ─── /portfolio/positions ─────────────────────────────────────────────────

const ASSET_TYPE = ["equity", "option", "future", "bond", "crypto", "cash"] as const

export const positionsQuerySchema = z.object({
  assetType: z.enum(ASSET_TYPE).optional(),
  /**
   * `closed=true` → include positions where closed_at IS NOT NULL.
   * Default: only open positions (closed_at IS NULL).
   */
  closed: z
    .enum(["true", "false"])
    .optional()
    .default("false")
    .transform((v) => v === "true"),
  limit: z.coerce.number().int().min(1).max(500).default(200),
  offset: z.coerce.number().int().min(0).default(0),
})

// ─── /portfolio/nav ───────────────────────────────────────────────────────

const NAV_RANGE = ["1m", "3m", "6m", "1y", "ytd", "all"] as const
export type NavRange = (typeof NAV_RANGE)[number]

export const navQuerySchema = z.object({
  range: z.enum(NAV_RANGE).default("3m"),
})

/**
 * Translate a range alias to a starting date relative to `today`.
 * Returns null for "all" (caller queries without a lower bound).
 */
export function rangeToStart(range: NavRange, today = new Date()): Date | null {
  const d = new Date(today)
  switch (range) {
    case "1m":
      d.setMonth(d.getMonth() - 1)
      return d
    case "3m":
      d.setMonth(d.getMonth() - 3)
      return d
    case "6m":
      d.setMonth(d.getMonth() - 6)
      return d
    case "1y":
      d.setFullYear(d.getFullYear() - 1)
      return d
    case "ytd":
      return new Date(today.getFullYear(), 0, 1)
    case "all":
      return null
  }
}
