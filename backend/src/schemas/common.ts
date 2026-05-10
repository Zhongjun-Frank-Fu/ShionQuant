/**
 * Reusable Zod schemas.
 */

import { z } from "zod"

export const uuidSchema = z.string().uuid()

export const isoDate = z.string().datetime({ offset: true })

/** Pagination cursor — opaque base64-encoded JSON. */
export const cursorSchema = z.string().optional()

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: cursorSchema,
})
