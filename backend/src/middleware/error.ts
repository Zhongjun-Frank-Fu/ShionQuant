/**
 * Unified error → JSON response.
 *
 * Catches:
 *   - AppError    → typed JSON with code, message, optional details
 *   - ZodError    → 422 with the validation issues (path + message)
 *   - HTTPException (Hono native) → preserve its status/message
 *   - Anything else → 500 INTERNAL with a request-id reference; details
 *     hidden from client in production, surfaced in dev
 *
 * The shape is deliberately stable so the frontend can pattern-match `code`:
 *
 *     { ok: false, code: "...", message: "...", details?: ..., requestId: "..." }
 */

import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { ErrorHandler } from "hono"
import { HTTPException } from "hono/http-exception"
import { ZodError } from "zod"

import { isProduction } from "../env.js"
import { AppError } from "../lib/errors.js"

export const errorMiddleware: ErrorHandler = (err, c) => {
  const requestId = c.get("requestId") ?? "unknown"

  if (err instanceof AppError) {
    return c.json(
      {
        ok: false,
        code: err.code,
        message: err.message,
        details: err.details ?? undefined,
        requestId,
      },
      err.status as ContentfulStatusCode,
    )
  }

  if (err instanceof ZodError) {
    return c.json(
      {
        ok: false,
        code: "VALIDATION_ERROR",
        message: "Request validation failed",
        details: err.issues.map((i) => ({
          path: i.path.join("."),
          message: i.message,
        })),
        requestId,
      },
      422,
    )
  }

  if (err instanceof HTTPException) {
    return c.json(
      {
        ok: false,
        code: "HTTP_EXCEPTION",
        message: err.message,
        requestId,
      },
      err.status as ContentfulStatusCode,
    )
  }

  // Unknown — log and respond with a generic 500.
  console.error("[unhandled]", { requestId, err })
  return c.json(
    {
      ok: false,
      code: "INTERNAL",
      message: isProduction() ? "Internal server error" : String(err),
      requestId,
    },
    500,
  )
}
