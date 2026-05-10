/**
 * Domain-level error types.
 *
 * Throw these from business logic; `errorMiddleware` catches and converts to
 * a stable JSON response. Never throw raw `Error` from a route — the client
 * loses the type/message structure.
 */

export type ErrorCode =
  | "BAD_REQUEST"
  | "UNAUTHENTICATED"
  | "MFA_REQUIRED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "CONFLICT"
  | "VALIDATION_ERROR"
  | "RATE_LIMITED"
  | "LOCKED"
  | "NOT_IMPLEMENTED"
  | "INTERNAL"

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  BAD_REQUEST: 400,
  VALIDATION_ERROR: 422,
  UNAUTHENTICATED: 401,
  MFA_REQUIRED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  LOCKED: 423,
  RATE_LIMITED: 429,
  NOT_IMPLEMENTED: 501,
  INTERNAL: 500,
}

export class AppError extends Error {
  readonly code: ErrorCode
  readonly status: number
  readonly details?: unknown

  constructor(code: ErrorCode, message: string, details?: unknown) {
    super(message)
    this.code = code
    this.status = STATUS_BY_CODE[code]
    this.details = details
    Error.captureStackTrace?.(this, AppError)
  }
}

// ─── Convenience constructors ──────────────────────────────────────────────

export const badRequest = (message: string, details?: unknown) =>
  new AppError("BAD_REQUEST", message, details)

export const unauthenticated = (message = "Authentication required") =>
  new AppError("UNAUTHENTICATED", message)

export const mfaRequired = (message = "MFA verification required") =>
  new AppError("MFA_REQUIRED", message)

export const forbidden = (message = "Forbidden") => new AppError("FORBIDDEN", message)

export const notFound = (message = "Not found") => new AppError("NOT_FOUND", message)

export const conflict = (message: string) => new AppError("CONFLICT", message)

export const validation = (message: string, details?: unknown) =>
  new AppError("VALIDATION_ERROR", message, details)

export const rateLimited = (message = "Too many requests, please slow down") =>
  new AppError("RATE_LIMITED", message)

export const locked = (message = "Account locked") => new AppError("LOCKED", message)

export const notImplemented = (route: string) =>
  new AppError("NOT_IMPLEMENTED", `${route} is scaffolded but not yet implemented`)
