/**
 * Append-only audit log writer.
 *
 * Every mutating operation (and most security-relevant reads) should call
 * `audit()` exactly once. Per schema.sql, `audit_log` rows are NEVER updated
 * or deleted — that's enforced by trigger; do not try to UPDATE/DELETE from
 * application code.
 *
 * If the call fails, log it loudly but don't break the request — losing a
 * single audit row is recoverable; failing the user's action because audit
 * write failed is not.
 */

import { createHash } from "node:crypto"
import { db, auditLog } from "../db/client.js"

export interface AuditInput {
  action: string
  userId?: string | null
  clientId?: string | null
  ip?: string | null
  userAgent?: string | null
  resourceType?: string | null
  resourceId?: string | null
  beforeState?: unknown
  afterState?: unknown
  metadata?: Record<string, unknown>
  /** Pre-hashed request body if relevant; will hash if a string is passed. */
  requestPayload?: string | null
}

export async function audit(input: AuditInput): Promise<void> {
  try {
    const requestSha256 = input.requestPayload
      ? hashSha256Hex(input.requestPayload)
      : null

    await db.insert(auditLog).values({
      action: input.action,
      userId: input.userId ?? null,
      clientId: input.clientId ?? null,
      ip: input.ip ?? null,
      userAgent: input.userAgent ?? null,
      resourceType: input.resourceType ?? null,
      resourceId: input.resourceId ?? null,
      beforeState: input.beforeState ?? null,
      afterState: input.afterState ?? null,
      metadata: input.metadata ?? null,
      requestSha256,
    })
  } catch (err) {
    console.error("[audit] write failed", { action: input.action, err })
  }
}

function hashSha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex")
}
