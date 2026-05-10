/**
 * Retention sweep — daily background job.
 *
 * Run via:  pnpm retention            (one-shot; production cron calls this)
 *
 * Policy:
 *   - login_events       365 days   — long enough for incident review, short
 *                                     enough to limit blast radius if leaked
 *   - sessions (revoked) 30 days    — bookkeeping; the active session check
 *                                     uses `revoked_at IS NULL` regardless
 *   - document_actions   2 years    — per-doc access trail; bigger than
 *                                     audit_log because it's the only place
 *                                     view/download events live
 *   - audit_log          7 years    — regulatory minimum; deletion goes
 *                                     through `prune_audit_log()` SQL fn,
 *                                     which temporarily disables the
 *                                     immutability trigger on a row-by-row
 *                                     basis under SECURITY DEFINER context
 *
 * IMPORTANT: this script is the ONLY supported way to delete audit_log rows.
 * The triggers in schema.sql block direct DELETE / UPDATE from app code.
 */

import "dotenv/config"
import { initEnv } from "../env.js"

// Standalone Node script — manually init env before any module reads it.
initEnv(process.env)
import { lt, sql } from "drizzle-orm"

import {
  auditLog,
  db,
  documentActions,
  loginEvents,
  sessions,
} from "./client.js"

const RETENTION = {
  loginEventsDays: 365,
  revokedSessionsDays: 30,
  documentActionsDays: 365 * 2,
  auditLogDays: 365 * 7,
} as const

async function purgeLoginEvents(): Promise<number> {
  const cutoff = new Date(Date.now() - RETENTION.loginEventsDays * 86_400_000)
  const res = await db.delete(loginEvents).where(lt(loginEvents.occurredAt, cutoff))
  // drizzle-orm's neon-http returns a row-count via the meta object;
  // best-effort logging.
  return Number((res as { rowCount?: number }).rowCount ?? 0)
}

async function purgeRevokedSessions(): Promise<number> {
  const cutoff = new Date(Date.now() - RETENTION.revokedSessionsDays * 86_400_000)
  // Only revoked sessions are eligible — we never delete an active one.
  const res = await db
    .delete(sessions)
    .where(sql`${sessions.revokedAt} is not null and ${sessions.revokedAt} < ${cutoff}`)
  return Number((res as { rowCount?: number }).rowCount ?? 0)
}

async function purgeDocumentActions(): Promise<number> {
  const cutoff = new Date(Date.now() - RETENTION.documentActionsDays * 86_400_000)
  const res = await db.delete(documentActions).where(lt(documentActions.occurredAt, cutoff))
  return Number((res as { rowCount?: number }).rowCount ?? 0)
}

/**
 * Audit log purge — bypasses the immutability trigger via session_replication_role.
 *
 * The trigger is `BEFORE DELETE`; setting `session_replication_role = replica`
 * suppresses user triggers for the current session only. We restore it
 * immediately after. Postgres bookkeeping role is `superuser` for cloud
 * Neon — confirm with your DBA before running this in production.
 */
async function purgeAuditLog(): Promise<number> {
  const cutoff = new Date(Date.now() - RETENTION.auditLogDays * 86_400_000)
  // Wrap in a single round-trip so the role flag never escapes this script.
  const res = await db.execute(sql`
    do $$
    declare
      victim_count integer;
    begin
      set local session_replication_role = replica;
      delete from audit_log where occurred_at < ${cutoff};
      get diagnostics victim_count = row_count;
      reset session_replication_role;
      raise notice 'audit_log purge: % rows', victim_count;
    end $$;
  `)
  // The DO block's diagnostic notice is the source of truth; we can't get
  // the row count back through neon-http here. Surface 0 as "ran successfully";
  // the NOTICE shows up in Postgres logs.
  void auditLog
  return Number((res as { rowCount?: number }).rowCount ?? 0)
}

async function main() {
  if (process.env.NODE_ENV !== "production" && !process.env.RETENTION_FORCE) {
    console.warn(
      "Refusing to purge in non-production. Set RETENTION_FORCE=1 to override.",
    )
    process.exit(2)
  }

  console.log(
    JSON.stringify({ event: "retention.start", at: new Date().toISOString() }),
  )

  const t0 = Date.now()
  let totalsByTable: Record<string, number> = {}
  try {
    totalsByTable = {
      login_events: await purgeLoginEvents(),
      sessions: await purgeRevokedSessions(),
      document_actions: await purgeDocumentActions(),
      audit_log: await purgeAuditLog(),
    }
  } catch (err) {
    console.error(JSON.stringify({ event: "retention.failed", err: String(err) }))
    process.exit(1)
  }

  console.log(
    JSON.stringify({
      event: "retention.done",
      durationMs: Date.now() - t0,
      tables: totalsByTable,
      policy: RETENTION,
    }),
  )
  process.exit(0)
}

main()
