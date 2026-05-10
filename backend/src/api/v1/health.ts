/**
 * /api/v1/health/* — internal health + compliance checks.
 *
 *   GET /health/compliance   one-shot self-test that production monitors
 *                            scrape into a dashboard. NOT auth-gated for
 *                            now (returns no PII), but a private network
 *                            ACL should fence it in production.
 *
 * The check exercises the four invariants we promise the auditor:
 *   1. The KEK is loaded and round-trips a test ciphertext (Local KMS up)
 *   2. The deterministic-hash site key is loaded and produces consistent
 *      output across calls
 *   3. The audit_log immutable triggers are installed (UPDATE/DELETE blocked)
 *   4. The session secret is at least 32 chars (caller config sanity)
 *
 * Each check returns `{ ok, detail? }`. Top-level `ok` is the AND of all four.
 *
 * NB: /health (without /api/v1) is a separate liveness probe in src/index.ts.
 */

import { sql } from "drizzle-orm"
import { Hono } from "hono"

import { db } from "../../db/client.js"
import { env } from "../../env.js"
import {
  decryptSecret,
  deterministicHash,
  encryptSecret,
} from "../../lib/crypto.js"

const app = new Hono()

interface CheckResult {
  ok: boolean
  detail?: string
}

async function checkEnvelopeRoundTrip(): Promise<CheckResult> {
  try {
    const testInput = `health-check ${Date.now()}`
    const enc = await encryptSecret(testInput)
    const dec = await decryptSecret(enc)
    if (dec !== testInput) {
      return { ok: false, detail: "decrypt produced different plaintext" }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, detail: String(err) }
  }
}

async function checkDeterministicHash(): Promise<CheckResult> {
  try {
    const a = deterministicHash("health-check-anchor")
    const b = deterministicHash("health-check-anchor")
    if (!a.equals(b)) {
      return { ok: false, detail: "site key produced inconsistent output" }
    }
    if (a.length !== 32) {
      return { ok: false, detail: `expected 32-byte hash, got ${a.length}` }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, detail: String(err) }
  }
}

/**
 * Verify the audit_log triggers are present. We can't actually attempt an
 * UPDATE — the trigger raises and we'd lose the connection's query slot for
 * an instant. Instead, query pg_trigger by name; if both rows exist, we
 * trust the trigger's body (set in schema.sql).
 */
async function checkAuditTriggers(): Promise<CheckResult> {
  try {
    const result = await db.execute<{ trigger_name: string }>(sql`
      select tgname as trigger_name
      from pg_trigger
      where tgrelid = 'audit_log'::regclass
        and tgname in ('audit_log_no_update', 'audit_log_no_delete')
    `)
    // neon-http returns { rows: [...] } shape.
    const rows = (result as unknown as { rows?: Array<{ trigger_name: string }> }).rows ?? []
    const names = new Set(rows.map((r) => r.trigger_name))
    const missing: string[] = []
    if (!names.has("audit_log_no_update")) missing.push("audit_log_no_update")
    if (!names.has("audit_log_no_delete")) missing.push("audit_log_no_delete")
    if (missing.length > 0) {
      return {
        ok: false,
        detail: `missing trigger(s): ${missing.join(", ")}. Run db/migrations/0001_audit_immutable.sql`,
      }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, detail: String(err) }
  }
}

function checkSessionSecret(): CheckResult {
  if (env.SESSION_SECRET.length < 32) {
    return {
      ok: false,
      detail: `SESSION_SECRET length ${env.SESSION_SECRET.length} < 32`,
    }
  }
  return { ok: true }
}

app.get("/compliance", async (c) => {
  const t0 = Date.now()

  const [envelope, hashCheck, triggers] = await Promise.all([
    checkEnvelopeRoundTrip(),
    checkDeterministicHash(),
    checkAuditTriggers(),
  ])
  const session = checkSessionSecret()

  const checks = {
    envelopeEncryption: envelope,
    deterministicHash: hashCheck,
    auditImmutability: triggers,
    sessionSecretLength: session,
  }

  const ok =
    envelope.ok && hashCheck.ok && triggers.ok && session.ok

  return c.json(
    {
      ok,
      checks,
      env: env.NODE_ENV,
      durationMs: Date.now() - t0,
      at: new Date().toISOString(),
    },
    ok ? 200 : 503,
  )
})

export default app
