#!/usr/bin/env node
/**
 * Push secrets from `backend/.env` to the deployed `shion-quant` Worker
 * via `wrangler secret bulk`.
 *
 * Why this exists:
 *   The non-secret env vars live in `wrangler.jsonc` (committed). Real
 *   secrets must live in Cloudflare's secret store, not the repo. Pushing
 *   them one-by-one with `wrangler secret put X` is tedious and easy to
 *   skip. This wrapper reads the values from `.env`, builds the bulk JSON
 *   payload Cloudflare expects, and ships them all in one round-trip.
 *
 * Usage:
 *   pnpm deploy:secrets         # pushes everything in REQUIRED + OPTIONAL
 *
 * Auth:
 *   Same as `wrangler deploy`. If $CLOUDFLARE_API_TOKEN is set, it's used.
 *   Otherwise wrangler opens a browser-based login on first run.
 *
 * The temp JSON is written with mode 0600 to /tmp and unlinked in a finally
 * block — no plaintext secret stays on disk after the command returns.
 */

import "dotenv/config"
import { spawnSync } from "node:child_process"
import { unlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// Hard-required by env.ts Zod schema. If any are missing the deployed
// Worker fails initEnv() and every request 500s.
const REQUIRED = [
  "NEON_DATABASE_URL",
  "SESSION_SECRET",
  "KYC_KEK_BASE64",
  "KYC_SEARCH_KEY_BASE64",
]

// Optional in env.ts — pushed only if present in .env. Listed here so the
// script ships everything you've configured locally without forcing you
// to maintain a separate list.
const OPTIONAL = [
  "ARGON2_PEPPER",
  "R2_ACCESS_KEY",
  "R2_SECRET_KEY",
  "RESEND_API_KEY",
]

const payload = {}
const missing = []
for (const key of REQUIRED) {
  const v = process.env[key]
  if (!v) missing.push(key)
  else payload[key] = v
}
for (const key of OPTIONAL) {
  if (process.env[key]) payload[key] = process.env[key]
}

if (missing.length > 0) {
  console.error("Missing required secrets in backend/.env:")
  for (const k of missing) console.error("  - " + k)
  console.error("\nGenerate the KYC keys with:")
  console.error("  bash scripts/generate-secrets.sh >> .env")
  process.exit(2)
}

const tmpFile = join(tmpdir(), `wrangler-secrets-${Date.now()}.json`)
writeFileSync(tmpFile, JSON.stringify(payload), { mode: 0o600 })

console.log(`Pushing ${Object.keys(payload).length} secret(s) to Worker "shion-quant":`)
for (const k of Object.keys(payload)) console.log("  - " + k)
console.log("")

try {
  const r = spawnSync(
    "pnpm",
    ["exec", "wrangler", "secret", "bulk", tmpFile],
    { stdio: "inherit" },
  )
  process.exit(r.status ?? 1)
} finally {
  try {
    unlinkSync(tmpFile)
  } catch {
    /* best-effort */
  }
}
