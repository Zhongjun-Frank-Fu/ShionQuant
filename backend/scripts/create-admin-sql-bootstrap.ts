/**
 * Bootstrap-mode admin SQL emitter.
 *
 *   pnpm tsx scripts/create-admin-sql-bootstrap.ts > admin.sql
 *
 * Difference from create-admin-sql.ts:
 *   - Skips TOTP factor + recovery codes (so we don't need the production
 *     KEK to encrypt anything). Login will skip MFA on the resulting account.
 *   - Caller is expected to enroll TOTP in-app immediately after first
 *     login, via POST /api/v1/account/security/2fa/totp/setup. That call
 *     runs inside the Worker, so the encryption uses the production KEK
 *     correctly.
 *
 * Output:
 *   stdout — pasteable SQL (INSERT into users + clients only)
 *   stderr — generated password (per email)
 *
 * No DB connection. No production secrets needed.
 */

import { randomBytes, randomUUID } from "node:crypto"

import { hashPassword } from "../src/auth/argon2.js"
import { initEnv } from "../src/env.js"

// hashPassword needs initEnv to satisfy the Proxy's parent shape, even
// though it doesn't read NEON_DATABASE_URL etc. Stub all required fields.
initEnv({
  NODE_ENV: "production",
  NEON_DATABASE_URL: "postgresql://x:x@example.neon.tech/x?sslmode=require",
  SESSION_SECRET: "x".repeat(40),
  KYC_KEK_BASE64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  KYC_SEARCH_KEY_BASE64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
})

interface AdminSpec {
  email: string
  preferredName: string
  clientNumber: string | null
  tier?: "diagnostic" | "retainer" | "build"
  jurisdiction?: string
}

const ADMIN_USERS: AdminSpec[] = [
  {
    email: "raincitiw@gmail.com",
    preferredName: "Frank",
    clientNumber: "SQ-ADMIN-001",
    tier: "build",
    jurisdiction: "HK",
  },
]

function q(s: string): string {
  return `'${s.replace(/'/g, "''")}'`
}

async function main() {
  process.stdout.write(`-- Generated ${new Date().toISOString()}\n`)
  process.stdout.write("-- Bootstrap admin accounts. Paste into Neon SQL Editor → Run.\n")
  process.stdout.write("-- After login, enroll TOTP via POST /api/v1/account/security/2fa/totp/setup\n\n")
  process.stdout.write("BEGIN;\n\n")

  for (const spec of ADMIN_USERS) {
    const userId = randomUUID()
    const clientId = spec.clientNumber ? randomUUID() : null
    const password = randomBytes(18).toString("base64url")
    const passwordHash = await hashPassword(password)

    process.stdout.write(`-- ${spec.email} (${spec.preferredName})\n`)
    process.stdout.write(
      `INSERT INTO users (id, email, password_hash, preferred_name, preferred_lang, is_active, email_verified_at)\n` +
        `VALUES (${q(userId)}, ${q(spec.email)}, ${q(passwordHash)}, ${q(spec.preferredName)}, 'en', true, now());\n\n`,
    )
    if (clientId && spec.clientNumber) {
      process.stdout.write(
        `INSERT INTO clients (id, user_id, client_number, tier, jurisdiction)\n` +
          `VALUES (${q(clientId)}, ${q(userId)}, ${q(spec.clientNumber)}, ${q(spec.tier ?? "build")}, ${q(spec.jurisdiction ?? "HK")});\n\n`,
      )
    }

    process.stderr.write("─".repeat(70) + "\n")
    process.stderr.write(`  ${spec.email}   (${spec.preferredName})\n`)
    process.stderr.write("─".repeat(70) + "\n")
    process.stderr.write(`  Password:  ${password}\n`)
    process.stderr.write(`  UserID:    ${userId}\n`)
    if (spec.clientNumber) {
      process.stderr.write(`  Client:    ${spec.clientNumber}  (id=${clientId})\n`)
    } else {
      process.stderr.write("  Client:    (staff-only — no client record)\n")
    }
    process.stderr.write("\n")
  }

  process.stdout.write("COMMIT;\n")
  process.stderr.write("✓ Done. Paste the stdout SQL into Neon SQL Editor.\n")
  process.stderr.write("✓ Save passwords above; enroll TOTP via API after first login.\n\n")
}

main().catch((err) => {
  console.error("create-admin-sql-bootstrap failed:", err)
  process.exit(1)
})
