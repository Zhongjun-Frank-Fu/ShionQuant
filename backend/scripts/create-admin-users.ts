/**
 * Create administrative / staff user accounts.
 *
 *   pnpm tsx scripts/create-admin-users.ts
 *
 * What it does, per entry in ADMIN_USERS below:
 *   1. Creates a `users` row with a generated random password (12+ chars).
 *   2. Optionally creates a paired `clients` row so the user can use the
 *      portal pages (otherwise the API rejects with FORBIDDEN — every
 *      portal endpoint requires a clients row).
 *   3. Generates a TOTP auth factor (printed as otpauth:// URI for
 *      authenticator scanning).
 *   4. Generates 10 single-use recovery codes (printed once).
 *
 * Output: a credentials block per user, printed to stdout. Save it to your
 * password manager before clearing the terminal.
 *
 * Idempotency: re-running with the same email is a no-op (the script
 * detects the existing user and skips them). To rotate credentials, delete
 * the user first via:
 *
 *   psql "$NEON_DATABASE_URL" -c "delete from clients where user_id = (select id from users where email = 'X'); delete from users where email = 'X'"
 *
 * SECURITY NOTES:
 *   - This script generates strong random passwords. Don't reuse the values
 *     it prints. Each is shown ONCE.
 *   - The TOTP URI contains the secret; treat the entire output block as
 *     sensitive. Don't paste into chat / Slack / email.
 *   - Run against your PRODUCTION Neon DB by setting NEON_DATABASE_URL to
 *     the prod connection string. By default it uses your local .env, which
 *     is your dev DB. ⚠️  Verify which DB you're hitting before running.
 */

import "dotenv/config"
import { eq } from "drizzle-orm"
import { randomBytes } from "node:crypto"

import {
  generateRecoveryCodes,
  hashPassword,
} from "../src/auth/argon2.js"
import { hashRecoveryCodes } from "../src/auth/recovery.js"
import { generateSecret, provisioningUri } from "../src/auth/totp.js"
import {
  authFactors,
  clients,
  db,
  recoveryCodes,
  users,
} from "../src/db/client.js"
import { initEnv } from "../src/env.js"
import { encryptSecret } from "../src/lib/crypto.js"

initEnv(process.env)

// ─── Edit this list ────────────────────────────────────────────────────────
// Add / remove rows as you want. Each row creates one user.
//
// `clientNumber` — leave null for staff-only users; set a value to also
//   create a paired client record (lets them log into the portal).
// `preferredName` — shown in the header / greeting.

interface AdminSpec {
  email: string
  preferredName: string
  /** Set to enable portal access (creates a `clients` row). null = staff only. */
  clientNumber: string | null
  /** "diagnostic" | "retainer" | "build" — only used if clientNumber is set. */
  tier?: "diagnostic" | "retainer" | "build"
  /** ISO country code; only used if clientNumber is set. */
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
  // Add more here, e.g.:
  // { email: "ops@shionquant.com", preferredName: "Ops", clientNumber: null },
  // { email: "compliance@shionquant.com", preferredName: "Compliance", clientNumber: "SQ-ADMIN-002", tier: "retainer", jurisdiction: "HK" },
]

// ─── Run ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("")
  console.log("Creating admin users on:", maskUrl(process.env.NEON_DATABASE_URL))
  if (process.env.NEON_DATABASE_URL?.includes("localhost") === false) {
    console.log("⚠️  This looks like a remote DB. Ctrl+C now if that's wrong.")
    await new Promise((r) => setTimeout(r, 3000))
  }
  console.log("")

  for (const spec of ADMIN_USERS) {
    await createOne(spec)
  }

  console.log("Done. Save the credentials above to your password manager.")
}

async function createOne(spec: AdminSpec) {
  const existing = await db.query.users.findFirst({
    where: eq(users.email, spec.email),
  })
  if (existing) {
    console.log(`SKIP  ${spec.email} — user already exists. Delete first if you want to rotate.`)
    console.log("")
    return
  }

  // Random 24-char password — easy to copy/paste, hard to brute force.
  const password = randomBytes(18).toString("base64url")
  const passwordHash = await hashPassword(password)

  const [user] = await db
    .insert(users)
    .values({
      email: spec.email,
      passwordHash,
      preferredName: spec.preferredName,
      preferredLang: "en",
      isActive: true,
      emailVerifiedAt: new Date(),
    })
    .returning()
  if (!user) throw new Error("user insert returned no row")

  let clientNumber = "(no client record — staff-only user)"
  if (spec.clientNumber) {
    const [client] = await db
      .insert(clients)
      .values({
        userId: user.id,
        clientNumber: spec.clientNumber,
        tier: spec.tier ?? "build",
        jurisdiction: spec.jurisdiction ?? "HK",
      })
      .returning()
    clientNumber = client?.clientNumber ?? "(insert failed)"
  }

  // TOTP factor
  const totpSecret = generateSecret()
  await db.insert(authFactors).values({
    userId: user.id,
    factorType: "totp",
    label: "Authenticator (admin)",
    secretEncrypted: await encryptSecret(totpSecret),
    isPrimary: true,
  })
  const otpauth = provisioningUri(totpSecret, spec.email)

  // Recovery codes
  const codes = generateRecoveryCodes(10)
  const hashed = await hashRecoveryCodes(codes)
  await db.insert(recoveryCodes).values(
    hashed.map((codeHash) => ({ userId: user.id, codeHash })),
  )

  console.log("─".repeat(70))
  console.log(`  ${spec.email}   (${spec.preferredName})`)
  console.log("─".repeat(70))
  console.log(`  Password:    ${password}`)
  console.log(`  Client:      ${clientNumber}`)
  console.log("")
  console.log(`  TOTP secret: ${totpSecret}`)
  console.log(`  TOTP URI:    ${otpauth}`)
  console.log("    → Paste URI into 1Password / Authy / Google Authenticator,")
  console.log("      or convert to a QR with `qrencode` and scan.")
  console.log("")
  console.log("  Recovery codes (each works ONCE):")
  for (const code of codes) console.log(`    ${code}`)
  console.log("")
}

function maskUrl(url: string | undefined): string {
  if (!url) return "(NEON_DATABASE_URL is not set!)"
  return url.replace(/:([^@]+)@/, ":••••••@")
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("create-admin-users failed:", err)
    process.exit(1)
  })
