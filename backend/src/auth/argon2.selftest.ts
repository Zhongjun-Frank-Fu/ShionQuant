/**
 * Self-test for the Argon2 module. Run with:
 *
 *     pnpm tsx src/auth/argon2.selftest.ts
 *     # or
 *     bun src/auth/argon2.selftest.ts
 *
 * Expected: hash and both verify operations should each take ~50ms on
 * production hardware. Tune `timeCost` in argon2.ts if you're far off.
 *
 *   < 30ms : bump timeCost up (you have CPU headroom)
 *   > 200ms: drop timeCost down (probably an underpowered VM)
 */

import "dotenv/config"
import { initEnv } from "../env.js"

// argon2.ts now reads env.ARGON2_PEPPER lazily (Worker-compatible).
// For this Node selftest, fake the minimum env that env.ts requires.
initEnv({
  NEON_DATABASE_URL: "postgresql://x:x@example.neon.tech/x?sslmode=require",
  SESSION_SECRET: "x".repeat(32),
  KYC_KEK_BASE64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  KYC_SEARCH_KEY_BASE64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  ARGON2_PEPPER: process.env.ARGON2_PEPPER,
})

import {
  dummyVerify,
  generateRecoveryCodes,
  hashPassword,
  verifyPassword,
} from "./argon2.js"

const password = "correct-horse-battery-staple-42"

const t0 = performance.now()
const stored = await hashPassword(password)
const t1 = performance.now()

const good = await verifyPassword(stored, password)
const t2 = performance.now()

const bad = await verifyPassword(stored, "wrong-password-completely")
const t3 = performance.now()

const t4 = performance.now()
await dummyVerify()
const t5 = performance.now()

console.log()
console.log(`hash:           ${(t1 - t0).toFixed(1).padStart(6)} ms`)
console.log(`verify (good):  ${(t2 - t1).toFixed(1).padStart(6)} ms  →  ok=${good.ok}`)
console.log(`verify (bad):   ${(t3 - t2).toFixed(1).padStart(6)} ms  →  ok=${bad.ok}`)
console.log(`dummy verify:   ${(t5 - t4).toFixed(1).padStart(6)} ms`)
console.log(`needs rehash:   ${good.newHash ? "yes" : "no"}`)
console.log()
console.log(`pepper set:     ${process.env.ARGON2_PEPPER ? "yes" : "no"}`)
console.log()
console.log("sample hash:")
console.log(`  ${stored}`)
console.log()
console.log("recovery codes (10):")
for (const code of generateRecoveryCodes()) console.log(`  ${code}`)
console.log()
