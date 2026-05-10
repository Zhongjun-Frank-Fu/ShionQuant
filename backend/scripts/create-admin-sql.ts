/**
 * 生成可粘贴到 Neon SQL Editor 的 INSERT 语句来创建管理员账号。
 *
 *   pnpm tsx scripts/create-admin-sql.ts > admin.sql
 *   # 然后把 admin.sql 内容复制到 Neon Dashboard → SQL Editor → Run
 *
 * 不连接数据库 —— 只在本地用 JS 算 Argon2 hash + AES-GCM 加密的 TOTP
 * secret，输出 SQL。你可以在 Neon SQL Editor 里执行 INSERT，凭据通过
 * stderr（终端，不写入 SQL 文件）打印给你保存。
 *
 * 必需的环境变量（用于加密 TOTP secret，跟 Worker 的环境一致即可）：
 *   KYC_KEK_BASE64
 *   KYC_SEARCH_KEY_BASE64
 *
 * 这两个值生产环境用什么，这里就用什么 —— 否则 TOTP 解密会失败。
 *
 *   KYC_KEK_BASE64='...' KYC_SEARCH_KEY_BASE64='...' \
 *     pnpm tsx scripts/create-admin-sql.ts > admin.sql
 *
 * 凭据（密码 / TOTP URI / recovery codes）打印到 stderr，所以
 * `> admin.sql` 不会把它们写进去。运行后立刻保存到密码管理器。
 */

import "dotenv/config"
import { randomBytes, randomUUID } from "node:crypto"

import {
  generateRecoveryCodes,
  hashPassword,
} from "../src/auth/argon2.js"
import { hashRecoveryCodes } from "../src/auth/recovery.js"
import { generateSecret, provisioningUri } from "../src/auth/totp.js"
import { initEnv } from "../src/env.js"
import { encryptSecret } from "../src/lib/crypto.js"

// 给 env 一个最小可用的输入。NEON_DATABASE_URL / SESSION_SECRET 用占位符
// 因为这个脚本不连数据库；KYC_* 必须用真实生产值（用来加密 TOTP secret）。
initEnv({
  NODE_ENV: "production",
  NEON_DATABASE_URL: "postgresql://x:x@example.neon.tech/x?sslmode=require",
  SESSION_SECRET: "x".repeat(40),
  KYC_KEK_BASE64: process.env.KYC_KEK_BASE64,
  KYC_SEARCH_KEY_BASE64: process.env.KYC_SEARCH_KEY_BASE64,
  ARGON2_PEPPER: process.env.ARGON2_PEPPER,
  TOTP_ISSUER: process.env.TOTP_ISSUER ?? "Shion Quant",
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
  // 加更多在这里，例如：
  // { email: "ops@shionquant.com", preferredName: "Ops", clientNumber: null },
]

// ─── SQL helpers ──────────────────────────────────────────────────────────

/** 给字符串加 Postgres 的标准字符串 quoting。 */
function q(s: string): string {
  return `'${s.replace(/'/g, "''")}'`
}

/** Buffer → Postgres bytea hex literal: `'\xdeadbeef'::bytea`. */
function qBytea(buf: Buffer): string {
  return `decode('${buf.toString("hex")}', 'hex')`
}

// ─── Run ──────────────────────────────────────────────────────────────────

async function main() {
  // SQL 头到 stdout
  process.stdout.write(`-- Generated ${new Date().toISOString()}\n`)
  process.stdout.write("-- 在 Neon SQL Editor 里整段复制粘贴运行。\n")
  process.stdout.write("-- 凭据（密码 / TOTP URI / recovery codes）见终端 stderr 输出。\n\n")
  process.stdout.write("BEGIN;\n\n")

  for (const spec of ADMIN_USERS) {
    await emitOne(spec)
  }

  process.stdout.write("COMMIT;\n")

  // 凭据汇总到 stderr
  process.stderr.write("\n")
  process.stderr.write("✓ SQL 已生成。把 stdout 内容粘贴到 Neon SQL Editor 运行。\n")
  process.stderr.write("✓ 凭据见上面，立刻保存到密码管理器。\n\n")
}

async function emitOne(spec: AdminSpec) {
  // 1. 生成 ID（让我们能在 SQL 中直接引用，不依赖 RETURNING）
  const userId = randomUUID()
  const clientId = spec.clientNumber ? randomUUID() : null
  const factorId = randomUUID()

  // 2. 加密相关的字段值
  const password = randomBytes(18).toString("base64url")
  const passwordHash = await hashPassword(password)

  const totpSecret = generateSecret()
  const totpEncrypted = await encryptSecret(totpSecret)
  const otpauth = provisioningUri(totpSecret, spec.email)

  const codes = generateRecoveryCodes(10)
  const codeHashes = await hashRecoveryCodes(codes)

  // 3. 生成 SQL
  process.stdout.write(`-- ─── ${spec.email} (${spec.preferredName}) ────────────────────────\n`)

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

  process.stdout.write(
    `INSERT INTO auth_factors (id, user_id, factor_type, label, secret_encrypted, is_primary)\n` +
      `VALUES (${q(factorId)}, ${q(userId)}, 'totp', 'Authenticator (admin)', ${qBytea(totpEncrypted)}, true);\n\n`,
  )

  if (codeHashes.length > 0) {
    process.stdout.write("INSERT INTO recovery_codes (user_id, code_hash) VALUES\n")
    process.stdout.write(
      codeHashes
        .map((h) => `  (${q(userId)}, ${q(h)})`)
        .join(",\n"),
    )
    process.stdout.write(";\n\n")
  }

  // 4. 凭据汇总到 stderr
  process.stderr.write("─".repeat(70) + "\n")
  process.stderr.write(`  ${spec.email}   (${spec.preferredName})\n`)
  process.stderr.write("─".repeat(70) + "\n")
  process.stderr.write(`  Password:    ${password}\n`)
  process.stderr.write(`  Client:      ${spec.clientNumber ?? "(staff-only, no client record)"}\n\n`)
  process.stderr.write(`  TOTP secret: ${totpSecret}\n`)
  process.stderr.write(`  TOTP URI:    ${otpauth}\n\n`)
  process.stderr.write("  Recovery codes (each works ONCE):\n")
  for (const code of codes) process.stderr.write(`    ${code}\n`)
  process.stderr.write("\n")
}

main().catch((err) => {
  console.error("create-admin-sql failed:", err)
  process.exit(1)
})
