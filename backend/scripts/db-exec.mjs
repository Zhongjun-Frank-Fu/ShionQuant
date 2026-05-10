#!/usr/bin/env node
/**
 * Run `psql "$NEON_DATABASE_URL" -f <file>` with `.env` auto-loaded.
 *
 * Why this exists:
 *   pnpm scripts inherit only the parent shell's env, not anything in
 *   `backend/.env`. Plain `psql "$NEON_DATABASE_URL" -f ...` therefore
 *   sees an empty string and silently falls back to the local Postgres
 *   socket — confusing for anyone whose only Postgres is on Neon.
 *
 * This wrapper loads `.env` via dotenv (already a dependency for the
 * Hono app), validates that NEON_DATABASE_URL is set, and forwards
 * everything to psql.
 *
 * Usage:
 *   node scripts/db-exec.mjs src/db/schema.sql
 *   node scripts/db-exec.mjs src/db/migrations/0002_buying_power.sql
 */

import "dotenv/config"
import { spawnSync } from "node:child_process"

const sqlFile = process.argv[2]
if (!sqlFile) {
  console.error("usage: node scripts/db-exec.mjs <sql-file>")
  process.exit(2)
}

const url = process.env.NEON_DATABASE_URL
if (!url) {
  console.error(
    "NEON_DATABASE_URL is not set. Add it to backend/.env or export it before running.",
  )
  process.exit(2)
}

const result = spawnSync("psql", [url, "-f", sqlFile], { stdio: "inherit" })
process.exit(result.status ?? 1)
