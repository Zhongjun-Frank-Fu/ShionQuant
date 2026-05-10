/**
 * Database client — Drizzle ORM over the Neon serverless driver.
 *
 * Why @neondatabase/serverless:
 *   - HTTP-based (and WebSocket fallback) — works in Node, Bun, edge runtimes
 *   - Plays nicely with Neon's connection pooling
 *   - No long-lived TCP connections to manage
 *
 * Lazy construction: the `db` export is a Proxy that resolves on first access.
 * Reading `process.env.NEON_DATABASE_URL` at module-load works on Node but
 * not on Workers (env is populated only inside the fetch handler, after
 * initEnv runs). Deferring the connection setup avoids the Worker deploy
 * validation throw.
 */

import { neon, neonConfig } from "@neondatabase/serverless"
import { drizzle } from "drizzle-orm/neon-http"

import { env } from "../env.js"
import * as schema from "./schema.js"

// Cache fetch responses where safe — speeds up Drizzle's repeated reads.
neonConfig.fetchConnectionCache = true

let _db: ReturnType<typeof drizzle<typeof schema>> | null = null

function getDb(): ReturnType<typeof drizzle<typeof schema>> {
  if (_db) return _db
  const sql = neon(env.NEON_DATABASE_URL)
  _db = drizzle(sql, { schema })
  return _db
}

/**
 * Lazy DB Proxy. Every method call goes through `getDb()` once per cold
 * start (cached after). Existing call sites — `db.select(...)`,
 * `db.insert(...)`, `db.query.users.findFirst(...)` — keep working unchanged.
 */
export const db = new Proxy({} as ReturnType<typeof drizzle<typeof schema>>, {
  get(_, prop) {
    return Reflect.get(getDb() as object, prop)
  },
})

// Re-export schema for convenient `import { db, users } from "./db/client.js"`
export * from "./schema.js"
