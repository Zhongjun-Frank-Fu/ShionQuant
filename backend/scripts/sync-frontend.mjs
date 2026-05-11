#!/usr/bin/env node
/**
 * Mirror static frontend assets from the repo root into `backend/public/`
 * so `wrangler deploy` (and `wrangler dev`) can ship them alongside the API.
 *
 * Source of truth = repo root (where the HTML files live and are edited).
 * `backend/public/` is gitignored — always derived.
 *
 * Run via:
 *   pnpm sync-frontend       (standalone)
 *   pnpm run deploy          (chained: sync → wrangler deploy)
 *   pnpm run dev             (chained: sync → wrangler dev)
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
} from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(__dirname, "../..")
const DEST = resolve(__dirname, "../public")

// File extensions we want to ship with the Worker. Add more here if you
// introduce CSS/JS/image assets at the repo root later.
const STATIC_EXTENSIONS = [".html", ".svg", ".ico", ".png", ".webmanifest"]

// 1. Wipe the destination so removed files at root don't linger.
if (existsSync(DEST)) rmSync(DEST, { recursive: true, force: true })
mkdirSync(DEST, { recursive: true })

// 2. Copy matching top-level files. We deliberately don't recurse — the
//    repo root is flat for now, and recursing risks pulling in `backend/`
//    or `node_modules/`.
const entries = readdirSync(REPO_ROOT, { withFileTypes: true })
let copied = 0
for (const entry of entries) {
  if (!entry.isFile()) continue
  if (!STATIC_EXTENSIONS.some((ext) => entry.name.toLowerCase().endsWith(ext))) continue
  copyFileSync(join(REPO_ROOT, entry.name), join(DEST, entry.name))
  copied++
}

console.log(`sync-frontend: copied ${copied} file(s) → backend/public/`)
