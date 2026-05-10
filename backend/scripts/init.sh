#!/usr/bin/env bash
#
# One-shot init for a fresh backend checkout.
#
#   bash scripts/init.sh
#
# Idempotent: re-running is safe — it skips steps that are already done.
# Refuses to overwrite a populated .env unless you delete it first.

set -euo pipefail

# ─── locate self ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# ─── prereqs ──────────────────────────────────────────────────────────────
echo "→ checking prereqs (node, pnpm, psql)…"
for cmd in node pnpm psql; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "  ✗ missing: $cmd"
    case "$cmd" in
      node) echo "      install Node 22 from https://nodejs.org or via nvm";;
      pnpm) echo "      npm install -g pnpm   (or: corepack enable)";;
      psql) echo "      brew install libpq && brew link --force libpq";;
    esac
    exit 1
  fi
done
echo "  ✓ ok"

# ─── install deps ─────────────────────────────────────────────────────────
if [ ! -d node_modules ]; then
  echo "→ pnpm install"
  pnpm install --frozen-lockfile
else
  echo "→ node_modules exists, skipping install"
fi

# ─── create .env ──────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  cp .env.example .env
  echo "→ created .env from .env.example"
fi

# ─── crypto secrets ───────────────────────────────────────────────────────
# Append only if SESSION_SECRET line is missing or empty.
if ! grep -qE '^SESSION_SECRET=.{32,}$' .env; then
  echo "→ generating crypto secrets"
  bash scripts/generate-secrets.sh >> .env
else
  echo "→ secrets already present in .env, skipping"
fi

# ─── Neon URL ─────────────────────────────────────────────────────────────
if ! grep -qE '^NEON_DATABASE_URL=postgresql://' .env; then
  echo ""
  echo "──────────────────────────────────────────────────────────────"
  echo "  Need NEON_DATABASE_URL."
  echo ""
  echo "  Get one at:  https://console.neon.tech"
  echo "    1. Create project (any name; pick a region near your users)"
  echo "    2. Connection Details → POOLED connection (NOT direct)"
  echo "    3. Copy the full URL"
  echo ""
  echo "  Or via CLI (npm install -g neonctl):"
  echo "    neonctl auth"
  echo "    neonctl connection-string --pooled"
  echo "──────────────────────────────────────────────────────────────"
  echo ""
  read -r -p "Paste the URL (or press Enter to skip): " NEON_URL
  if [ -n "$NEON_URL" ]; then
    # macOS sed needs '' after -i; Linux doesn't. Use a backup file then remove.
    sed -i.bak "s|^NEON_DATABASE_URL=.*|NEON_DATABASE_URL=${NEON_URL//|/\\|}|" .env
    rm -f .env.bak
    echo "  ✓ wrote NEON_DATABASE_URL"
  else
    echo "  → skipped; edit .env manually before running pnpm db:apply-sql"
    exit 0
  fi
fi

# ─── R2 (optional, doc upload only) ───────────────────────────────────────
if grep -qE '^R2_ACCESS_KEY=$' .env || grep -qE '^R2_BUCKET=$' .env; then
  echo ""
  echo "→ R2 is unset; documents endpoints will return 503 on upload/download."
  echo "  Set R2_ENDPOINT / R2_BUCKET / R2_ACCESS_KEY / R2_SECRET_KEY in .env"
  echo "  when you're ready (see SETUP.md § Step 3). All other endpoints work without it."
fi

# ─── test connection + apply schema ───────────────────────────────────────
# shellcheck disable=SC1091
set -a; . ./.env; set +a

echo "→ testing DB connection"
if ! psql "$NEON_DATABASE_URL" -tAc "select version()" >/dev/null 2>&1; then
  echo "  ✗ connection failed. Check NEON_DATABASE_URL in .env."
  exit 1
fi
echo "  ✓ connected"

# Skip schema apply if `users` table already exists.
if psql "$NEON_DATABASE_URL" -tAc "select to_regclass('public.users')" 2>/dev/null | grep -q '^users$'; then
  echo "→ schema already applied (users table exists), skipping db:apply-sql"
else
  echo "→ applying schema (~30 tables + triggers)"
  pnpm db:apply-sql
fi

# ─── optional seed ────────────────────────────────────────────────────────
echo ""
read -r -p "Insert test fixtures via pnpm seed? [Y/n] " RUN_SEED
RUN_SEED="${RUN_SEED:-Y}"
if [[ "$RUN_SEED" =~ ^[Yy] ]]; then
  pnpm seed
fi

# ─── done ─────────────────────────────────────────────────────────────────
cat <<EOF

──────────────────────────────────────────────────────────────
  Init complete.
──────────────────────────────────────────────────────────────

  Next:
    pnpm dev                                       # start the server
    curl http://localhost:3001/health              # liveness
    curl http://localhost:3001/api/v1/health/compliance   # crypto + audit triggers

  Login fixture (if you ran seed):
    chen@test.local  /  demo-password-2026
    Then: scan the TOTP otpauth URI from the seed log into your authenticator.

EOF
