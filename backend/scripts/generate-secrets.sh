#!/usr/bin/env bash
#
# Generate the 4 cryptographic secrets the backend needs.
# Output is .env-pasteable; redirect to a file or copy by hand.
#
#   bash scripts/generate-secrets.sh > .env.secrets
#   cat .env.secrets >> .env
#   rm .env.secrets
#
# Each secret is 32 raw bytes. base64url for cookie/HMAC keys (URL-safe, no
# padding); plain base64 for the KEK + search key (matches schema validation
# in env.ts which calls Buffer.from(s, "base64")).

set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
  echo "node is required (uses crypto.randomBytes)" >&2
  exit 1
fi

# Two encodings:
#   base64url — for SESSION_SECRET and ARGON2_PEPPER (no special chars)
#   base64    — for KYC_KEK_BASE64 and KYC_SEARCH_KEY_BASE64 (env.ts validates
#               that base64 decode → exactly 32 bytes)
SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
ARGON2_PEPPER=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
KYC_KEK_BASE64=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
KYC_SEARCH_KEY_BASE64=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")

cat <<EOF
# Generated $(date -u +"%Y-%m-%dT%H:%M:%SZ") by scripts/generate-secrets.sh
# DO NOT commit. DO NOT share. Treat as you would a database password.

SESSION_SECRET=${SESSION_SECRET}
ARGON2_PEPPER=${ARGON2_PEPPER}
KYC_KEK_BASE64=${KYC_KEK_BASE64}
KYC_SEARCH_KEY_BASE64=${KYC_SEARCH_KEY_BASE64}
EOF
