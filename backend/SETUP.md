# Setup — bringing the backend up against real services

The code is ready; this doc walks through wiring it to Neon, Cloudflare R2,
GitHub Actions, and a Node.js host. Allow ~30 minutes.

> All commands assume your shell is sitting in `backend/`.

---

## What you need to acquire

| Service | What | Why | Cost |
|---------|------|-----|------|
| **Neon** | Postgres connection string | Primary DB | Free tier OK to start |
| **Cloudflare R2** | Account ID + API token (access key / secret) | Document storage | $0.015/GB·mo, no egress |
| **GitHub** | Repo access (already have) + secrets | CI/CD | Free |
| **Email** *(optional, post-M8)* | Resend API key | Reminder dispatch | Free tier 3k/mo |

You'll generate four cryptographic secrets locally — they never come from a
service provider.

---

## Step 1 — generate cryptographic secrets

```bash
bash scripts/generate-secrets.sh
```

This prints four `.env`-pasteable lines:

```
SESSION_SECRET=<32 bytes base64url>
ARGON2_PEPPER=<32 bytes base64url>
KYC_KEK_BASE64=<32 bytes base64>
KYC_SEARCH_KEY_BASE64=<32 bytes base64>
```

**Treat these like database passwords.** Losing `KYC_KEK_BASE64` after data
exists = losing every encrypted KYC field. Back them up to your password
manager (1Password / Bitwarden / etc.) the same way you back up DB credentials.

If you've already created `.env`, append:

```bash
bash scripts/generate-secrets.sh >> .env
```

---

## Step 2 — Neon Postgres

1. Sign up / sign in at <https://neon.tech>.
2. **Create project** → name it `shion-quant` → pick a region close to where
   the backend will run (Singapore for HK clients; us-east-2 if deploying in
   AWS Virginia, etc.).
3. After provisioning, the dashboard shows two connection strings:
   - **Pooled connection** ← use this one
   - Direct connection
4. Copy the pooled URL into `.env`:

   ```env
   NEON_DATABASE_URL=postgresql://user:pwd@ep-xxx-pooler.<region>.aws.neon.tech/neondb?sslmode=require
   ```

5. Apply the schema:

   ```bash
   pnpm db:apply-sql
   # provisions ~30 tables + indices + audit_log immutability triggers
   ```

6. (Optional) Seed test fixtures:

   ```bash
   pnpm seed
   # creates Mr. Chen + Client SQ-0042 + KT advisor + 90d of NAV data + ...
   ```

7. Verify:

   ```bash
   pnpm dev
   curl http://localhost:3001/health
   curl http://localhost:3001/api/v1/health/compliance
   ```

   The compliance check exercises the KEK round-trip + audit triggers; both
   should be green.

> **Production note:** Neon's free tier auto-suspends inactive databases
> after 5 minutes of idle. The first request after a sleep period takes ~1s
> to wake. Upgrade to the $19/mo plan once you have real users.

---

## Step 3 — Cloudflare R2

R2 is S3-compatible object storage with no egress fees. The backend uses it
for the document vault (M4) — uploads / downloads happen via presigned URLs,
so the API process never handles file bytes.

1. Sign up / sign in at <https://dash.cloudflare.com>.
2. Sidebar → **R2 Object Storage** → **Get started** (first-time only;
   requires payment method even for free tier).
3. **Create bucket** → name `shion-quant-docs` → location: Asia Pacific
   (Hong Kong if available; else Tokyo or Singapore) → keep defaults.
4. Sidebar → **R2** → **Manage R2 API Tokens** → **Create API token**.
   - Token name: `shion-quant-backend`
   - Permissions: **Object Read & Write**
   - Bucket: select `shion-quant-docs` (don't grant access to all)
   - TTL: leave blank (long-lived token; rotate quarterly)
5. The token reveal screen shows three things — copy them ALL now (revealed
   only once):
   - **Access Key ID** → `R2_ACCESS_KEY`
   - **Secret Access Key** → `R2_SECRET_KEY`
   - **Endpoint** for S3 clients → `R2_ENDPOINT` (looks like
     `https://<account-id>.r2.cloudflarestorage.com`)
6. Add to `.env`:

   ```env
   R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
   R2_BUCKET=shion-quant-docs
   R2_ACCESS_KEY=<from step 5>
   R2_SECRET_KEY=<from step 5>
   R2_REGION=auto
   ```

7. Verify (after restarting `pnpm dev`):

   ```bash
   # Login + MFA, then:
   curl -X POST -H 'Origin: http://localhost:5173' -H 'Content-Type: application/json' \
     -b cookies.txt http://localhost:3001/api/v1/documents/upload-url \
     -d '{"title":"R2 smoke test","category":"misc","fileFormat":"txt","fileSizeBytes":12}'
   # → { uploadUrl, documentId, expiresAt }
   echo "hello world!" | curl -X PUT --data-binary @- \
     -H 'Content-Type: text/plain' "<uploadUrl from above>"
   # → 200
   ```

   If R2 is misconfigured, `/upload-url` returns a clear 500 with
   `"Document storage is not configured. Set R2_* in .env"`.

---

## Step 4 — fill in the rest of `.env`

Copy `.env.example` to `.env` (if you haven't already), then make sure every
non-optional field is populated:

```env
NODE_ENV=development
PORT=3001

# DB (Step 2)
NEON_DATABASE_URL=postgresql://...

# Crypto (Step 1)
ARGON2_PEPPER=...
SESSION_SECRET=...
KYC_KEK_BASE64=...
KYC_SEARCH_KEY_BASE64=...

# Auth tuning (defaults are fine)
SESSION_TTL_HOURS=336        # 14 days
SESSION_COOKIE_NAME=sq_session
TOTP_ISSUER=Shion Quant
MAX_LOGIN_FAILURES=5
LOCKOUT_MINUTES=15

# CORS — comma-separated origins of your frontend
ALLOWED_ORIGINS=http://localhost:5173,https://zhongjun-frank-fu.github.io

# Rate limits (defaults fine)
RATE_LIMIT_LOGIN_PER_MIN=10
RATE_LIMIT_GLOBAL_PER_MIN=120

# R2 (Step 3)
R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
R2_BUCKET=shion-quant-docs
R2_ACCESS_KEY=...
R2_SECRET_KEY=...
R2_REGION=auto

# Email (Phase 2 — leave empty for now)
RESEND_API_KEY=
```

> **`.env` is gitignored.** Never commit it. Production secrets go into your
> hosting provider's secret manager (Step 6) and into GitHub Actions secrets
> for CI/CD (Step 7).

---

## Step 5 — pick a deployment target

The backend is **Node.js** (`@hono/node-server`) — it does NOT run on
Cloudflare Workers because `@node-rs/argon2` is a native binding. Realistic
hosts:

| Host | Setup time | Cost (small app) | Pros | Cons |
|------|-----------|------------------|------|------|
| **Railway** | 5 min | ~$5/mo | Connects to GitHub, auto-deploys, env vars in dashboard | Vendor lock for the dashboard UX |
| **Fly.io** | 15 min | ~$5/mo | Ships everywhere, multi-region | More config (Dockerfile, fly.toml) |
| **Render** | 5 min | ~$7/mo | Simple, reliable | Slightly pricier |
| **AWS App Runner / Lightsail** | 30 min+ | $10+ | Familiar if you're AWS-shop | Setup overhead |
| **Cloudflare Workers** | — | — | Already paying for CF | **Won't work** — would need to swap argon2 for a wasm impl + restructure |

Recommendation for a single-region HK/APAC client portal: **Fly.io
(`hkg` region)** for low latency to clients, or **Railway (`ap-southeast-1`)**
if you want zero-config.

> **Tell me which one** before we wire CI/CD; the deploy step in
> `.github/workflows/backend-ci.yml` differs by host.

---

## Step 6 — production secrets

For whichever host you pick, set these as environment variables in their
secret manager (NOT in source):

```
NEON_DATABASE_URL          ← production Neon DB (separate project from dev)
SESSION_SECRET             ← REGENERATE — don't share dev key
ARGON2_PEPPER              ← REGENERATE
KYC_KEK_BASE64             ← REGENERATE — and back up immediately
KYC_SEARCH_KEY_BASE64      ← REGENERATE
ALLOWED_ORIGINS            ← https://your-prod-frontend.com
R2_ENDPOINT                ← same as dev (separate bucket OK)
R2_BUCKET                  ← shion-quant-docs-prod
R2_ACCESS_KEY              ← REGENERATE — production-only token
R2_SECRET_KEY              ← REGENERATE
NODE_ENV                   ← production
```

Run a **fresh** `bash scripts/generate-secrets.sh` for production — never
share crypto keys between dev and prod.

---

## Step 7 — GitHub Actions CI

`.github/workflows/backend-ci.yml` runs typecheck on every PR and push to
`main`. No secrets needed for CI — only deploy.

For the deploy stage (when you've picked a host in Step 5), you'll add:

| Secret name | Where to find it |
|-------------|------------------|
| `RAILWAY_TOKEN` (if Railway) | Railway dashboard → Account → Tokens |
| `FLY_API_TOKEN` (if Fly.io) | `flyctl auth token` |
| `RENDER_API_KEY` (if Render) | Render dashboard → Account → API keys |

Add via GitHub repo → **Settings** → **Secrets and variables** → **Actions**
→ **New repository secret**.

---

## Step 8 — first deploy

After you've told me the host:

1. Create the production Neon project; copy `NEON_DATABASE_URL`.
2. Apply schema:
   ```bash
   psql "$PROD_NEON_DATABASE_URL" -f src/db/schema.sql
   ```
   (Don't run `pnpm seed` against prod — it inserts test fixtures.)
3. Set production secrets in your host's dashboard.
4. Push to `main`; CI runs typecheck; deploy job ships the Docker image
   (or buildpack output).
5. Smoke-test:
   ```bash
   curl https://api.your-domain.com/api/v1/health/compliance
   ```
   All four checks should be green.
6. Schedule the daily retention cron — the host's scheduled-task feature
   runs `pnpm retention` once a day.

---

## Troubleshooting

**`./scripts/generate-secrets.sh: Permission denied`**
→ `chmod +x scripts/generate-secrets.sh`

**`Invalid environment variables: KYC_KEK_BASE64 must decode to exactly 32 bytes`**
→ Use the script. Common mistake: pasting `node -e "...base64url"` output
into `KYC_KEK_BASE64` — that field expects plain `base64`, the script is
already correct.

**`pnpm db:apply-sql` says `password authentication failed`**
→ The Neon dashboard rotates passwords when you regenerate the connection
string. Copy the URL fresh.

**`/api/v1/documents/upload-url` returns 500 even after R2 setup**
→ Check the bucket name matches exactly (case-sensitive). Check `R2_REGION`
is `auto` for Cloudflare R2 (use the AWS region only if you're on real S3).

**`/api/v1/health/compliance` shows `auditImmutability: { ok: false }`**
→ Run `pnpm db:migrate-audit-immutable` once. Fresh DBs from `db:apply-sql`
get the trigger automatically; databases provisioned before M8 need this
one-shot migration.
