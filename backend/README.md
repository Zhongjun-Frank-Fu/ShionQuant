# Shion Quant — backend

Client portal backend. **Cloudflare Workers · Hono · Drizzle ORM · Neon Postgres · TypeScript**.

Argon2 password hashing runs in pure WebAssembly (`hash-wasm`); R2 + Pages
share the same Cloudflare account; standalone scripts (`pnpm seed`, `pnpm
retention`) still run on Node 22 from your laptop.

Local dev:
```bash
pnpm install
pnpm dev          # wrangler dev — runs Workers locally via miniflare; no Docker
```

Deploy:
```bash
pnpm deploy       # wrangler deploy
```

---

## Status: M8 (audit & compliance polish complete — all 9 milestones shipped)

Audit log is trigger-immutable; daily retention job purges per the schema's
stated horizons (login_events 365d, audit_log 7y). Full security self-service:
sessions list/revoke, password change with session sweep, TOTP enroll /
verify / disable, recovery codes regenerate, API tokens, 90-day login history.
Compliance health-check endpoint sanity-checks the cryptographic invariants
the auditor will ask about.

| Milestone | Scope | Status |
|---|---|---|
| **M0** | Scaffold — Hono boot, middleware, routes, stubs | ✅ done |
| **M1** | Auth core — login / mfa / logout / session middleware / lockout / login_events | ✅ done |
| **M2** | Profile + KYC + envelope encryption | ✅ done |
| **M3** | Portfolio read — positions / cash / NAV / risk | ✅ done |
| **M4** | Documents + R2 — upload, presigned URLs, signature | ✅ done |
| **M5** | Schedules + ICS feed | ✅ done |
| **M6** | Reports library + custom request flow | ✅ done |
| **M7** | Communication — messaging, advisor booking | ✅ done |
| **M8** | Audit & compliance polish (immutable trigger, retention job) | ✅ done |

---

## Layout

```
backend/
├── package.json
├── tsconfig.json
├── drizzle.config.ts
├── .env.example
├── .gitignore
└── src/
    ├── index.ts                       ← Hono app entry, listens on PORT
    ├── env.ts                         ← Zod-validated env (boots fail fast)
    ├── auth/
    │   ├── argon2.ts                  ← password hashing (✅ ready)
    │   ├── argon2.selftest.ts         ← `pnpm selftest:argon2`
    │   ├── sessions.ts                ← session cookie format + issue/verify
    │   ├── totp.ts                    ← TOTP wrapper (otpauth)
    │   └── recovery.ts                ← recovery code consumption
    ├── db/
    │   ├── client.ts                  ← Neon driver + Drizzle setup
    │   ├── schema.ts                  ← Drizzle schema (~30 tables)
    │   ├── schema.sql                 ← canonical DDL — run once
    │   ├── seed.ts                    ← `pnpm seed` — test fixture
    │   ├── retention.ts               ← `pnpm retention` — daily purge job
    │   └── migrations/
    │       └── 0001_audit_immutable.sql  ← M8 trigger for existing DBs
    ├── lib/
    │   ├── errors.ts                  ← AppError + helpers
    │   ├── audit.ts                   ← audit_log writer
    │   ├── ratelimit.ts               ← in-memory token bucket
    │   ├── lockout.ts                 ← failure counting + locked_until
    │   ├── ip.ts                      ← real-IP extraction
    │   ├── kms.ts                     ← KEK abstraction (local → cloud KMS)
    │   ├── crypto.ts                  ← envelope encryption + deterministicHash
    │   ├── storage.ts                 ← R2 / S3 presign + headObject
    │   ├── ics.ts                     ← RFC 5545 calendar feed builder
    │   ├── availability.ts            ← advisor working-hours slot generation
    │   └── time.ts                    ← duration helpers
    ├── middleware/
    │   ├── logger.ts                  ← request ID + structured logs
    │   ├── error.ts                   ← error → JSON
    │   ├── cors.ts                    ← strict origin allowlist
    │   ├── csrf.ts                    ← Origin-check CSRF defense
    │   ├── ratelimit.ts               ← IP + email rate limiters
    │   └── auth.ts                    ← session validation, attaches user/client
    ├── api/v1/
    │   ├── index.ts                   ← v1 router mounting
    │   ├── auth.ts                    ← login / mfa / logout / session
    │   ├── account.ts                 ← profile / security / billing
    │   ├── portfolio.ts               ← overview / positions / cash / nav / risk
    │   ├── schedules.ts               ← events / settings / ICS
    │   ├── reports.ts                 ← list / detail / subscriptions / requests
    │   ├── documents.ts               ← list / viewer / upload / sign
    │   ├── communication.ts           ← threads / messages / meetings
    │   └── health.ts                  ← compliance self-test
    ├── schemas/
    │   ├── common.ts                  ← uuid, pagination, isoDate
    │   ├── auth.ts                    ← login / mfa / logout schemas
    │   ├── profile.ts                 ← profile / beneficiary / address / tax
    │   ├── portfolio.ts               ← positions filter + nav range
    │   ├── documents.ts               ← list / upload / finalize / sign / request
    │   ├── schedules.ts               ← events query / create / patch / settings
    │   ├── reports.ts                 ← list / subscriptions / custom requests
    │   ├── communication.ts           ← threads / messages / availability / meetings
    │   └── account-security.ts       ← password / TOTP / token / login-history
    └── types/
        └── hono.d.ts                  ← context extensions (user/client/session)
```

---

## Running

> **First-time setup?** See **[SETUP.md](./SETUP.md)** — it walks through
> Neon, Cloudflare R2, GitHub Actions secrets, deploy targets, and the
> production checklist. The 30-second version is below.

```bash
cd backend
pnpm install
cp .env.example .env

# Generate the four cryptographic secrets in .env-pasteable form:
bash scripts/generate-secrets.sh >> .env

# Then fill in:
#   NEON_DATABASE_URL          ← Neon pooled connection string
#   R2_*                       ← Cloudflare R2 token (optional in dev)

pnpm db:apply-sql       # provisions ~30 tables on Neon
pnpm seed               # creates Mr. Chen + Client SQ-0042 + KT + TOTP + KYC fixtures
pnpm dev                # starts server with watch on http://localhost:3001
```

⚠️  **Don't lose `KYC_KEK_BASE64`.** It wraps every row's data encryption key —
losing it = losing every encrypted KYC field. In production this is replaced
with cloud KMS (key never leaves the HSM); in dev, back it up the same way you
back up your database.

`pnpm seed` prints the TOTP `otpauth://...` URI and 10 recovery codes. Either
paste the URI into a QR generator or import it into 1Password / Authy directly.

### Try the auth flow end-to-end

```bash
# Health check
curl http://localhost:3001/health

# 1. Login — returns mfaRequired:true + challengeToken (TOTP factor exists)
curl -i -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/auth/login \
  -d '{"email":"chen@test.local","password":"demo-password-2026"}'

# 2. Exchange the challenge for a session — replace <CHALLENGE> + <CODE>
curl -i -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/auth/mfa \
  -d '{"challengeToken":"<CHALLENGE>","code":"<6-digit TOTP>"}'

# 3. Confirm the cookie session
curl -b cookies.txt http://localhost:3001/api/v1/auth/session

# 4. Profile (M2): decrypt + return KYC, addresses, beneficiaries, tax residencies
curl -b cookies.txt http://localhost:3001/api/v1/account/profile

# 5. Add a beneficiary (M2)
curl -i -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/account/beneficiaries \
  -d '{"fullName":"陳小明","relation":"son","sharePct":50,"permissions":"read"}'

# 6. Portfolio (M3): hero + positions + cash + nav curve + risk
curl -b cookies.txt http://localhost:3001/api/v1/portfolio/overview
curl -b cookies.txt 'http://localhost:3001/api/v1/portfolio/positions?assetType=equity'
curl -b cookies.txt http://localhost:3001/api/v1/portfolio/cash
curl -b cookies.txt 'http://localhost:3001/api/v1/portfolio/nav?range=3m'
curl -b cookies.txt http://localhost:3001/api/v1/portfolio/risk

# 7. Documents (M4): list + detail (work without R2)
curl -b cookies.txt http://localhost:3001/api/v1/documents
curl -b cookies.txt 'http://localhost:3001/api/v1/documents?status=pending_signature'

# 8. Document upload (M4) — requires R2 configured
curl -i -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/documents/upload-url \
  -d '{"title":"Tax 1099 2026","category":"tax","fileFormat":"pdf","fileSizeBytes":42000}'
# → returns { uploadUrl, documentId, expiresAt }
# Then PUT bytes directly:
#   curl -X PUT --data-binary @file.pdf -H 'Content-Type: application/pdf' "<uploadUrl>"
# Then finalize (sha256 = `shasum -a 256 file.pdf | awk '{print $1}'`):
#   curl -X POST -H 'Content-Type: application/json' -H 'Origin: ...' \
#     --cookie cookies.txt -d '{"sha256":"<64-hex>"}' \
#     http://localhost:3001/api/v1/documents/<documentId>/finalize

# 9. Schedules (M5)
curl -b cookies.txt http://localhost:3001/api/v1/schedules/events
curl -b cookies.txt 'http://localhost:3001/api/v1/schedules/events?types=earnings,advisor_call'
curl -b cookies.txt http://localhost:3001/api/v1/schedules/settings

# Create a personal event
curl -i -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/schedules/events \
  -d '{"title":"Lunch with banker","startsAt":"2026-06-12T05:00:00Z","endsAt":"2026-06-12T06:00:00Z","reminders":[{"channel":"email","leadMinutes":60}]}'

# ICS feed — public URL, paste into any calendar app
curl -i -c cookies.txt -b cookies.txt \
  -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/schedules/ics/rotate
# → { token, feedUrl }   ← paste feedUrl into Calendar.app / Google Calendar
curl http://localhost:3001/api/v1/schedules/ics/<token>
# → text/calendar BEGIN:VCALENDAR ... END:VCALENDAR

# 10. Reports (M6): list + detail + bookmark + subscriptions
curl -b cookies.txt http://localhost:3001/api/v1/reports
curl -b cookies.txt 'http://localhost:3001/api/v1/reports?scope=mine&type=performance'
curl -b cookies.txt http://localhost:3001/api/v1/reports/<id>          # full bodyMd
curl -b cookies.txt -X POST -H 'Origin: http://localhost:5173' \
  http://localhost:3001/api/v1/reports/<id>/bookmark

# Update channel subscriptions
curl -b cookies.txt -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X PATCH http://localhost:3001/api/v1/reports/subscriptions \
  -d '{"subscriptions":[{"reportType":"performance","channels":["email","push"]}]}'

# Submit a custom research request (MFA-gated)
curl -b cookies.txt -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/reports/custom-requests \
  -d '{"projectType":"backtest","question":"Backtest a 60/40 HK equity / US treasury allocation across the last 15 years; show drawdowns and recovery time.","timelinePref":"flexible"}'

# 11. Communication (M7): threads + messages
curl -b cookies.txt http://localhost:3001/api/v1/communication/threads
curl -b cookies.txt http://localhost:3001/api/v1/communication/threads/<id>

# Reply to a thread
curl -b cookies.txt -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/communication/threads/<id>/messages \
  -d '{"body":"Sounds good — let me know when the memo is ready."}'

# Mark thread as read
curl -b cookies.txt -X POST -H 'Origin: http://localhost:5173' \
  http://localhost:3001/api/v1/communication/threads/<id>/read

# Advisor availability + book a meeting
curl -b cookies.txt http://localhost:3001/api/v1/communication/advisor/availability
curl -b cookies.txt -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/communication/meetings \
  -d '{"scheduledAt":"2026-06-15T06:00:00Z","durationMin":60,"meetingType":"video","agenda":"Mid-quarter check-in"}'

# Cancel (≥24h ahead, otherwise 409)
curl -b cookies.txt -X DELETE -H 'Origin: http://localhost:5173' \
  http://localhost:3001/api/v1/communication/meetings/<id>

# 12. Security self-service (M8)
curl -b cookies.txt http://localhost:3001/api/v1/account/security/sessions
curl -b cookies.txt 'http://localhost:3001/api/v1/account/security/login-history?limit=20'

# Change password (revokes all other sessions)
curl -b cookies.txt -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/account/security/password \
  -d '{"currentPassword":"demo-password-2026","newPassword":"new-better-pw-2026!"}'

# Enroll a new TOTP authenticator
curl -b cookies.txt -X POST -H 'Origin: http://localhost:5173' \
  http://localhost:3001/api/v1/account/security/2fa/totp/setup
# → { factorId, secret, otpauthUri }
# Scan the URI in your authenticator, then verify:
curl -b cookies.txt -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/account/security/2fa/totp/verify \
  -d '{"factorId":"<id>","code":"123456","label":"Phone"}'

# Regenerate recovery codes (10 fresh, returned ONCE)
curl -b cookies.txt -X POST -H 'Origin: http://localhost:5173' \
  http://localhost:3001/api/v1/account/security/recovery-codes/regenerate

# Create an API token
curl -b cookies.txt -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/account/security/tokens \
  -d '{"name":"Reporting bot","scopes":["read:portfolio","read:reports"]}'
# → { id, prefix, token: "sq_a1b2c3d4_…" }   ← only shown ONCE

# 13. Compliance health-check (no auth, internal — fence with ACL in prod)
curl http://localhost:3001/api/v1/health/compliance
# → 200 + { ok: true, checks: { envelopeEncryption, deterministicHash, auditImmutability, sessionSecretLength } }

# 14. Logout
curl -i -b cookies.txt -c cookies.txt \
  -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:3001/api/v1/auth/logout \
  -d '{}'
```

The `Origin` header is required — `csrfMiddleware` rejects state-changing
requests without an allow-listed origin.

---

## Stack notes

| Concern | Choice | Why |
|---|---|---|
| Runtime | **Node 22 LTS** | Battle-tested; Bun works too via `bun src/index.ts` |
| Framework | **[Hono](https://hono.dev)** | Cross-runtime, faster than Express, type-safe context |
| ORM | **[Drizzle](https://orm.drizzle.team)** | Schema-as-code TS, no codegen step |
| DB driver | **`@neondatabase/serverless`** | HTTP+WS, edge-friendly, plays nice with Neon's pooler |
| Argon2 | **`@node-rs/argon2`** | Rust napi binding, fastest, native pepper support |
| Validation | **Zod** | Standard runtime + compile-time validation |
| TOTP | **`otpauth`** | Tiny, no deps, RFC 6238 conformant |
| Logging | **stdout JSON** | Stream to Better Stack / Axiom / wherever later |

### Things deliberately NOT in M0

- A separate worker process for ICS generation, daily NAV jobs, broker sync (Phase 2 — can be Cron + scripts initially)
- Object storage upload (Phase 2 — schema is ready, R2 config is in `.env.example` already)
- WebAuthn / passkeys (after TOTP is solid)
- Multi-firm tenancy (single `firm_id` column would gate everything; only when needed)
- Full E2E tests (good for after M3 when there's enough surface to test end-to-end)

---

## Conventions

### Errors

Throw `AppError` from any handler — never raw `Error`. The shape on the wire is
always:

```json
{
  "ok": false,
  "code": "NOT_IMPLEMENTED",
  "message": "POST /api/v1/auth/login is scaffolded but not yet implemented",
  "details": null,
  "requestId": "9b8c4f1e-..."
}
```

Frontend pattern-matches on `code`, surfaces `message` only for unknown codes.

### Auth on a route

```typescript
import { authMiddleware } from "../../middleware/auth.js"
import { mfaAuthMiddleware } from "../../middleware/auth.js"  // for trade-y stuff

const app = new Hono()
app.use("*", authMiddleware)         // any session works
// app.use("*", mfaAuthMiddleware)   // requires session.is2faVerified
```

Inside the route, `c.get("user")`, `c.get("client")`, `c.get("session")`,
`c.get("is2faVerified")` are all populated and typed.

### Audit log

```typescript
import { audit } from "../../lib/audit.js"

await audit({
  action: "documents.signed",
  userId: user.id,
  clientId: client.id,
  ip: extractIp(c),
  resourceType: "document",
  resourceId: documentId,
  metadata: { method: "drawn" },
})
```

Once written, `audit_log` rows are immutable (DB trigger). Don't try to UPDATE.

### Money / time

- Money is `numeric(20, 4)` everywhere. Never `float`.
- Timestamps are `timestamptz`, stored UTC. Convert at the API boundary using
  the user's timezone (set in profile / session).

---

## Source-of-truth (SQL ↔ Drizzle)

Two files describe the schema:

- **`src/db/schema.sql`** — full DDL with triggers, generated columns, partial
  indexes, CHECK constraints. Used for **initial provisioning** (`pnpm db:apply-sql`).
- **`src/db/schema.ts`** — Drizzle's TypeScript representation. Used for **type-safe queries**.

For early iteration, edit both together. drizzle-kit (`pnpm db:generate`)
produces migration SQL from `schema.ts` diffs but doesn't manage triggers /
functions — those are manual.

---

## What M1 + M2 actually shipped

### M1 — auth core
| Concern                | Implementation                                                            |
|------------------------|---------------------------------------------------------------------------|
| Login                  | `POST /auth/login` — Argon2id verify → optional TOTP challenge OR session |
| MFA                    | `POST /auth/mfa` — 6-digit TOTP **or** `XXXXX-XXXXX` recovery code        |
| Logout                 | `POST /auth/logout` — revoke single (default) or all sessions; idempotent |
| Session middleware     | `middleware/auth.ts` — cookie → DB lookup → `c.get("user"/"client"/...)`  |
| Rate limiting          | IP-keyed (login + MFA) + email-keyed (login). In-memory token bucket.     |
| Lockout                | `lib/lockout.ts` — N failures in window → `users.locked_until = now + 15m` |
| CSRF                   | `middleware/csrf.ts` — `hono/csrf` against `env.ALLOWED_ORIGINS`          |
| Audit                  | `login_events` row per attempt + `audit_log` for every state change       |

### M2 — profile + KYC + envelope encryption
| Concern                  | Implementation                                                          |
|--------------------------|-------------------------------------------------------------------------|
| Encryption layer         | `lib/crypto.ts` — AES-256-GCM, per-row 32-byte DEK, wrapped via `lib/kms.ts` |
| KMS abstraction          | `lib/kms.ts` — Local impl (KEK in env). Network swap to AWS / GCP KMS = 1 file. |
| Searchable hash          | `deterministicHash()` — HMAC-SHA256 with separate site key; fuels `legal_name_hash` |
| Wire format              | `[v 1B][wrap_dek_len 2B][wrapped_dek][iv 12B][gcm_tag 16B][ct]` — versioned |
| Profile                  | `GET/POST/PATCH /account/profile` — all `bytea` fields decrypted on read |
| KYC lock policy          | `legalName / dateOfBirth / nationality / hkid / passport` write-once via POST; PATCH ignores them |
| Beneficiaries            | `GET/POST/PATCH/DELETE /account/beneficiaries[/:id]`                    |
| Addresses                | `GET/POST/PATCH/DELETE /account/addresses[/:id]` — primary uniqueness enforced |
| Tax residencies          | `GET/POST/PATCH/DELETE /account/tax-residencies[/:id]`                  |
| MFA gate                 | All KYC routes use `mfaAuthMiddleware` — session must be 2FA-verified   |
| Audit                    | Every read produces `account.<resource>.read`; every write `audit_log` row with `changedFields` metadata; plaintext NEVER recorded |

### M3 — portfolio reads
| Endpoint                                   | Returns                                                                  |
|--------------------------------------------|--------------------------------------------------------------------------|
| `GET /portfolio/overview`                  | latest NAV + day P/L, YTD %, beta-to-SPY, allocation by asset_type, 30-day sparkline |
| `GET /portfolio/positions?assetType=…`     | filterable + paginated; option / future / bond fields nested under their own key |
| `GET /portfolio/cash`                      | per-currency cash + margin + USD-equivalent totals                       |
| `GET /portfolio/nav?range=1m\|3m\|6m\|1y\|ytd\|all` | `daily_nav` time series for the equity curve                       |
| `GET /portfolio/risk`                      | latest `risk_metrics` row — beta / sharpe / sortino / max DD / vol       |

Money is sent as **strings** for row-level fields (preserves Postgres `numeric`
precision) and as **numbers** for top-level summary scalars.

### M4 — documents vault
| Endpoint                              | What it does                                                                  |
|---------------------------------------|-------------------------------------------------------------------------------|
| `GET /documents`                      | list w/ filters (category / status / taxYear / archived) + pagination         |
| `GET /documents/:id`                  | metadata; logs a `document_actions` `view` event                              |
| `GET /documents/:id/url`              | issues a presigned R2 GET URL (5 min); logs view + `audit_log`                |
| `POST /documents/upload-url`          | creates `pending_upload` row + returns presigned PUT URL (15 min)             |
| `POST /documents/:id/finalize`        | HEADs R2, verifies size, stamps sha256, flips status `pending_upload→active`  |
| `POST /documents/:id/sign`            | captures signature, writes `document_signatures`, flips `pending_signature→active` |
| `GET /documents/requests`             | list outstanding document-request submissions                                 |
| `POST /documents/requests`            | submit a `bank_ref` / `tax_pkg` / `cost_basis` / `custom` request             |

Direct-to-R2 upload model: bytes never touch the API process. Object keys
follow `clients/{clientId}/{documentId}.{ext}` for clean tenant isolation.

If R2 isn't configured, list / detail / requests still work; URL-issuing
endpoints return a clear 500 with `"Set R2_* in .env"`.

### M5 — schedules + ICS feed
| Endpoint                              | What it does                                                                  |
|---------------------------------------|-------------------------------------------------------------------------------|
| `GET /schedules/events`               | range + type + ticker filter; sorted by `starts_at`                           |
| `GET /schedules/events/:id`           | event detail + attached reminders + linked position context                   |
| `POST /schedules/events`              | create — forces `eventType="personal"`, `source="personal"`                   |
| `PATCH /schedules/events/:id`         | edit — refuses non-personal events with 409                                   |
| `DELETE /schedules/events/:id`        | soft-archive (sets `is_archived=true`); idempotent                            |
| `GET /schedules/settings`             | reminder prefs from `profiles` + ICS subscription state                       |
| `PATCH /schedules/settings`           | update `preferredChannel` + `quietHoursLocal`                                 |
| `POST /schedules/ics/rotate`          | issue fresh `ics_token` + return paste-ready feed URL (one-time exposure)     |
| `GET /schedules/ics/:token`           | **public** ICS feed; no auth, token IS the auth; emits `text/calendar`        |

ICS specifics: full RFC 5545 escape + 73-char line folding (CJK-safe),
`STATUS:CONFIRMED/CANCELLED`, `PRIORITY:1` for critical, `RRULE:` passthrough,
all-day events use `VALUE=DATE`. UIDs are stable (`<event.id>@shionquant.local`)
so calendar apps tombstone correctly across edits.

### M6 — reports library + custom requests
| Endpoint                                       | What it does                                                            |
|------------------------------------------------|-------------------------------------------------------------------------|
| `GET /reports`                                 | filter by type / bookmarked / scope; joined with per-row read state     |
| `GET /reports/:id`                             | full bodyMd; upserts `report_access` (insert or bump `read_count`)      |
| `POST /reports/:id/bookmark`                   | upsert `report_access.is_bookmarked = true`                             |
| `DELETE /reports/:id/bookmark`                 | flip back to false (no-op if no row)                                    |
| `GET /reports/subscriptions`                   | per-`reportType` channel set                                            |
| `PATCH /reports/subscriptions`                 | bulk upsert (`channels: []` silences a type)                            |
| `POST /reports/custom-requests`                | submit research project request (**MFA-gated** — material commitment)   |
| `GET /reports/custom-requests`                 | list this client's submissions, ordered newest-first                    |

Visibility: `is_draft = false AND published_at IS NOT NULL AND (clientId IS NULL OR clientId = me)`.
Drafts and other clients' reports are 404 (not 403) so existence isn't leaked.

### M7 — communication + advisor booking
| Endpoint                                              | What it does                                                       |
|-------------------------------------------------------|--------------------------------------------------------------------|
| `GET /communication/threads`                          | list active threads w/ last-message + advisor + unread count       |
| `GET /communication/threads/:id`                      | paginated message history (oldest-first by default)                |
| `POST /communication/threads`                         | new thread + first message; defaults `advisorId` to client's primary |
| `POST /communication/threads/:id/messages`            | reply; bumps `lastMessageAt` + `unread_count_advisor`              |
| `POST /communication/threads/:id/read`                | stamp `messages.read_at` + zero `unread_count_client`              |
| `GET /communication/advisor/availability`             | bookable slots — advisor 9–17 in their tz, weekdays only, minus existing meetings |
| `POST /communication/meetings`                        | book + auto-create linked `events` row (so it appears in /schedules + ICS feed) |
| `DELETE /communication/meetings/:id`                  | cancel ≥24h ahead; otherwise 409                                   |

Slot generation lives in `lib/availability.ts` — Intl.DateTimeFormat does the
heavy lifting for tz-correct working-hours filtering, no `tz-database` dep.

Booking auto-links to a calendar `events` row of `eventType="advisor_call"` so
the meeting shows up in the user's existing schedule view + ICS feed without
data duplication. Cancellation soft-archives that linked event.

### M8 — audit & compliance polish

**Database invariants:**
- `audit_log` is now append-only at the trigger level (`audit_log_no_update`,
  `audit_log_no_delete`). Any app-code UPDATE/DELETE raises with errcode
  `restrict_violation`.
- The retention script (`pnpm retention`) is the ONLY supported deletion
  path; it bypasses the trigger via `set local session_replication_role = replica`
  inside a single DO-block transaction.

**Retention horizons** (configured in `db/retention.ts`):
| Table              | Retention | Rationale                                         |
|--------------------|-----------|---------------------------------------------------|
| `login_events`     | 365 days  | incident-review window; bounded blast radius      |
| `sessions` (revoked) | 30 days | active-session check uses `revoked_at IS NULL` anyway |
| `document_actions` | 2 years   | only place per-doc view/download trail lives      |
| `audit_log`        | 7 years   | regulatory minimum                                |

**Security self-service** (all under `/api/v1/account/security/*`):
| Endpoint                                  | What it does                                              |
|-------------------------------------------|-----------------------------------------------------------|
| `GET /sessions`                           | active sessions with `isCurrent` flag                     |
| `DELETE /sessions/:id`                    | revoke one (refuses current — use /auth/logout)           |
| `POST /sessions/revoke-others`            | revoke everything except this device                      |
| `POST /password`                          | change password + revoke all other sessions               |
| `POST /2fa/totp/setup`                    | enroll a fresh factor; returns secret + provisioning URI  |
| `POST /2fa/totp/verify`                   | commit a pending factor; old factor revoked atomically    |
| `DELETE /2fa/totp`                        | disable TOTP (requires current password); burns recovery codes |
| `POST /recovery-codes/regenerate`         | issue 10 fresh codes; returned ONCE                       |
| `GET /tokens` + `POST` + `DELETE /:id`    | API tokens (`sq_<prefix>_<secret>`; secret SHA-256-hashed) |
| `GET /login-history`                      | paginated last-90-day default; capped at 365              |

**Compliance health-check** at `GET /api/v1/health/compliance` exercises four
invariants (envelope round-trip, deterministic-hash consistency,
audit-trigger presence, session-secret length) and returns 503 on any failure.
Wire this into your monitoring system.

### Things deliberately NOT shipped (parked for the worker tier)

- WebAuthn / passkeys (TOTP-only is fine for the first cohort)
- Real cloud KMS — Local KMS is the same algorithm; production swap is `lib/kms.ts`
- Redis-backed rate limiter — single-process is enough until we scale out
- Field-level encryption for `beneficiaries.contact_encrypted` JSON — stored as plain jsonb
- Magic-link email login
- "Trusted device" cookies that skip MFA for N days
- Profile change history table — audit_log carries the trail
- Broker connector / nightly NAV-snapshot job — `pnpm seed` populates portfolio data
- Per-position cost-basis lots / FIFO matching — aggregate cost basis only
- Document virus scanning — chain ClamAV / Lambda after upload finalize
- Reminder dispatcher — `event_reminders` rows are queued; worker that emails / pushes is post-M8
- Notification fan-out for new-report / new-message — config rows exist; worker is post-M8
- Per-advisor working-hours table — hard-coded 9–17 weekdays in advisor tz
- Realtime / websockets — `/threads` polls; sockets when cohort outgrows polling
- Billing endpoints (plan / invoices / payment methods / projects) — schema exists, routes still 501

## Production checklist

Before flipping the DNS record, confirm:

1. **Env vars set:** `NEON_DATABASE_URL`, `SESSION_SECRET` (≥32 chars),
   `ARGON2_PEPPER`, `KYC_KEK_BASE64`, `KYC_SEARCH_KEY_BASE64`,
   `R2_ENDPOINT` + `R2_BUCKET` + `R2_ACCESS_KEY` + `R2_SECRET_KEY`,
   `ALLOWED_ORIGINS` (production domain).
2. **Schema applied:** `pnpm db:apply-sql` on a fresh DB,
   or `pnpm db:migrate-audit-immutable` if upgrading from pre-M8.
3. **Compliance health-check passes:** `curl /api/v1/health/compliance` → `ok: true`.
4. **Retention cron scheduled:** daily (UTC midnight) `pnpm retention` —
   set `NODE_ENV=production` so it doesn't refuse to run.
5. **Internal ACL:** fence `/api/v1/health/*` behind a private network or
   IP allowlist before exposing to the internet.
6. **Backup:** Neon point-in-time recovery enabled; `KYC_KEK_BASE64` stored
   in your secrets manager (NOT just on the host).
