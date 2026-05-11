/**
 * /api/v1/account/* — profile / KYC / security / billing.
 *
 * Layers:
 *   M2: profile + addresses + tax residencies + beneficiaries (envelope
 *       encrypted KYC; mfaAuthMiddleware-gated).
 *   M8: security self-service — sessions list/revoke, password change, TOTP
 *       enroll/verify/disable, recovery codes regenerate, API tokens,
 *       login history. All MFA-gated except read-only listings.
 *   Future: billing endpoints (plan / invoices / payment methods / projects).
 */

import { createHash, randomBytes } from "node:crypto"
import { and, asc, between, desc, eq, ne, sql } from "drizzle-orm"
import { Hono } from "hono"

import {
  generateRecoveryCodes,
  hashPassword,
  verifyPassword,
} from "../../auth/argon2.js"
import { hashRecoveryCodes } from "../../auth/recovery.js"
import { randomOpaqueSecret } from "../../auth/sessions.js"
import {
  generateSecret as generateTotpSecret,
  provisioningUri,
  verifyCode as verifyTotpCode,
} from "../../auth/totp.js"
import {
  addresses,
  apiTokens,
  authFactors,
  beneficiaries,
  db,
  loginEvents,
  profiles,
  recoveryCodes,
  sessions,
  taxResidencies,
  users,
} from "../../db/client.js"
import { env } from "../../env.js"
import { audit } from "../../lib/audit.js"
import {
  decryptField,
  decryptSecret,
  encryptAndHash,
  encryptField,
  encryptSecret,
} from "../../lib/crypto.js"
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
  notImplemented,
  unauthenticated,
} from "../../lib/errors.js"
import { extractIp } from "../../lib/ip.js"
import { authMiddleware, mfaAuthMiddleware } from "../../middleware/auth.js"
import {
  loginHistoryQuerySchema,
  passwordChangeSchema,
  tokenCreateSchema,
  totpDisableSchema,
  totpVerifySchema,
} from "../../schemas/account-security.js"
import {
  addressCreateSchema,
  addressPatchSchema,
  beneficiaryCreateSchema,
  beneficiaryPatchSchema,
  profileCreateSchema,
  profilePatchSchema,
  taxResidencyCreateSchema,
  taxResidencyPatchSchema,
} from "../../schemas/profile.js"

const app = new Hono()

// All /account/* requires a session. KYC sub-routes additionally require MFA.
app.use("*", authMiddleware)

function requireClient(c: import("hono").Context) {
  const client = c.get("client")
  if (!client) throw forbidden("This endpoint is for client users only")
  return client
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/account/me
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Tiny "who am I" response shaped specifically for the nav-bar account
 * dropdown. Returns just the bits a global navigation widget needs:
 *   preferredName, preferredChineseName, primaryEmail, clientNumber, initial.
 *
 * Deliberately:
 *   - NOT mfa-gated (cosmetic data only; same as the user's email which is
 *     visible in the login flow)
 *   - NOT audited (would flood audit_log on every page nav)
 *   - cheap: at most one decrypt per cold-cache request
 *
 * Cache hint: frontend should store the result in sessionStorage and reuse
 * across page navigations until logout.
 */
app.get("/me", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")

  const profile = await db.query.profiles.findFirst({
    where: eq(profiles.clientId, client.id),
  })

  const [preferredName, preferredChineseName] = await Promise.all([
    profile?.preferredNameEncrypted
      ? decryptField(profile.preferredNameEncrypted)
      : Promise.resolve(null),
    profile?.preferredChineseNameEncrypted
      ? decryptField(profile.preferredChineseNameEncrypted)
      : Promise.resolve(null),
  ])

  // Initial: prefer the first letter of the preferred Chinese name (single
  // glyph fits a 32px avatar best); fall back to preferred English; finally
  // the auth-email's first letter so the avatar is never empty.
  const initial =
    (preferredChineseName && preferredChineseName.charAt(0)) ||
    (preferredName && preferredName.replace(/^(Mr|Ms|Dr|Mrs)\.\s*/, "").charAt(0)) ||
    user.email.charAt(0).toUpperCase()

  return c.json({
    ok: true,
    user: {
      id: user.id,
      email: user.email, // auth-email
      preferredLang: user.preferredLang,
    },
    profile: {
      preferredName,
      preferredChineseName,
      primaryEmail: profile?.primaryEmail ?? user.email,
      initial,
    },
    client: {
      id: client.id,
      clientNumber: client.clientNumber,
      tier: client.tier,
      jurisdiction: client.jurisdiction,
      joinedAt: client.joinedAt,
    },
  })
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  PROFILE                                                                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

/**
 * GET /api/v1/account/profile
 *
 * Returns the client's profile + addresses + tax residencies + beneficiaries,
 * with all encrypted fields decrypted on the way out.
 *
 * Heavy: this is the canonical "load my profile page" call. The frontend
 * should cache for the page session.
 */
app.get("/profile", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const profile = await db.query.profiles.findFirst({
    where: eq(profiles.clientId, client.id),
  })

  if (!profile) {
    // Returning a 404 lets the frontend distinguish "first-time KYC needed"
    // from "actual error". POST /profile is how they create one.
    throw notFound("Profile not yet created. POST /api/v1/account/profile to begin KYC.")
  }

  // Decrypt KYC fields. Each `decryptField` is one KMS call; in a real KMS
  // we'd batch these, but for the Local KMS the round-trip is local memory.
  const [
    legalName,
    firstName,
    lastName,
    chineseName,
    preferredName,
    preferredChineseName,
    hkid,
    passport,
    identitiesRaw,
    peopleAndBeneficiariesRaw,
  ] = await Promise.all([
    decryptField(profile.legalNameEncrypted),
    profile.firstNameEncrypted ? decryptField(profile.firstNameEncrypted) : Promise.resolve(null),
    profile.lastNameEncrypted ? decryptField(profile.lastNameEncrypted) : Promise.resolve(null),
    profile.chineseNameEncrypted ? decryptField(profile.chineseNameEncrypted) : Promise.resolve(null),
    profile.preferredNameEncrypted ? decryptField(profile.preferredNameEncrypted) : Promise.resolve(null),
    profile.preferredChineseNameEncrypted ? decryptField(profile.preferredChineseNameEncrypted) : Promise.resolve(null),
    profile.hkidEncrypted ? decryptField(profile.hkidEncrypted) : Promise.resolve(null),
    profile.passportEncrypted ? decryptField(profile.passportEncrypted) : Promise.resolve(null),
    profile.identitiesEncrypted ? decryptField(profile.identitiesEncrypted) : Promise.resolve(null),
    profile.peopleAndBeneficiariesEncrypted
      ? decryptField(profile.peopleAndBeneficiariesEncrypted)
      : Promise.resolve(null),
  ])

  // Both jsonb-equivalent fields are stored as encrypted JSON strings; parse
  // here so the client sees structured data. Bad JSON → ignore + log.
  const safeParse = (label: string, raw: string | null) => {
    if (!raw) return null
    try { return JSON.parse(raw) } catch (err) {
      console.warn(`[account.profile] failed to JSON.parse ${label}: ${String(err)}`)
      return null
    }
  }
  const identities = safeParse("identities", identitiesRaw)
  const peopleAndBeneficiaries = safeParse("peopleAndBeneficiaries", peopleAndBeneficiariesRaw)

  // Sub-resources.
  const [addressRows, taxRows, beneficiaryRows] = await Promise.all([
    db.query.addresses.findMany({
      where: eq(addresses.clientId, client.id),
      orderBy: [asc(addresses.createdAt)],
    }),
    db.query.taxResidencies.findMany({
      where: eq(taxResidencies.clientId, client.id),
      orderBy: [asc(taxResidencies.establishedAt)],
    }),
    db.query.beneficiaries.findMany({
      where: eq(beneficiaries.clientId, client.id),
      orderBy: [asc(beneficiaries.createdAt)],
    }),
  ])

  const decryptedAddresses = await Promise.all(
    addressRows.map(async (a) => ({
      id: a.id,
      kind: a.kind,
      line1: await decryptField(a.line1Encrypted),
      line2: a.line2Encrypted ? await decryptField(a.line2Encrypted) : null,
      city: a.city,
      region: a.region,
      countryIso: a.countryIso,
      postalCode: a.postalCode,
      isPrimary: a.isPrimary,
      verifiedAt: a.verifiedAt,
    })),
  )

  const decryptedTax = await Promise.all(
    taxRows.map(async (t) => ({
      id: t.id,
      countryIso: t.countryIso,
      taxId: t.taxIdEncrypted ? await decryptField(t.taxIdEncrypted) : null,
      isPrimary: t.isPrimary,
      treatyForm: t.treatyForm,
      treatyFormSignedAt: t.treatyFormSignedAt,
      treatyFormRenewsAt: t.treatyFormRenewsAt,
      establishedAt: t.establishedAt,
    })),
  )

  const decryptedBeneficiaries = await Promise.all(
    beneficiaryRows.map(async (b) => ({
      id: b.id,
      fullName: await decryptField(b.fullNameEncrypted),
      displayLabel: b.displayLabel,
      relation: b.relation,
      sharePct: b.sharePct,
      permissions: b.permissions,
      contact: b.contactEncrypted ?? null,
      authorizedAt: b.authorizedAt,
      revisitAt: b.revisitAt,
    })),
  )

  // Audit. Profile reads are sensitive — record them.
  await audit({
    action: "account.profile.read",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "profile",
    resourceId: client.id,
  })

  return c.json({
    ok: true,
    profile: {
      // Granular names (added 2026-05). Frontend should prefer these over
      // `legalName`; that one stays around as the KYC-locked anchor.
      firstName,
      lastName,
      chineseName,
      preferredName,
      preferredChineseName,
      legalName,
      dateOfBirth: profile.dateOfBirth,
      nationality: profile.nationality,
      hkid,
      passport,
      // Unified identities (decrypted JSON array). HKID + passport above
      // are the special-cased ones; this is the catch-all bucket.
      identities,
      tradingStatus: profile.tradingStatus,
      primaryEmail: profile.primaryEmail,
      primaryPhone: profile.primaryPhone,
      // JSON-as-table alternative to the `beneficiaries` table below.
      // Frontend renders this if present; falls back to `beneficiaries`.
      peopleAndBeneficiaries,
      preferredChannel: profile.preferredChannel,
      preferredLang: user.preferredLang, // lives on users; surface here for convenience
      quietHoursLocal: profile.quietHoursLocal,
      marketingConsent: profile.marketingConsent,
      caseStudyConsent: profile.caseStudyConsent,
      updatedAt: profile.updatedAt,
    },
    addresses: decryptedAddresses,
    taxResidencies: decryptedTax,
    beneficiaries: decryptedBeneficiaries,
    client: {
      id: client.id,
      clientNumber: client.clientNumber,
      tier: client.tier,
      jurisdiction: client.jurisdiction,
      joinedAt: client.joinedAt,
    },
  })
})

/**
 * POST /api/v1/account/profile
 *
 * One-time profile creation. Locked KYC fields (legal_name, DOB, nationality,
 * HKID, passport) accepted here only. Once created, you must PATCH for
 * changes — and PATCH refuses to touch the locked fields.
 */
app.post("/profile", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const existing = await db.query.profiles.findFirst({
    where: eq(profiles.clientId, client.id),
  })
  if (existing) {
    throw conflict("Profile already exists. Use PATCH to update.")
  }

  const body = profileCreateSchema.parse(await c.req.json())

  // Encrypt + hash legal name (hash powers `WHERE legal_name_hash = ?` lookups
  // for compliance searches). hkid + passport are opaque; no hash.
  const { encrypted: legalNameEncrypted, hash: legalNameHash } =
    await encryptAndHash(body.legalName)
  const hkidEncrypted = body.hkid ? await encryptField(body.hkid) : null
  const passportEncrypted = body.passport
    ? await encryptField(body.passport)
    : null

  const [created] = await db
    .insert(profiles)
    .values({
      clientId: client.id,
      legalNameEncrypted,
      legalNameHash,
      dateOfBirth: body.dateOfBirth ?? null,
      nationality: body.nationality ?? null,
      hkidEncrypted,
      passportEncrypted,
      primaryEmail: body.primaryEmail ?? null,
      primaryPhone: body.primaryPhone ?? null,
      preferredChannel: body.preferredChannel ?? "email",
      quietHoursLocal: body.quietHoursLocal ?? null,
      marketingConsent: body.marketingConsent ?? true,
      caseStudyConsent: body.caseStudyConsent ?? false,
    })
    .returning({ clientId: profiles.clientId })

  await audit({
    action: "account.profile.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "profile",
    resourceId: client.id,
    afterState: {
      // Don't write plaintext to audit_log. Record what changed shape-wise.
      hasLegalName: true,
      hasDob: !!body.dateOfBirth,
      hasNationality: !!body.nationality,
      hasHkid: !!body.hkid,
      hasPassport: !!body.passport,
    },
  })

  return c.json({ ok: true, clientId: created!.clientId }, 201)
})

/**
 * PATCH /api/v1/account/profile
 *
 * Update non-locked fields. Locked KYC fields ignored if present (silently;
 * to avoid leaking which ones are locked, we just don't touch them — the
 * schema's `.strict()` already rejects unknown keys).
 */
app.patch("/profile", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const profile = await db.query.profiles.findFirst({
    where: eq(profiles.clientId, client.id),
  })
  if (!profile) {
    throw notFound("Profile not yet created. POST /profile first.")
  }

  const body = profilePatchSchema.parse(await c.req.json())

  // Build the update payload — only include keys that were sent (PATCH
  // semantics, not PUT).
  const update: Record<string, unknown> = { updatedAt: new Date() }
  for (const key of [
    "primaryEmail",
    "primaryPhone",
    "preferredChannel",
    "quietHoursLocal",
    "marketingConsent",
    "caseStudyConsent",
  ] as const) {
    if (key in body) update[key] = body[key]
  }

  if (Object.keys(update).length === 1) {
    // Only updatedAt would change → no-op.
    throw badRequest("No fields to update")
  }

  await db.update(profiles).set(update).where(eq(profiles.clientId, client.id))

  await audit({
    action: "account.profile.update",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "profile",
    resourceId: client.id,
    metadata: { changedFields: Object.keys(update).filter((k) => k !== "updatedAt") },
  })

  return c.json({ ok: true })
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  BENEFICIARIES                                                             ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

app.get("/beneficiaries", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)

  const rows = await db.query.beneficiaries.findMany({
    where: eq(beneficiaries.clientId, client.id),
    orderBy: [asc(beneficiaries.createdAt)],
  })

  const decrypted = await Promise.all(
    rows.map(async (b) => ({
      id: b.id,
      fullName: await decryptField(b.fullNameEncrypted),
      displayLabel: b.displayLabel,
      relation: b.relation,
      sharePct: b.sharePct,
      permissions: b.permissions,
      contact: b.contactEncrypted ?? null,
      authorizedAt: b.authorizedAt,
      revisitAt: b.revisitAt,
      createdAt: b.createdAt,
    })),
  )

  return c.json({ ok: true, beneficiaries: decrypted })
})

app.post("/beneficiaries", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = beneficiaryCreateSchema.parse(await c.req.json())

  const fullNameEncrypted = await encryptField(body.fullName)
  // contact is currently jsonb (not encrypted at column level — it's just
  // structured data with email/phone/notes). We store it directly; M3 will
  // add field-level encryption inside the JSON if needed.

  const [created] = await db
    .insert(beneficiaries)
    .values({
      clientId: client.id,
      fullNameEncrypted,
      displayLabel: body.displayLabel ?? null,
      relation: body.relation,
      sharePct: body.sharePct?.toString() ?? null,
      permissions: body.permissions,
      contactEncrypted: body.contact ?? null,
      revisitAt: body.revisitAt ?? null,
    })
    .returning({ id: beneficiaries.id })

  await audit({
    action: "account.beneficiary.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "beneficiary",
    resourceId: created!.id,
  })

  return c.json({ ok: true, id: created!.id }, 201)
})

app.patch("/beneficiaries/:id", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const existing = await db.query.beneficiaries.findFirst({
    where: and(eq(beneficiaries.id, id), eq(beneficiaries.clientId, client.id)),
  })
  if (!existing) throw notFound("Beneficiary not found")

  const body = beneficiaryPatchSchema.parse(await c.req.json())

  const update: Record<string, unknown> = {}
  if ("fullName" in body && body.fullName !== undefined) {
    update.fullNameEncrypted = await encryptField(body.fullName)
  }
  if ("displayLabel" in body) update.displayLabel = body.displayLabel ?? null
  if ("relation" in body && body.relation !== undefined) update.relation = body.relation
  if ("sharePct" in body) {
    update.sharePct = body.sharePct?.toString() ?? null
  }
  if ("permissions" in body && body.permissions !== undefined) update.permissions = body.permissions
  if ("contact" in body) update.contactEncrypted = body.contact ?? null
  if ("revisitAt" in body) update.revisitAt = body.revisitAt ?? null

  if (Object.keys(update).length === 0) {
    throw badRequest("No fields to update")
  }

  await db.update(beneficiaries).set(update).where(eq(beneficiaries.id, id))

  await audit({
    action: "account.beneficiary.update",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "beneficiary",
    resourceId: id,
    metadata: { changedFields: Object.keys(update) },
  })

  return c.json({ ok: true })
})

app.delete("/beneficiaries/:id", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const existing = await db.query.beneficiaries.findFirst({
    where: and(eq(beneficiaries.id, id), eq(beneficiaries.clientId, client.id)),
  })
  if (!existing) throw notFound("Beneficiary not found")

  await db.delete(beneficiaries).where(eq(beneficiaries.id, id))

  await audit({
    action: "account.beneficiary.delete",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "beneficiary",
    resourceId: id,
  })

  return c.json({ ok: true })
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  ADDRESSES                                                                 ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

app.get("/addresses", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const rows = await db.query.addresses.findMany({
    where: eq(addresses.clientId, client.id),
    orderBy: [asc(addresses.createdAt)],
  })
  const decrypted = await Promise.all(
    rows.map(async (a) => ({
      id: a.id,
      kind: a.kind,
      line1: await decryptField(a.line1Encrypted),
      line2: a.line2Encrypted ? await decryptField(a.line2Encrypted) : null,
      city: a.city,
      region: a.region,
      countryIso: a.countryIso,
      postalCode: a.postalCode,
      isPrimary: a.isPrimary,
      verifiedAt: a.verifiedAt,
      createdAt: a.createdAt,
    })),
  )
  return c.json({ ok: true, addresses: decrypted })
})

app.post("/addresses", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = addressCreateSchema.parse(await c.req.json())

  const line1Encrypted = await encryptField(body.line1)
  const line2Encrypted = body.line2 ? await encryptField(body.line2) : null

  // If marking primary, demote any existing primary first.
  if (body.isPrimary) {
    await db
      .update(addresses)
      .set({ isPrimary: false })
      .where(and(eq(addresses.clientId, client.id), eq(addresses.isPrimary, true)))
  }

  const [created] = await db
    .insert(addresses)
    .values({
      clientId: client.id,
      kind: body.kind,
      line1Encrypted,
      line2Encrypted,
      city: body.city ?? null,
      region: body.region ?? null,
      countryIso: body.countryIso,
      postalCode: body.postalCode ?? null,
      isPrimary: body.isPrimary,
    })
    .returning({ id: addresses.id })

  await audit({
    action: "account.address.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "address",
    resourceId: created!.id,
  })

  return c.json({ ok: true, id: created!.id }, 201)
})

app.patch("/addresses/:id", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const existing = await db.query.addresses.findFirst({
    where: and(eq(addresses.id, id), eq(addresses.clientId, client.id)),
  })
  if (!existing) throw notFound("Address not found")

  const body = addressPatchSchema.parse(await c.req.json())

  const update: Record<string, unknown> = {}
  if ("line1" in body && body.line1 !== undefined) {
    update.line1Encrypted = await encryptField(body.line1)
  }
  if ("line2" in body) {
    update.line2Encrypted = body.line2 ? await encryptField(body.line2) : null
  }
  if ("kind" in body && body.kind !== undefined) update.kind = body.kind
  if ("city" in body) update.city = body.city ?? null
  if ("region" in body) update.region = body.region ?? null
  if ("countryIso" in body && body.countryIso !== undefined) update.countryIso = body.countryIso
  if ("postalCode" in body) update.postalCode = body.postalCode ?? null

  if ("isPrimary" in body && body.isPrimary === true && !existing.isPrimary) {
    // Demote any current primary first.
    await db
      .update(addresses)
      .set({ isPrimary: false })
      .where(and(eq(addresses.clientId, client.id), eq(addresses.isPrimary, true)))
    update.isPrimary = true
  } else if ("isPrimary" in body && body.isPrimary === false) {
    update.isPrimary = false
  }

  if (Object.keys(update).length === 0) {
    throw badRequest("No fields to update")
  }

  await db.update(addresses).set(update).where(eq(addresses.id, id))

  await audit({
    action: "account.address.update",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "address",
    resourceId: id,
    metadata: { changedFields: Object.keys(update) },
  })

  return c.json({ ok: true })
})

app.delete("/addresses/:id", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const existing = await db.query.addresses.findFirst({
    where: and(eq(addresses.id, id), eq(addresses.clientId, client.id)),
  })
  if (!existing) throw notFound("Address not found")

  await db.delete(addresses).where(eq(addresses.id, id))

  await audit({
    action: "account.address.delete",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "address",
    resourceId: id,
  })

  return c.json({ ok: true })
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  TAX RESIDENCIES                                                           ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

app.get("/tax-residencies", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const rows = await db.query.taxResidencies.findMany({
    where: eq(taxResidencies.clientId, client.id),
    orderBy: [asc(taxResidencies.establishedAt)],
  })
  const decrypted = await Promise.all(
    rows.map(async (t) => ({
      id: t.id,
      countryIso: t.countryIso,
      taxId: t.taxIdEncrypted ? await decryptField(t.taxIdEncrypted) : null,
      isPrimary: t.isPrimary,
      treatyForm: t.treatyForm,
      treatyFormSignedAt: t.treatyFormSignedAt,
      treatyFormRenewsAt: t.treatyFormRenewsAt,
      establishedAt: t.establishedAt,
    })),
  )
  return c.json({ ok: true, taxResidencies: decrypted })
})

app.post("/tax-residencies", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = taxResidencyCreateSchema.parse(await c.req.json())

  const taxIdEncrypted = body.taxId ? await encryptField(body.taxId) : null

  if (body.isPrimary) {
    await db
      .update(taxResidencies)
      .set({ isPrimary: false })
      .where(
        and(
          eq(taxResidencies.clientId, client.id),
          eq(taxResidencies.isPrimary, true),
        ),
      )
  }

  const [created] = await db
    .insert(taxResidencies)
    .values({
      clientId: client.id,
      countryIso: body.countryIso,
      taxIdEncrypted,
      isPrimary: body.isPrimary,
      treatyForm: body.treatyForm ?? null,
      treatyFormSignedAt: body.treatyFormSignedAt
        ? new Date(body.treatyFormSignedAt)
        : null,
      treatyFormRenewsAt: body.treatyFormRenewsAt
        ? new Date(body.treatyFormRenewsAt)
        : null,
      establishedAt: body.establishedAt
        ? new Date(body.establishedAt)
        : new Date(),
    })
    .returning({ id: taxResidencies.id })

  await audit({
    action: "account.tax_residency.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "tax_residency",
    resourceId: created!.id,
    metadata: { countryIso: body.countryIso, isPrimary: body.isPrimary },
  })

  return c.json({ ok: true, id: created!.id }, 201)
})

app.patch("/tax-residencies/:id", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const existing = await db.query.taxResidencies.findFirst({
    where: and(
      eq(taxResidencies.id, id),
      eq(taxResidencies.clientId, client.id),
    ),
  })
  if (!existing) throw notFound("Tax residency not found")

  const body = taxResidencyPatchSchema.parse(await c.req.json())

  const update: Record<string, unknown> = {}
  if ("countryIso" in body && body.countryIso !== undefined) update.countryIso = body.countryIso
  if ("taxId" in body) {
    update.taxIdEncrypted = body.taxId ? await encryptField(body.taxId) : null
  }
  if ("treatyForm" in body) update.treatyForm = body.treatyForm ?? null
  if ("treatyFormSignedAt" in body) {
    update.treatyFormSignedAt = body.treatyFormSignedAt
      ? new Date(body.treatyFormSignedAt)
      : null
  }
  if ("treatyFormRenewsAt" in body) {
    update.treatyFormRenewsAt = body.treatyFormRenewsAt
      ? new Date(body.treatyFormRenewsAt)
      : null
  }
  if ("establishedAt" in body) {
    update.establishedAt = body.establishedAt
      ? new Date(body.establishedAt)
      : null
  }

  if ("isPrimary" in body && body.isPrimary === true && !existing.isPrimary) {
    await db
      .update(taxResidencies)
      .set({ isPrimary: false })
      .where(
        and(
          eq(taxResidencies.clientId, client.id),
          eq(taxResidencies.isPrimary, true),
        ),
      )
    update.isPrimary = true
  } else if ("isPrimary" in body && body.isPrimary === false) {
    update.isPrimary = false
  }

  if (Object.keys(update).length === 0) {
    throw badRequest("No fields to update")
  }

  await db.update(taxResidencies).set(update).where(eq(taxResidencies.id, id))

  await audit({
    action: "account.tax_residency.update",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "tax_residency",
    resourceId: id,
    metadata: { changedFields: Object.keys(update) },
  })

  return c.json({ ok: true })
})

app.delete("/tax-residencies/:id", mfaAuthMiddleware, async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const existing = await db.query.taxResidencies.findFirst({
    where: and(
      eq(taxResidencies.id, id),
      eq(taxResidencies.clientId, client.id),
    ),
  })
  if (!existing) throw notFound("Tax residency not found")

  await db.delete(taxResidencies).where(eq(taxResidencies.id, id))

  await audit({
    action: "account.tax_residency.delete",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "tax_residency",
    resourceId: id,
  })

  return c.json({ ok: true })
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  SECURITY (M8)                                                             ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
//
// All routes require an active session. Most also require MFA — these are
// the operations a stolen-cookie attacker would target.

// ─── Active sessions ──────────────────────────────────────────────────────

/**
 * GET /security/sessions — list non-revoked, non-expired sessions for the
 * current user. The current session is flagged so the UI can render
 * "this device" without an extra round-trip.
 */
app.get("/security/sessions", authMiddleware, async (c) => {
  const user = c.get("user")
  const currentSession = c.get("session")

  const rows = await db
    .select()
    .from(sessions)
    .where(
      and(
        eq(sessions.userId, user.id),
        sql`${sessions.revokedAt} is null`,
        sql`${sessions.expiresAt} > now()`,
      ),
    )
    .orderBy(desc(sessions.lastSeenAt))

  return c.json({
    ok: true,
    sessions: rows.map((s) => ({
      id: s.id,
      ip: s.ip,
      deviceLabel: s.deviceLabel,
      userAgent: s.userAgent,
      is2faVerified: s.is2faVerified,
      createdAt: s.createdAt,
      lastSeenAt: s.lastSeenAt,
      expiresAt: s.expiresAt,
      isCurrent: s.id === currentSession.id,
    })),
  })
})

/** DELETE /security/sessions/:id — revoke a specific session (refuses current). */
app.delete("/security/sessions/:id", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const currentSession = c.get("session")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  if (id === currentSession.id) {
    throw conflict(
      "Cannot revoke the current session via this endpoint. Use /auth/logout instead.",
    )
  }

  const target = await db.query.sessions.findFirst({
    where: and(eq(sessions.id, id), eq(sessions.userId, user.id)),
  })
  if (!target) throw notFound("Session not found")
  if (target.revokedAt) {
    return c.json({ ok: true, alreadyRevoked: true })
  }

  await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(eq(sessions.id, id))

  await audit({
    action: "account.security.session.revoke",
    userId: user.id,
    ip,
    userAgent,
    resourceType: "session",
    resourceId: id,
    metadata: { deviceLabel: target.deviceLabel, ip: target.ip },
  })

  return c.json({ ok: true })
})

/** POST /security/sessions/revoke-others — revoke every session except this one. */
app.post("/security/sessions/revoke-others", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const currentSession = c.get("session")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const result = await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(sessions.userId, user.id),
        ne(sessions.id, currentSession.id),
        sql`${sessions.revokedAt} is null`,
      ),
    )
  const revoked = Number((result as { rowCount?: number }).rowCount ?? 0)

  await audit({
    action: "account.security.session.revoke_others",
    userId: user.id,
    ip,
    userAgent,
    metadata: { revoked },
  })

  return c.json({ ok: true, revoked })
})

// ─── Password change ──────────────────────────────────────────────────────

app.post("/security/password", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const currentSession = c.get("session")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = passwordChangeSchema.parse(await c.req.json())

  const verify = await verifyPassword(user.passwordHash, body.currentPassword)
  if (!verify.ok) {
    // Log the failed attempt so a credential-stuffing run is visible.
    await db.insert(loginEvents).values({
      userId: user.id,
      ip,
      userAgent,
      method: "password",
      status: "bad_password",
    })
    throw unauthenticated("Current password is incorrect")
  }

  const newHash = await hashPassword(body.newPassword)
  await db
    .update(users)
    .set({ passwordHash: newHash, updatedAt: new Date() })
    .where(eq(users.id, user.id))

  // Defense in depth: revoke ALL OTHER sessions for this user. Whoever has
  // them shouldn't be allowed to keep going after the password rotated.
  // We keep the current session alive so the user isn't logged out mid-flow.
  await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(sessions.userId, user.id),
        ne(sessions.id, currentSession.id),
        sql`${sessions.revokedAt} is null`,
      ),
    )

  await audit({
    action: "account.security.password.change",
    userId: user.id,
    ip,
    userAgent,
    metadata: { sessionsRevoked: "all_except_current" },
  })

  return c.json({ ok: true })
})

// ─── TOTP self-service ────────────────────────────────────────────────────

/**
 * POST /security/2fa/totp/setup — kicks off enrollment.
 *
 * Inserts an UNVERIFIED auth_factors row (we mark it via lastUsedAt = NULL +
 * label "PENDING") and returns the secret + provisioning URI. The client
 * shows the QR, then calls /verify with a TOTP code to commit the factor.
 *
 * Pre-existing TOTP factors are kept until the new one verifies — there's no
 * window during which the user has zero factors.
 */
app.post("/security/2fa/totp/setup", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const secretBase32 = generateTotpSecret()
  const otpauth = provisioningUri(secretBase32, user.email)

  const [factor] = await db
    .insert(authFactors)
    .values({
      userId: user.id,
      factorType: "totp",
      label: "PENDING",
      secretEncrypted: await encryptSecret(secretBase32),
      isPrimary: false,
    })
    .returning({ id: authFactors.id })

  await audit({
    action: "account.security.2fa.totp.setup",
    userId: user.id,
    ip,
    userAgent,
    resourceType: "auth_factor",
    resourceId: factor!.id,
  })

  return c.json({
    ok: true,
    factorId: factor!.id,
    secret: secretBase32,
    otpauthUri: otpauth,
    issuer: env.TOTP_ISSUER,
    accountName: user.email,
  })
})

/**
 * POST /security/2fa/totp/verify — commits a pending factor.
 *
 * On success: revokes any other active TOTP factors for this user (one
 * primary at a time), labels this one, and stamps `lastUsedAt`.
 */
app.post("/security/2fa/totp/verify", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = totpVerifySchema.parse(await c.req.json())

  const factor = await db.query.authFactors.findFirst({
    where: and(
      eq(authFactors.id, body.factorId),
      eq(authFactors.userId, user.id),
      eq(authFactors.factorType, "totp"),
      sql`${authFactors.revokedAt} is null`,
    ),
  })
  if (!factor || !factor.secretEncrypted) {
    throw notFound("TOTP factor not found or already revoked")
  }

  const secretBase32 = await decryptSecret(factor.secretEncrypted)
  if (!verifyTotpCode(secretBase32, body.code)) {
    throw unauthenticated("Invalid TOTP code")
  }

  const now = new Date()

  // Demote prior TOTP factors. We REVOKE rather than delete — the audit
  // trail is preserved.
  await db
    .update(authFactors)
    .set({ revokedAt: now })
    .where(
      and(
        eq(authFactors.userId, user.id),
        eq(authFactors.factorType, "totp"),
        ne(authFactors.id, factor.id),
        sql`${authFactors.revokedAt} is null`,
      ),
    )

  await db
    .update(authFactors)
    .set({
      label: body.label ?? "Authenticator",
      isPrimary: true,
      lastUsedAt: now,
    })
    .where(eq(authFactors.id, factor.id))

  await audit({
    action: "account.security.2fa.totp.verify",
    userId: user.id,
    ip,
    userAgent,
    resourceType: "auth_factor",
    resourceId: factor.id,
  })

  return c.json({ ok: true })
})

/**
 * DELETE /security/2fa/totp — disable TOTP for this account.
 *
 * Requires the current password (defense vs. lost-device + still-logged-in).
 * Revokes ALL active TOTP factors. Recovery codes also get revoked since
 * they're tied to the same MFA tier — the user must regenerate them after
 * re-enrolling.
 */
app.delete("/security/2fa/totp", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = totpDisableSchema.parse(await c.req.json())

  const verify = await verifyPassword(user.passwordHash, body.currentPassword)
  if (!verify.ok) {
    throw unauthenticated("Current password is incorrect")
  }

  const now = new Date()
  await db
    .update(authFactors)
    .set({ revokedAt: now })
    .where(
      and(
        eq(authFactors.userId, user.id),
        eq(authFactors.factorType, "totp"),
        sql`${authFactors.revokedAt} is null`,
      ),
    )

  // Mark all unused recovery codes as used (use `usedAt = now`, no ip).
  await db
    .update(recoveryCodes)
    .set({ usedAt: now, usedIp: ip })
    .where(
      and(eq(recoveryCodes.userId, user.id), sql`${recoveryCodes.usedAt} is null`),
    )

  await audit({
    action: "account.security.2fa.totp.disable",
    userId: user.id,
    ip,
    userAgent,
  })

  return c.json({ ok: true })
})

// ─── Recovery codes ───────────────────────────────────────────────────────

/**
 * POST /security/recovery-codes/regenerate — burn all existing codes,
 * issue 10 fresh ones, return them ONCE. Client must persist them then.
 */
app.post("/security/recovery-codes/regenerate", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const now = new Date()

  // Mark prior codes used (audit-friendly delete).
  await db
    .update(recoveryCodes)
    .set({ usedAt: now, usedIp: ip })
    .where(
      and(eq(recoveryCodes.userId, user.id), sql`${recoveryCodes.usedAt} is null`),
    )

  const codes = generateRecoveryCodes(10)
  const hashed = await hashRecoveryCodes(codes)
  await db.insert(recoveryCodes).values(
    hashed.map((codeHash) => ({ userId: user.id, codeHash })),
  )

  await audit({
    action: "account.security.recovery_codes.regenerate",
    userId: user.id,
    ip,
    userAgent,
    metadata: { generated: codes.length },
  })

  return c.json({ ok: true, codes })
})

// ─── API tokens ───────────────────────────────────────────────────────────

/**
 * Token format: `sq_<8-char prefix>_<32-byte secret>`. The prefix is stored
 * as plaintext so we can show "sq_a1b2c3d4_…" in the UI; the secret is
 * SHA-256-hashed before storing in `api_tokens.secret_hash`.
 *
 * Tokens are returned ONCE on creation — never readable again.
 */
app.get("/security/tokens", authMiddleware, async (c) => {
  const user = c.get("user")
  const rows = await db
    .select()
    .from(apiTokens)
    .where(
      and(eq(apiTokens.userId, user.id), sql`${apiTokens.revokedAt} is null`),
    )
    .orderBy(desc(apiTokens.createdAt))

  return c.json({
    ok: true,
    tokens: rows.map((t) => ({
      id: t.id,
      name: t.name,
      prefix: t.prefix,
      scopes: t.scopes,
      lastUsedAt: t.lastUsedAt,
      callCount: t.callCount,
      createdAt: t.createdAt,
    })),
  })
})

app.post("/security/tokens", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = tokenCreateSchema.parse(await c.req.json())

  const prefix = randomBytes(4).toString("hex") // 8 chars
  const secret = randomOpaqueSecret(32)
  const fullToken = `sq_${prefix}_${secret}`
  const secretHash = createHash("sha256").update(secret, "utf-8").digest()

  const [created] = await db
    .insert(apiTokens)
    .values({
      userId: user.id,
      name: body.name,
      prefix,
      secretHash,
      scopes: body.scopes,
    })
    .returning({ id: apiTokens.id })

  await audit({
    action: "account.security.token.create",
    userId: user.id,
    ip,
    userAgent,
    resourceType: "api_token",
    resourceId: created!.id,
    metadata: { name: body.name, scopes: body.scopes, prefix },
  })

  return c.json({ ok: true, id: created!.id, prefix, token: fullToken }, 201)
})

app.delete("/security/tokens/:id", mfaAuthMiddleware, async (c) => {
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const target = await db.query.apiTokens.findFirst({
    where: and(eq(apiTokens.id, id), eq(apiTokens.userId, user.id)),
  })
  if (!target) throw notFound("Token not found")
  if (target.revokedAt) {
    return c.json({ ok: true, alreadyRevoked: true })
  }

  await db
    .update(apiTokens)
    .set({ revokedAt: new Date() })
    .where(eq(apiTokens.id, id))

  await audit({
    action: "account.security.token.revoke",
    userId: user.id,
    ip,
    userAgent,
    resourceType: "api_token",
    resourceId: id,
    metadata: { name: target.name, prefix: target.prefix },
  })

  return c.json({ ok: true })
})

// ─── Login history ────────────────────────────────────────────────────────

app.get("/security/login-history", authMiddleware, async (c) => {
  const user = c.get("user")
  const query = loginHistoryQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const to = query.to ? new Date(query.to) : new Date()
  const from = query.from
    ? new Date(query.from)
    : new Date(to.getTime() - 90 * 24 * 60 * 60_000)
  // Cap range at 365d for cost control.
  const minFrom = new Date(to.getTime() - 365 * 24 * 60 * 60_000)
  const effectiveFrom = from < minFrom ? minFrom : from

  const rows = await db
    .select()
    .from(loginEvents)
    .where(
      and(
        eq(loginEvents.userId, user.id),
        between(loginEvents.occurredAt, effectiveFrom, to),
      ),
    )
    .orderBy(desc(loginEvents.occurredAt))
    .limit(query.limit)
    .offset(query.offset)

  return c.json({
    ok: true,
    from: effectiveFrom.toISOString(),
    to: to.toISOString(),
    events: rows.map((r) => ({
      id: r.id,
      occurredAt: r.occurredAt,
      ip: r.ip,
      userAgent: r.userAgent,
      method: r.method,
      status: r.status,
      geoCountry: r.geoCountry,
      geoCity: r.geoCity,
    })),
    limit: query.limit,
    offset: query.offset,
  })
})

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  BILLING (still M3+ stubs)                                                 ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

app.get("/billing/plan", async (c) => {
  requireClient(c)
  throw notImplemented("GET /api/v1/account/billing/plan")
})

app.get("/billing/invoices", async (c) => {
  requireClient(c)
  throw notImplemented("GET /api/v1/account/billing/invoices")
})

app.get("/billing/invoices/:id", async (c) => {
  requireClient(c)
  throw notImplemented("GET /api/v1/account/billing/invoices/:id")
})

app.get("/billing/payment-methods", async (c) => {
  requireClient(c)
  throw notImplemented("GET /api/v1/account/billing/payment-methods")
})

app.get("/billing/projects", async (c) => {
  requireClient(c)
  throw notImplemented("GET /api/v1/account/billing/projects")
})

export default app
