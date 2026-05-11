/**
 * /api/v1/documents/* — document vault.
 *
 * Storage layer: Cloudflare R2 (S3-compatible) via lib/storage.ts. Bytes flow
 * directly between client and R2; the app never touches the file contents.
 *
 *   Upload flow:
 *     1. POST /documents/upload-url  → server creates a `pending_upload` row
 *        in `documents`, returns a presigned PUT URL + the row's id
 *     2. Client PUTs file bytes to the presigned URL (15 min TTL)
 *     3. POST /documents/:id/finalize { sha256 }  → server HEADs the object
 *        in R2, verifies size matches, flips status from `pending_upload`
 *        to `active`, stamps sha256
 *
 *   Download flow:
 *     1. GET /documents/:id/url  → server logs a `document_actions` view event
 *        and returns a presigned GET URL (5 min TTL)
 *     2. Client fetches the URL directly from R2
 *
 *   Sign flow:
 *     1. Document was created with `status="pending_signature"` (advisor-side
 *        flow that's outside the M4 scope — seed.ts inserts one for testing)
 *     2. POST /documents/:id/sign { signatureMethod, … }  → server records
 *        a `document_signatures` row + flips status to `active`
 *
 * Auth posture: `mfaAuthMiddleware` everywhere — these are sensitive
 * (statements, tax docs, KYC paperwork). Reads are NOT audited per-call to
 * avoid `audit_log` flooding; they ARE recorded in `document_actions` (a
 * narrower per-resource log).
 */

import { randomUUID } from "node:crypto"
import { and, count, desc, eq, sql, type SQL } from "drizzle-orm"
import { Hono } from "hono"
import { PDFDocument, StandardFonts, rgb } from "pdf-lib"

import {
  db,
  documentActions,
  documentRequests,
  documentSignatures,
  documents,
} from "../../db/client.js"
import { audit } from "../../lib/audit.js"
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
  AppError,
} from "../../lib/errors.js"
import { extractIp } from "../../lib/ip.js"
import {
  headObject,
  isStorageConfigured,
  makeObjectKey,
  presignDownload,
  presignUpload,
} from "../../lib/storage.js"
import { mfaAuthMiddleware } from "../../middleware/auth.js"
import {
  documentRequestCreateSchema,
  finalizeUploadSchema,
  listQuerySchema,
  signSchema,
  uploadUrlSchema,
} from "../../schemas/documents.js"

const app = new Hono()

// All /documents/* needs MFA — these are sensitive.
app.use("*", mfaAuthMiddleware)

function requireClient(c: import("hono").Context) {
  const client = c.get("client")
  if (!client) throw forbidden("This endpoint is for client users only")
  return client
}

const FORMAT_TO_MIME: Record<string, string> = {
  pdf: "application/pdf",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  jpg: "image/jpeg",
  png: "image/png",
  csv: "text/csv",
  txt: "text/plain",
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/documents
// ═══════════════════════════════════════════════════════════════════════════

/**
 * `?category=` `?status=` `?taxYear=` `?archived=true` `?limit=` `?offset=`
 *
 * Default: `archived=false`, `status` not filtered (so `active` and
 * `pending_signature` both show up — that's how the UI wants it).
 */
app.get("/", async (c) => {
  const client = requireClient(c)
  const query = listQuerySchema.parse(
    Object.fromEntries(new URL(c.req.url).searchParams),
  )

  const conditions: SQL[] = [eq(documents.clientId, client.id)]
  if (query.category) conditions.push(eq(documents.category, query.category))
  if (query.status) conditions.push(eq(documents.status, query.status))
  if (query.taxYear) conditions.push(eq(documents.taxYear, query.taxYear))
  if (!query.archived) conditions.push(eq(documents.isArchived, false))
  // Hide pending_upload from listings — upload not finalized = doesn't exist
  // from the client's point of view.
  conditions.push(sql`${documents.status} != 'pending_upload'`)

  const where = and(...conditions)

  const [countRow] = await db
    .select({ value: count() })
    .from(documents)
    .where(where)

  const rows = await db
    .select()
    .from(documents)
    .where(where)
    .orderBy(desc(documents.issuedAt), desc(documents.createdAt))
    .limit(query.limit)
    .offset(query.offset)

  return c.json({
    ok: true,
    documents: rows.map(shapeDoc),
    total: countRow?.value ?? 0,
    limit: query.limit,
    offset: query.offset,
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/documents/:id
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Document metadata. Logs a `document_actions` view event but does NOT
 * presign a URL — the frontend should call `/url` only when it actually
 * needs to render the file (saves R2 bandwidth on hover-render).
 */
app.get("/:id", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const id = c.req.param("id")

  const doc = await loadOwnedDoc(id, client.id)

  // Best-effort access log; never block the response.
  void db
    .insert(documentActions)
    .values({
      documentId: doc.id,
      userId: user.id,
      action: "view",
      ip,
    })
    .catch((err: unknown) =>
      console.error("[documents] failed to write document_actions", err),
    )

  return c.json({ ok: true, document: shapeDoc(doc) })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/documents/:id/url
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Presigned R2 GET URL (5 min). Records a `document_actions` download event
 * and an `audit_log` entry — every byte of the file leaving R2 is traceable
 * back through these tables.
 */
app.get("/:id/url", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  if (!isStorageConfigured()) {
    throw new AppError(
      "INTERNAL",
      "Document storage is not configured. Set R2_* in .env",
    )
  }

  const doc = await loadOwnedDoc(id, client.id)
  if (doc.status === "pending_upload") {
    throw badRequest("Document upload not yet finalized")
  }
  if (!doc.fileUrl) {
    throw conflict("Document has no associated file (metadata-only record)")
  }

  // file_url stores the R2 object key (not a public URL). The presigner
  // wraps it into a temporarily-valid HTTPS URL.
  const filename = `${doc.title.replace(/[^a-zA-Z0-9._\- ]/g, "_")}.${doc.fileFormat}`
  const { downloadUrl, expiresAt } = await presignDownload({
    key: doc.fileUrl,
    contentDisposition: `inline; filename="${filename}"`,
  })

  await db.insert(documentActions).values({
    documentId: doc.id,
    userId: user.id,
    action: "download",
    ip,
  })

  await audit({
    action: "document.download_url",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "document",
    resourceId: doc.id,
  })

  return c.json({ ok: true, downloadUrl, expiresAt })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/documents/:id/file
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Streams the document's PDF bytes directly through the Worker.
 *
 * In production this should fetch from R2 (same flow as /url but server-side
 * proxied). For now, we generate a deterministic placeholder PDF on-the-fly
 * via pdf-lib so the dev experience works without any blob storage. The
 * placeholder includes the document's title, source, key metadata and a
 * page count matching `documents.pages` — enough to exercise the viewer's
 * page navigation + zoom flow.
 *
 * Auth: same `mfaAuthMiddleware` as the rest of /documents.
 * Response: application/pdf body, ~10–30 KB per page.
 */
app.get("/:id/file", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const id = c.req.param("id")
  const doc = await loadOwnedDoc(id, client.id)

  const pdfBytes = await renderPlaceholderPdf(doc)

  // Best-effort access log; never block the response.
  void db
    .insert(documentActions)
    .values({
      documentId: doc.id,
      userId: user.id,
      action: "view",
      ip,
    })
    .catch(() => null)

  // Copy the bytes into a fresh ArrayBuffer-backed view. pdf-lib's return
  // type is Uint8Array<ArrayBufferLike> (could be Shared); Response wants
  // a plain ArrayBuffer-backed view.
  const buf = new Uint8Array(pdfBytes.byteLength)
  buf.set(pdfBytes)
  return new Response(buf, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Length": String(buf.byteLength),
      // PDFs are deterministic per (doc, page count, title) — cache an hour.
      "Cache-Control": "private, max-age=3600",
    },
  })
})

/**
 * Build a placeholder PDF for a document. Page 1 is a "cover" with title +
 * source + key dates; subsequent pages contain filler prose so the viewer
 * has something multi-page to render.
 *
 * Deterministic given the same document row → safe to cache by id.
 */
async function renderPlaceholderPdf(
  doc: typeof documents.$inferSelect,
): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.create()
  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica)
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold)
  const fontItalic = await pdfDoc.embedFont(StandardFonts.HelveticaOblique)

  const pageCount = Math.max(1, Math.min(doc.pages ?? 3, 30))
  const PAGE_W = 595 // A4 in points
  const PAGE_H = 842
  const ROYAL = rgb(0.137, 0.278, 0.831) // ~ #2347d4
  const INK = rgb(0.05, 0.063, 0.125) // ~ #0d1020
  const INK_SOFT = rgb(0.29, 0.314, 0.451) // ~ #4a5070
  const RULE = rgb(0.78, 0.812, 0.886) // light gray

  for (let i = 0; i < pageCount; i++) {
    const page = pdfDoc.addPage([PAGE_W, PAGE_H])

    // Header strip
    page.drawRectangle({ x: 0, y: PAGE_H - 80, width: PAGE_W, height: 80, color: rgb(0.953, 0.961, 0.988) })
    page.drawText("INTELLIGENCE INVESTMENT", {
      x: 50, y: PAGE_H - 38, size: 9, font: fontBold, color: ROYAL,
    })
    page.drawText(doc.sourceLabel ?? "INTERNAL", {
      x: 50, y: PAGE_H - 54, size: 8, font: fontRegular, color: INK_SOFT,
    })
    // Code badge top-right
    if (doc.displayCode) {
      const codeText = doc.displayCode
      const w = fontBold.widthOfTextAtSize(codeText, 9) + 16
      page.drawRectangle({
        x: PAGE_W - 50 - w, y: PAGE_H - 50, width: w, height: 22,
        color: ROYAL,
      })
      page.drawText(codeText, {
        x: PAGE_W - 50 - w + 8, y: PAGE_H - 44, size: 9, font: fontBold, color: rgb(1, 1, 1),
      })
    }

    if (i === 0) {
      // Cover page
      let y = PAGE_H - 160
      page.drawText(doc.title, {
        x: 50, y, size: 22, font: fontBold, color: INK,
        maxWidth: PAGE_W - 100, lineHeight: 26,
      })
      y -= 50
      if (doc.description) {
        page.drawText(doc.description, {
          x: 50, y, size: 11, font: fontItalic, color: INK_SOFT,
          maxWidth: PAGE_W - 100, lineHeight: 16,
        })
        y -= 60
      }

      // Meta table
      page.drawLine({ start: { x: 50, y: y + 10 }, end: { x: PAGE_W - 50, y: y + 10 }, thickness: 1, color: RULE })
      const metaRows: Array<[string, string]> = [
        ["Source", doc.sourceLabel ?? "—"],
        ["Document code", doc.displayCode ?? "—"],
        ["Issued", doc.issuedAt ? new Date(doc.issuedAt).toISOString().slice(0, 10) : "—"],
        ["Delivered", doc.deliveredAt ? new Date(doc.deliveredAt).toISOString().slice(0, 10) : "—"],
        ["Pages", String(pageCount)],
        ["Size (estimated)", doc.fileSizeBytes ? `${(doc.fileSizeBytes / 1024).toFixed(1)} KB` : "—"],
        ["SHA-256", doc.sha256 ? `${doc.sha256.slice(0, 12)}…${doc.sha256.slice(-4)}` : "—"],
        ["Document ID", doc.id.slice(0, 8) + "…"],
      ]
      for (const [k, v] of metaRows) {
        y -= 22
        page.drawText(k.toUpperCase(), {
          x: 50, y, size: 7, font: fontBold, color: INK_SOFT,
        })
        page.drawText(String(v), {
          x: 200, y, size: 11, font: fontRegular, color: INK,
        })
      }

      // Watermark
      page.drawText("DEV PLACEHOLDER · NOT FOR DISTRIBUTION", {
        x: 50, y: 60, size: 8, font: fontBold, color: rgb(0.55, 0.598, 0.7),
      })
    } else {
      // Filler page with section title + lorem-ish prose
      page.drawText(`Section ${String(i + 1).padStart(2, "0")} · placeholder body`, {
        x: 50, y: PAGE_H - 130, size: 14, font: fontBold, color: INK,
      })
      page.drawLine({
        start: { x: 50, y: PAGE_H - 140 }, end: { x: 200, y: PAGE_H - 140 },
        thickness: 1.5, color: ROYAL,
      })

      const body =
        "This is a placeholder PDF generated by the Worker for development. " +
        "Each document in the seed has a minimal multi-page artifact backing it so the " +
        "Document Viewer can exercise its page-navigation, zoom and download flows " +
        "without a real R2 bucket. Production deploys would back this endpoint with " +
        "an R2 GetObject call instead, and the bytes here would never need to be " +
        "synthesized at request time. The document's actual title, source and key " +
        "metadata are printed on page 1; pages 2..N exist purely to exercise the " +
        "renderer."
      // Naive word wrapping
      const maxLineChars = 78
      const words = body.split(" ")
      let line = ""
      let y2 = PAGE_H - 180
      for (const w of words) {
        if ((line + " " + w).trim().length > maxLineChars) {
          page.drawText(line.trim(), { x: 50, y: y2, size: 11, font: fontRegular, color: INK })
          y2 -= 18
          line = w
        } else {
          line = line ? line + " " + w : w
        }
      }
      if (line) {
        page.drawText(line.trim(), { x: 50, y: y2, size: 11, font: fontRegular, color: INK })
      }
    }

    // Footer
    page.drawLine({
      start: { x: 50, y: 60 }, end: { x: PAGE_W - 50, y: 60 },
      thickness: 0.5, color: RULE,
    })
    page.drawText(`Page ${i + 1} of ${pageCount}`, {
      x: 50, y: 42, size: 8, font: fontRegular, color: INK_SOFT,
    })
    page.drawText(doc.title, {
      x: PAGE_W - 50 - fontItalic.widthOfTextAtSize(doc.title, 8), y: 42,
      size: 8, font: fontItalic, color: INK_SOFT,
    })
  }

  return await pdfDoc.save()
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/documents/upload-url
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Body: { title, category, fileFormat, fileSizeBytes, ... }
 *
 * Creates a `pending_upload` row + returns presigned PUT URL.
 * The object key is server-chosen — the client never names files in R2.
 */
app.post("/upload-url", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  if (!isStorageConfigured()) {
    throw new AppError(
      "INTERNAL",
      "Document storage is not configured. Set R2_* in .env",
    )
  }

  const body = uploadUrlSchema.parse(await c.req.json())

  const documentId = randomUUID()
  const key = makeObjectKey({
    clientId: client.id,
    documentId,
    ext: body.fileFormat,
  })

  // Pre-create the documents row in `pending_upload` — finalize flips it.
  await db.insert(documents).values({
    id: documentId,
    clientId: client.id,
    category: body.category,
    title: body.title,
    description: body.description ?? null,
    sourceLabel: body.sourceLabel ?? null,
    sourceParty: body.sourceParty ?? null,
    fileUrl: key, // store the R2 object key here; presigner consumes it
    fileFormat: body.fileFormat,
    fileSizeBytes: body.fileSizeBytes,
    sha256: null,
    issuedAt: body.issuedAt ? new Date(body.issuedAt) : null,
    tags: body.tags ?? null,
    taxYear: body.taxYear ?? null,
    uploadedByUserId: user.id,
    status: "pending_upload",
  })

  const { uploadUrl, expiresAt } = await presignUpload({
    key,
    contentType: FORMAT_TO_MIME[body.fileFormat] ?? "application/octet-stream",
    contentLength: body.fileSizeBytes,
  })

  await audit({
    action: "document.upload_url_issued",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "document",
    resourceId: documentId,
    metadata: { sizeBytes: body.fileSizeBytes, format: body.fileFormat },
  })

  return c.json({
    ok: true,
    documentId,
    uploadUrl,
    expiresAt,
    method: "PUT",
    headers: {
      "Content-Type":
        FORMAT_TO_MIME[body.fileFormat] ?? "application/octet-stream",
    },
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/documents/:id/finalize
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Body: { sha256 }
 *
 * Confirms the upload — HEADs the R2 object, verifies size matches the
 * pre-declared `file_size_bytes`, stamps `sha256`, and flips `status` to
 * `active`. Idempotent: calling on an already-finalized doc is a no-op 200.
 */
app.post("/:id/finalize", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  if (!isStorageConfigured()) {
    throw new AppError(
      "INTERNAL",
      "Document storage is not configured. Set R2_* in .env",
    )
  }

  const body = finalizeUploadSchema.parse(await c.req.json())

  const doc = await loadOwnedDoc(id, client.id)
  // Treat already-active as success (idempotency). Anything else is a bug.
  if (doc.status === "active") {
    return c.json({ ok: true, alreadyFinalized: true })
  }

  if (!doc.fileUrl) {
    throw conflict("Document has no R2 key — wasn't created via /upload-url")
  }

  // HEAD the object — confirms presence and gets actual size.
  const head = await headObject(doc.fileUrl)
  if (!head) {
    throw notFound("Uploaded object not found in storage. Did the PUT succeed?")
  }
  if (doc.fileSizeBytes && head.sizeBytes !== doc.fileSizeBytes) {
    throw conflict(
      `Uploaded size (${head.sizeBytes}) doesn't match declared size (${doc.fileSizeBytes})`,
    )
  }

  await db
    .update(documents)
    .set({
      status: "active",
      sha256: body.sha256.toLowerCase(),
      deliveredAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(documents.id, doc.id))

  await audit({
    action: "document.finalize",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "document",
    resourceId: doc.id,
    metadata: { sha256: body.sha256.toLowerCase(), sizeBytes: head.sizeBytes },
  })

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/v1/documents/:id/sign
// ═══════════════════════════════════════════════════════════════════════════

app.post("/:id/sign", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null
  const id = c.req.param("id")

  const body = signSchema.parse(await c.req.json())

  const doc = await loadOwnedDoc(id, client.id)
  if (doc.status !== "pending_signature") {
    throw conflict(
      `Document status is "${doc.status}" — only pending_signature can be signed`,
    )
  }

  await db.insert(documentSignatures).values({
    documentId: doc.id,
    signerUserId: user.id,
    signatureImageUrl: body.signatureImageUrl ?? null,
    signatureMethod: body.signatureMethod,
    signedIp: ip,
    signedUserAgent: userAgent,
    envelopeRef: body.envelopeRef ?? null,
  })

  await db
    .update(documents)
    .set({
      status: "active",
      pendingAction: null,
      pendingDueAt: null,
      updatedAt: new Date(),
    })
    .where(eq(documents.id, doc.id))

  await audit({
    action: "document.signed",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "document",
    resourceId: doc.id,
    metadata: {
      method: body.signatureMethod,
      typedName: body.typedName ?? null,
    },
  })

  return c.json({ ok: true })
})

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/documents/requests
// POST /api/v1/documents/requests
// ═══════════════════════════════════════════════════════════════════════════

app.get("/requests", async (c) => {
  const client = requireClient(c)
  const rows = await db
    .select()
    .from(documentRequests)
    .where(eq(documentRequests.clientId, client.id))
    .orderBy(desc(documentRequests.submittedAt))
  return c.json({ ok: true, requests: rows })
})

app.post("/requests", async (c) => {
  const client = requireClient(c)
  const user = c.get("user")
  const ip = extractIp(c)
  const userAgent = c.req.header("user-agent") ?? null

  const body = documentRequestCreateSchema.parse(await c.req.json())

  const [created] = await db
    .insert(documentRequests)
    .values({
      clientId: client.id,
      userId: user.id,
      requestType: body.requestType,
      purpose: body.purpose ?? null,
      recipient: body.recipient ?? null,
      asOfDate: body.asOfDate ?? null,
      neededByDate: body.neededByDate ?? null,
      format: body.format,
      notes: body.notes ?? null,
    })
    .returning({ id: documentRequests.id })

  await audit({
    action: "document.request.create",
    userId: user.id,
    clientId: client.id,
    ip,
    userAgent,
    resourceType: "document_request",
    resourceId: created!.id,
    metadata: { requestType: body.requestType, format: body.format },
  })

  return c.json({ ok: true, id: created!.id }, 201)
})

export default app

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Load a document and verify it belongs to the calling client. Throws 404
 * for "not yours" (don't differentiate from "not found" — leaks existence).
 */
async function loadOwnedDoc(id: string, clientId: string) {
  const doc = await db.query.documents.findFirst({
    where: and(eq(documents.id, id), eq(documents.clientId, clientId)),
  })
  if (!doc) throw notFound("Document not found")
  return doc
}

function shapeDoc(d: typeof documents.$inferSelect) {
  return {
    id: d.id,
    category: d.category,
    title: d.title,
    displayCode: d.displayCode,
    description: d.description,
    sourceLabel: d.sourceLabel,
    sourceParty: d.sourceParty,
    fileFormat: d.fileFormat,
    fileSizeBytes: d.fileSizeBytes,
    pages: d.pages,
    sha256: d.sha256,
    issuedAt: d.issuedAt,
    deliveredAt: d.deliveredAt,
    retentionUntil: d.retentionUntil,
    isArchived: d.isArchived,
    status: d.status,
    pendingAction: d.pendingAction,
    pendingDueAt: d.pendingDueAt,
    tags: d.tags,
    taxYear: d.taxYear,
    // Added 2026-05: UI grouping + sidebar metadata. See schema.ts.
    isFolded: d.isFolded,
    metadata: d.metadata,
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
  }
}
