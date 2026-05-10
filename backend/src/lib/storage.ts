/**
 * Document storage abstraction — Cloudflare R2 (or any S3-compatible).
 *
 * Configuration:
 *   - R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY, R2_SECRET_KEY in .env
 *   - R2_REGION optional ("auto" for R2, an AWS region for S3)
 *
 * If any of the four required vars is missing, `getStorage()` throws a clear
 * 503-style error. List / metadata endpoints in /api/v1/documents work fine
 * without storage configured; only upload / download bytes paths need it.
 *
 * Object key conventions (NEVER serialize document IDs into the path before
 * the row exists — the row is the source of truth):
 *
 *   clients/{clientId}/{documentId}.{ext}
 *
 * This keeps tenant boundaries visible at the storage layer (cross-client
 * R2 bucket policies become trivial later) and makes audit-forensics easy
 * (one prefix → one client's files).
 *
 * Presigned URLs:
 *   - PUT (upload): 15 min expiry. Client uploads directly; server never
 *     touches the bytes.
 *   - GET (download): 5 min expiry. Re-issued on every fetch. Cookie auth
 *     gates the issue, the URL itself is single-use-ish (anyone with the URL
 *     during its TTL can download — that's the security model).
 *
 * Why no server-side proxying:
 *   - Saves bandwidth: 100 MB statements don't go through our app process
 *   - Lets us scale R2 independently
 *   - Forces every download through the audit log via the URL-issue endpoint
 *
 * The S3 SDK call surface is intentionally minimal — three operations:
 *
 *     presignUpload({ key, contentType, contentLength })
 *     presignDownload({ key, contentDisposition? })
 *     headObject({ key })   →  { sizeBytes, sha256 } | null
 */

import {
  HeadObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3"
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"

import { env } from "../env.js"
import { AppError } from "./errors.js"

// ─── Config + lazy client ─────────────────────────────────────────────────

interface StorageConfig {
  endpoint: string
  bucket: string
  accessKey: string
  secretKey: string
  region: string
}

function readConfig(): StorageConfig | null {
  if (
    !env.R2_ENDPOINT ||
    !env.R2_BUCKET ||
    !env.R2_ACCESS_KEY ||
    !env.R2_SECRET_KEY
  ) {
    return null
  }
  return {
    endpoint: env.R2_ENDPOINT,
    bucket: env.R2_BUCKET,
    accessKey: env.R2_ACCESS_KEY,
    secretKey: env.R2_SECRET_KEY,
    region: env.R2_REGION,
  }
}

let cachedClient: S3Client | null = null
let cachedConfig: StorageConfig | null = null

function getStorage(): { client: S3Client; bucket: string } {
  if (cachedClient && cachedConfig) {
    return { client: cachedClient, bucket: cachedConfig.bucket }
  }
  const cfg = readConfig()
  if (!cfg) {
    // 503-style — service unavailable rather than 500. Caller can branch on
    // the code and surface "feature unavailable" to the user.
    throw new AppError(
      "INTERNAL",
      "Document storage is not configured. Set R2_ENDPOINT / R2_BUCKET / R2_ACCESS_KEY / R2_SECRET_KEY in .env",
    )
  }
  cachedClient = new S3Client({
    region: cfg.region,
    endpoint: cfg.endpoint,
    credentials: {
      accessKeyId: cfg.accessKey,
      secretAccessKey: cfg.secretKey,
    },
    // R2 requires path-style addressing; doesn't hurt with AWS S3 either.
    forcePathStyle: true,
  })
  cachedConfig = cfg
  return { client: cachedClient, bucket: cfg.bucket }
}

/**
 * Return whether storage is configured. Call from request handlers to decide
 * whether to attempt a presign or short-circuit with a clear error.
 */
export function isStorageConfigured(): boolean {
  return readConfig() !== null
}

// ─── Object key helpers ───────────────────────────────────────────────────

const SAFE_EXT = /^[a-z0-9]{2,8}$/i

/**
 * Build the canonical R2 key for a client document.
 *
 *   clients/{clientId}/{documentId}.{ext}
 *
 * `ext` MUST be a short alphanumeric file extension (without the dot). We
 * tightly constrain this — the extension is part of the URL the user sees,
 * and any path traversal is a hard bug.
 */
export function makeObjectKey(opts: {
  clientId: string
  documentId: string
  ext: string
}): string {
  const ext = opts.ext.toLowerCase().replace(/^\./, "")
  if (!SAFE_EXT.test(ext)) {
    throw new AppError("BAD_REQUEST", `invalid file extension: ${opts.ext}`)
  }
  return `clients/${opts.clientId}/${opts.documentId}.${ext}`
}

// ─── Presign + head ───────────────────────────────────────────────────────

const UPLOAD_TTL_SEC = 15 * 60 // 15 min — client may take a while on slow nets
const DOWNLOAD_TTL_SEC = 5 * 60 // 5 min — re-issue on every fetch

export async function presignUpload(opts: {
  key: string
  contentType: string
  contentLength: number
}): Promise<{ uploadUrl: string; expiresAt: Date }> {
  const { client, bucket } = getStorage()
  const cmd = new PutObjectCommand({
    Bucket: bucket,
    Key: opts.key,
    ContentType: opts.contentType,
    ContentLength: opts.contentLength,
  })
  const uploadUrl = await getSignedUrl(client, cmd, { expiresIn: UPLOAD_TTL_SEC })
  const expiresAt = new Date(Date.now() + UPLOAD_TTL_SEC * 1000)
  return { uploadUrl, expiresAt }
}

export async function presignDownload(opts: {
  key: string
  /** Optional: render Content-Disposition header so the browser shows a sensible filename. */
  contentDisposition?: string
}): Promise<{ downloadUrl: string; expiresAt: Date }> {
  const { client, bucket } = getStorage()
  const cmd = new GetObjectCommand({
    Bucket: bucket,
    Key: opts.key,
    ResponseContentDisposition: opts.contentDisposition,
  })
  const downloadUrl = await getSignedUrl(client, cmd, {
    expiresIn: DOWNLOAD_TTL_SEC,
  })
  const expiresAt = new Date(Date.now() + DOWNLOAD_TTL_SEC * 1000)
  return { downloadUrl, expiresAt }
}

/**
 * HEAD an object. Returns its byte size + checksum if present (R2 stores
 * `ChecksumSHA256` when the uploader supplied it), or null if the object
 * doesn't exist.
 *
 * Use after the client claims to have uploaded — the document row stays in
 * `pending_upload` until HEAD confirms presence + size.
 */
export async function headObject(
  key: string,
): Promise<{ sizeBytes: number; sha256?: string } | null> {
  const { client, bucket } = getStorage()
  try {
    const res = await client.send(
      new HeadObjectCommand({ Bucket: bucket, Key: key }),
    )
    return {
      sizeBytes: Number(res.ContentLength ?? 0),
      sha256: res.ChecksumSHA256 ?? undefined,
    }
  } catch (err: unknown) {
    if (
      err &&
      typeof err === "object" &&
      "name" in err &&
      (err.name === "NotFound" || err.name === "NoSuchKey")
    ) {
      return null
    }
    throw err
  }
}
