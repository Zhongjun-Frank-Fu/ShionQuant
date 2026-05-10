/**
 * Envelope encryption + searchable hash for KYC fields.
 *
 *                      ┌─────────────────────────────────────┐
 *   plaintext ───────► │ envelopeEncrypt                     │ ───► bytea
 *                      │   1. generate fresh DEK (32 bytes)  │
 *                      │   2. AES-256-GCM(plaintext, DEK)    │
 *                      │   3. wrap DEK via KMS (lib/kms.ts)  │
 *                      │   4. concat header + wrapped + ct   │
 *                      └─────────────────────────────────────┘
 *
 * Wire format (single bytea column):
 *
 *     ┌────┬──────────────┬──────────────┬─────┬──────────┬─────────────┐
 *     │ v  │ wrap_dek_len │  wrapped_dek │ iv  │ gcm_tag  │ ciphertext  │
 *     │ 1B │    2B BE     │    variable  │ 12B │   16B    │  variable   │
 *     └────┴──────────────┴──────────────┴─────┴──────────┴─────────────┘
 *
 *   v               format version (currently 0x01)
 *   wrap_dek_len    big-endian uint16; lets us swap KMS providers without
 *                   changing the envelope structure (Local KMS = 60 bytes;
 *                   AWS KMS ≈ 150 bytes; GCP KMS varies)
 *   wrapped_dek     opaque to lib/crypto — only lib/kms.ts knows the format
 *   iv              random per encryption — never reused with the same DEK
 *   gcm_tag         AES-GCM auth tag (detects tampering)
 *
 * Threat model assumptions:
 *   ✓ DB compromise alone (without KEK) → ciphertext is opaque
 *   ✓ Application memory snapshot → DEKs cleared post-use (best effort; V8
 *     doesn't guarantee, but we try)
 *   ✗ KEK + DB compromise → game over (mitigated in M3 by moving KEK to KMS)
 *   ✗ Malicious app code → can decrypt anything; defense is code review
 *
 * deterministicHash uses a SEPARATE site key — searchable hashes leak
 * frequency information, so we don't want one key compromise to break both
 * the encryption AND the search hashes.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
} from "node:crypto"

import { env } from "../env.js"
import { kmsUnwrap, kmsWrap } from "./kms.js"

// ─── Wire format constants ────────────────────────────────────────────────

const FORMAT_VERSION = 0x01
const HEADER_LEN = 1 + 2 // version + wrap_dek_len
const IV_LEN = 12
const TAG_LEN = 16
const DEK_LEN = 32

// ─── Internal: envelope encrypt / decrypt ─────────────────────────────────

async function envelopeEncrypt(plaintext: string): Promise<Buffer> {
  if (typeof plaintext !== "string") {
    throw new Error("envelopeEncrypt: plaintext must be a string")
  }

  // 1. Fresh DEK per encryption — never reuse, even within a row.
  const dek = randomBytes(DEK_LEN)

  // 2. Wrap the DEK under the KEK (KMS abstraction).
  const wrappedDek = await kmsWrap(dek)

  // 3. Encrypt the plaintext with AES-256-GCM under the DEK.
  const iv = randomBytes(IV_LEN)
  const cipher = createCipheriv("aes-256-gcm", dek, iv)
  const ct = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()])
  const tag = cipher.getAuthTag()

  // 4. Best-effort: zero out the DEK after we're done. Node's Buffer is
  //    backed by ArrayBuffer; this overwrites the bytes but V8 may have
  //    copied them around inside other objects. Real protection would need
  //    a libsodium-style protected allocator.
  dek.fill(0)

  // 5. Pack the envelope.
  const lenBuf = Buffer.alloc(2)
  lenBuf.writeUInt16BE(wrappedDek.length, 0)
  return Buffer.concat([
    Buffer.from([FORMAT_VERSION]),
    lenBuf,
    wrappedDek,
    iv,
    tag,
    ct,
  ])
}

async function envelopeDecrypt(envelope: Buffer): Promise<string> {
  if (!Buffer.isBuffer(envelope)) {
    throw new Error("envelopeDecrypt: envelope must be a Buffer")
  }
  if (envelope.length < HEADER_LEN + IV_LEN + TAG_LEN) {
    throw new Error("envelopeDecrypt: envelope too short")
  }

  // Parse header.
  const version = envelope.readUInt8(0)
  if (version !== FORMAT_VERSION) {
    throw new Error(
      `envelopeDecrypt: unsupported format version 0x${version.toString(16)}`,
    )
  }
  const wrappedLen = envelope.readUInt16BE(1)

  // Bounds-check the rest of the parse.
  const expectedMin = HEADER_LEN + wrappedLen + IV_LEN + TAG_LEN
  if (envelope.length < expectedMin) {
    throw new Error("envelopeDecrypt: envelope shorter than header indicates")
  }

  let off = HEADER_LEN
  const wrappedDek = envelope.subarray(off, off + wrappedLen)
  off += wrappedLen
  const iv = envelope.subarray(off, off + IV_LEN)
  off += IV_LEN
  const tag = envelope.subarray(off, off + TAG_LEN)
  off += TAG_LEN
  const ct = envelope.subarray(off)

  // Unwrap DEK then decrypt. Always zero the DEK afterwards.
  const dek = await kmsUnwrap(wrappedDek)
  try {
    const decipher = createDecipheriv("aes-256-gcm", dek, iv)
    decipher.setAuthTag(tag)
    const pt = Buffer.concat([decipher.update(ct), decipher.final()])
    return pt.toString("utf-8")
  } finally {
    dek.fill(0)
  }
}

// ─── Public API ──────────────────────────────────────────────────────────

/**
 * Encrypt a low-stakes secret (TOTP seed, recovery seed phrase, …) for
 * storage in a `bytea` column. Same envelope as `encryptField`; the split
 * is purely intentional — `Secret` for things only the user proves they have,
 * `Field` for things the firm holds in trust (KYC).
 */
export async function encryptSecret(plaintext: string): Promise<Buffer> {
  return envelopeEncrypt(plaintext)
}

export async function decryptSecret(envelope: Buffer): Promise<string> {
  return envelopeDecrypt(envelope)
}

/**
 * Encrypt a KYC field (legal name, HKID, passport number, address line, …).
 * Caller is responsible for normalizing the plaintext before encrypting if
 * they also need a `deterministicHash` lookup column (so encrypt and hash
 * see the same bytes).
 */
export async function encryptField(plaintext: string): Promise<Buffer> {
  return envelopeEncrypt(plaintext)
}

export async function decryptField(envelope: Buffer): Promise<string> {
  return envelopeDecrypt(envelope)
}

// ─── Searchable encryption (deterministic hash) ──────────────────────────

/**
 * Lazy SEARCH_KEY accessor — same rationale as `lib/kms.ts` getKek().
 * env.ts validates length via Zod refinement; defensive re-check on first read.
 */
let _searchKey: Buffer | null = null
function getSearchKey(): Buffer {
  if (_searchKey) return _searchKey
  const buf = Buffer.from(env.KYC_SEARCH_KEY_BASE64, "base64")
  if (buf.length !== 32) {
    throw new Error(
      `KYC_SEARCH_KEY_BASE64 must decode to exactly 32 bytes (got ${buf.length})`,
    )
  }
  _searchKey = buf
  return _searchKey
}

/**
 * Deterministic hash for searchable encrypted fields (e.g. legal_name_hash).
 *
 *   - HMAC-SHA256, keyed by SEARCH_KEY (separate from KEK)
 *   - Plaintext is normalized: trim → collapse whitespace → lowercase
 *   - Output is 32 raw bytes; store in a `bytea` column with an index
 *
 * Use sparingly. Trade-off:
 *
 *   ✓ Enables `WHERE legal_name_hash = ?` lookups across encrypted columns
 *   ✗ Leaks frequency: if 50 clients are named "陳", their hashes are equal
 *
 * Don't hash high-cardinality but low-entropy data (DOBs, postcodes) — the
 * adversary can rebuild a rainbow table for the entire input space.
 *
 * Returned as `Buffer` for consistency with the encryption helpers, even
 * though this function is sync (no KMS round-trip needed).
 */
export function deterministicHash(plaintext: string): Buffer {
  const normalized = plaintext.toLowerCase().trim().replace(/\s+/g, " ")
  return createHmac("sha256", getSearchKey()).update(normalized).digest()
}

/**
 * Convenience wrapper for the common case: encrypt + hash for the same
 * plaintext (e.g. a profile's legal name).
 */
export async function encryptAndHash(
  plaintext: string,
): Promise<{ encrypted: Buffer; hash: Buffer }> {
  const [encrypted, hash] = await Promise.all([
    envelopeEncrypt(plaintext),
    Promise.resolve(deterministicHash(plaintext)),
  ])
  return { encrypted, hash }
}
