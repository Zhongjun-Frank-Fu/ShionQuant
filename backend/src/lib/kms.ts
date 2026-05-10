/**
 * Key wrapping abstraction.
 *
 * Two implementations:
 *   - **Local** (this file, dev + early prod): KEK lives in env as a 32-byte
 *     base64 blob (`KYC_KEK_BASE64`). Same algorithm as production-grade KMS,
 *     just with a different key custodian. Fine until you need:
 *       - audit log of every wrap/unwrap (compliance)
 *       - rotation without redeploys
 *       - hardware-isolated key material (HSM)
 *   - **AWS KMS / GCP KMS** (later): the wrap/unwrap below becomes a network
 *     call to `kms.Encrypt({ KeyId, Plaintext })` / `kms.Decrypt({ Ciphertext })`.
 *     The wire format of `wrapped` changes (the KMS adds its own framing) but
 *     the lib/crypto.ts envelope already records `wrapped_dek_len` so swapping
 *     is a 1-file change.
 *
 * The wrapped DEK format from this Local KMS is:
 *
 *     [12-byte iv][16-byte GCM tag][32-byte ciphertext_dek]   = 60 bytes total
 *
 * Always tied to a 32-byte (256-bit) DEK — fixed for now. Future versions
 * could parameterize, but we don't need it.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"

import { env } from "../env.js"

const WRAP_IV_LEN = 12
const WRAP_TAG_LEN = 16
const DEK_LEN = 32
const WRAPPED_LEN = WRAP_IV_LEN + WRAP_TAG_LEN + DEK_LEN // 60

/**
 * Lazy KEK accessor.
 *
 * Workers initialize env per request (after module load), so we can't decode
 * `env.KYC_KEK_BASE64` at module top-level — the proxy throws before the
 * fetch handler runs. First call here decodes + caches; subsequent calls
 * return the cached buffer. env.ts has already Zod-validated the byte
 * length, but we re-check defensively because a wrong KEK is the kind of
 * bug you want to fail loud.
 */
let _kek: Buffer | null = null
function getKek(): Buffer {
  if (_kek) return _kek
  const buf = Buffer.from(env.KYC_KEK_BASE64, "base64")
  if (buf.length !== 32) {
    throw new Error(
      `KYC_KEK_BASE64 must decode to exactly 32 bytes (got ${buf.length})`,
    )
  }
  _kek = buf
  return _kek
}

/**
 * Wrap a 32-byte data encryption key under the master KEK.
 *
 * In production with real KMS, this becomes one network call. We keep the
 * Promise-returning signature so M2 callers don't change when M3 swaps in
 * AWS KMS / GCP KMS.
 */
export async function kmsWrap(dek: Buffer): Promise<Buffer> {
  if (dek.length !== DEK_LEN) {
    throw new Error(`kmsWrap: DEK must be ${DEK_LEN} bytes (got ${dek.length})`)
  }
  const iv = randomBytes(WRAP_IV_LEN)
  const cipher = createCipheriv("aes-256-gcm", getKek(), iv)
  const ct = Buffer.concat([cipher.update(dek), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, ct])
}

/**
 * Reverse `kmsWrap`. Throws if the wrapped blob is malformed or the GCM tag
 * doesn't authenticate (KEK mismatch, tampering, …).
 */
export async function kmsUnwrap(wrapped: Buffer): Promise<Buffer> {
  if (wrapped.length !== WRAPPED_LEN) {
    throw new Error(
      `kmsUnwrap: wrapped DEK must be ${WRAPPED_LEN} bytes (got ${wrapped.length})`,
    )
  }
  const iv = wrapped.subarray(0, WRAP_IV_LEN)
  const tag = wrapped.subarray(WRAP_IV_LEN, WRAP_IV_LEN + WRAP_TAG_LEN)
  const ct = wrapped.subarray(WRAP_IV_LEN + WRAP_TAG_LEN)
  const decipher = createDecipheriv("aes-256-gcm", getKek(), iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ct), decipher.final()])
}

/** The fixed length of a `kmsWrap()` output for this Local KMS. */
export const WRAPPED_DEK_LEN = WRAPPED_LEN
