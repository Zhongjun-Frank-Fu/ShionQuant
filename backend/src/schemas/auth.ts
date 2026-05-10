/**
 * Zod schemas for auth endpoints.
 *
 * `loginSchema` is intentionally lenient — we don't want the response to
 * differentiate "format invalid" from "credentials wrong". Format errors
 * still return 422; credentials errors return 401 with the same generic
 * message. The frontend treats both as a single failure mode.
 */

import { z } from "zod"

export const loginSchema = z.object({
  email: z.string().min(3).max(254).toLowerCase().trim(),
  password: z.string().min(1).max(1024),  // any length; argon2 handles bounds
  rememberDevice: z.boolean().optional().default(true),
})

export const mfaSchema = z.object({
  challengeToken: z.string().min(10),
  code: z.string().min(6).max(11),  // 6 digits OR 11-char recovery code (XXXXX-XXXXX)
})

export const logoutSchema = z.object({
  allDevices: z.boolean().optional().default(false),
})
