/**
 * Hono context extensions.
 *
 * Anything middleware attaches to `c.set(...)` should be declared here so
 * downstream handlers get full type safety on `c.get(...)`.
 */

import "hono"
import type { Client, Session, User } from "../db/schema.js"

declare module "hono" {
  interface ContextVariableMap {
    /** Set by `requestId` middleware — UUIDv4 per request. */
    requestId: string

    /** Set by `auth` middleware on a valid session. */
    session: Session
    user: User
    /** Set if the authenticated user is associated with a client record. */
    client: Client | null

    /** Set by `auth` middleware to indicate 2FA status of current session. */
    is2faVerified: boolean

    /**
     * Set by `rateLimitLoginByEmail` middleware: parsed login body, so the
     * handler doesn't have to re-read the one-shot request stream.
     * Type is `unknown` because the schema validation happens in the handler.
     */
    __loginBody: unknown
  }
}
