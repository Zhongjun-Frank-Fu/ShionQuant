/**
 * /api/v1 router — mounts all v1 resources.
 *
 * Adding a new resource: create `./resource.ts` with a default-exported
 * Hono app, then `.route()` it here.
 */

import { Hono } from "hono"

import auth from "./auth.js"
import portfolio from "./portfolio.js"
import schedules from "./schedules.js"
import reports from "./reports.js"
import documents from "./documents.js"
import account from "./account.js"
import communication from "./communication.js"
import health from "./health.js"

const v1 = new Hono()

v1.route("/auth", auth)
v1.route("/portfolio", portfolio)
v1.route("/schedules", schedules)
v1.route("/reports", reports)
v1.route("/documents", documents)
v1.route("/account", account)
v1.route("/communication", communication)
v1.route("/health", health)

export default v1
