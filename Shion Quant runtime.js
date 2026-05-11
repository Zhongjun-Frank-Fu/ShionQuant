/*!
 * Shion Quant — shared portal runtime
 * ============================================================================
 * Loaded by every portal HTML page via <script defer>. Exposes a single
 * global namespace `window.SQ` with the primitives every page needs:
 *
 *   SQ.api(path, init)       — credentialed fetch w/ JSON + 401 redirect + 5xx toast
 *   SQ.fetch(key, fn, opts)  — sessionStorage stale-while-revalidate cache
 *   SQ.section(opts)         — declarative section loader (target, fetcher, render,
 *                              skeleton, deps, cacheKey, ttlMs). Handles every
 *                              state (skeleton → loading → loaded / error / empty).
 *   SQ.bind(key, value)      — sets [data-bind="key"].textContent across the page
 *   SQ.rebuild(key, html)    — sets [data-rebuild="key"].innerHTML across the page
 *   SQ.escape(s)             — XSS-safe HTML escape
 *   SQ.toast(msg, opts)      — bottom-right ephemeral toast (replaces all per-page copies)
 *   SQ.isZh() / SQ.onLang()  — language helpers (EN/ZH toggle)
 *   SQ.fmt.{date, time, datetime, relative, duration, money, pct}
 *   SQ.redirectToLogin(why)  — single source of truth for 401 navigation
 *   SQ.invalidate(prefix)    — wipe cache entries whose key starts with `prefix`
 *
 * Design notes
 * ─────────────────────────────────────────────────────────────────────────────
 *  • Idempotent: re-loading the script is a no-op (returns early).
 *  • Backward-compatible: pages that don't call SQ.* still work — existing
 *    inline IIFEs continue to coexist (each maintains its own state).
 *  • Cache is keyed in sessionStorage so a new tab pays the cost once; nav
 *    inside the tab is instant. Default TTL 5 minutes — covers a normal
 *    portal browsing session without showing stale data after a long break.
 *  • Stale-while-revalidate: a cached value within TTL is returned synchronously
 *    AND a background refresh fires; the section re-renders silently when
 *    fresh data arrives. Crash-resilient: a failed refresh keeps the cached
 *    value visible.
 *  • Inflight dedup: two concurrent SQ.fetch calls with the same key share
 *    one network request.
 *  • No imports — plain script, runs everywhere.
 */
(function() {
  "use strict"
  if (window.SQ && window.SQ.__v) return // idempotent

  // ─── Config ──────────────────────────────────────────────────────────────
  const API_BASE = (() => {
    if (typeof window.__SQ_API_BASE__ === "string") return window.__SQ_API_BASE__
    const meta = document.querySelector('meta[name="sq-api-base"]')
    if (meta && meta.content) return meta.content
    const host = window.location.hostname
    const isLocal =
      window.location.protocol === "file:" ||
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === ""
    return isLocal ? "http://localhost:8787/api/v1" : "/api/v1"
  })()

  const CACHE_NS = "sq:v2:" // bump if cache shape changes
  const DEFAULT_TTL_MS = 5 * 60 * 1000
  const inflight = new Map() // key → Promise (dedup)
  const langListeners = []

  // ─── DOM helpers ─────────────────────────────────────────────────────────
  const $ = (sel, root) => (root || document).querySelector(sel)
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel))

  function escapeHtml(s) {
    if (s == null) return ""
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[c])
  }

  function bind(key, value) {
    $$(`[data-bind="${key}"]`).forEach((el) => {
      el.textContent = value == null ? "—" : String(value)
    })
  }

  function rebuild(key, html) {
    const el = $(`[data-rebuild="${key}"]`)
    if (el) el.innerHTML = html
    return el
  }

  function isZh() {
    return document.body.classList.contains("lang-zh")
  }
  function onLang(cb) {
    langListeners.push(cb)
    return () => {
      const i = langListeners.indexOf(cb)
      if (i >= 0) langListeners.splice(i, 1)
    }
  }
  // Watch for lang-zh class toggle on body and notify listeners.
  // MutationObserver is cheap (single attribute filter).
  const langObserver = new MutationObserver(() => {
    for (const cb of langListeners) {
      try { cb(isZh()) } catch (err) { console.warn("[SQ] lang listener:", err) }
    }
  })
  langObserver.observe(document.body, { attributes: true, attributeFilter: ["class"] })

  // ─── Auth coordination ───────────────────────────────────────────────────
  // 401 path: every page sends users back to /index.html. Preserve the
  // current path so the login flow can bounce back after auth (future
  // enhancement — query string is stable, just unused right now).
  let redirecting = false
  function redirectToLogin(why) {
    if (redirecting) return
    redirecting = true
    const ret = encodeURIComponent(window.location.pathname + window.location.search)
    const debug = why ? `?return=${ret}&from=${encodeURIComponent(why)}` : ""
    // Hit the public login page. Use replace so back-button doesn't bounce.
    window.location.replace("index.html" + debug)
  }

  // ─── HTTP layer ──────────────────────────────────────────────────────────
  /**
   * SQ.api(path, init)
   *   path: "/account/me" (will prepend API_BASE) OR absolute http(s) URL
   *   init: standard fetch init
   *     - body as object → JSON-serialized + Content-Type set
   *     - credentials defaults to 'include'
   *   resolves to parsed JSON; rejects on !ok with { status, code, message }
   *   On 401: triggers global redirect AND rejects (so the caller's catch
   *   doesn't have to special-case auth).
   */
  async function api(path, init) {
    init = init || {}
    const url = /^https?:\/\//.test(path) ? path : API_BASE + path
    const headers = Object.assign(
      { Accept: "application/json" },
      init.headers || {},
    )
    let body = init.body
    if (body && typeof body === "object" && !(body instanceof FormData) && !(body instanceof Blob)) {
      headers["Content-Type"] = headers["Content-Type"] || "application/json"
      body = JSON.stringify(body)
    }
    const res = await fetch(url, {
      method: init.method || (body ? "POST" : "GET"),
      credentials: init.credentials || "include",
      headers,
      body,
      signal: init.signal,
    })
    if (res.status === 401) {
      redirectToLogin("api")
      const err = new Error("Unauthorized")
      err.status = 401
      throw err
    }
    // Some endpoints (ICS / RSS) return non-JSON. If the caller asked
    // explicitly via init.parse, honor it; otherwise default to JSON.
    let payload = null
    const contentType = res.headers.get("content-type") || ""
    if (init.parse === "text") payload = await res.text()
    else if (init.parse === "blob") payload = await res.blob()
    else if (contentType.includes("json")) payload = await res.json()
    else payload = await res.text()

    if (!res.ok) {
      const err = new Error(
        (payload && payload.message) ||
          (payload && payload.error) ||
          `HTTP ${res.status}`,
      )
      err.status = res.status
      err.code = payload && payload.code
      err.payload = payload
      throw err
    }
    return payload
  }

  // ─── Cache + SWR ─────────────────────────────────────────────────────────
  function cacheRead(key) {
    try {
      const raw = sessionStorage.getItem(CACHE_NS + key)
      if (!raw) return null
      const parsed = JSON.parse(raw)
      return parsed && parsed.t && parsed.v !== undefined ? parsed : null
    } catch { return null }
  }
  function cacheWrite(key, value) {
    try {
      sessionStorage.setItem(
        CACHE_NS + key,
        JSON.stringify({ t: Date.now(), v: value }),
      )
    } catch {
      // Quota / private mode — silently drop. Network still works.
    }
  }
  /**
   * Wipe cache entries whose key starts with `prefix`. Pass an empty string
   * to nuke everything. Call after a write that affects another section
   * (e.g. POST a contact request → invalidate("contact.")).
   */
  function invalidate(prefix) {
    prefix = prefix || ""
    const full = CACHE_NS + prefix
    const keys = []
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const k = sessionStorage.key(i)
      if (k && k.indexOf(full) === 0) keys.push(k)
    }
    keys.forEach((k) => sessionStorage.removeItem(k))
  }

  /**
   * SQ.fetch(key, fetcher, opts)
   *   key:     cache key (e.g. "billing.plan", "user.identity")
   *   fetcher: () => Promise<value>
   *   opts:    { ttlMs?: number, onUpdate?: (value) => void }
   *
   * Returns a thenable that resolves with the *initial* value to show
   *   - cached value if present (regardless of age)
   *   - network value if no cache
   *
   * If cached but stale (older than ttlMs), kicks off a background refresh
   * and calls opts.onUpdate(freshValue) when it lands. Failed refreshes are
   * swallowed (we keep showing the cached value).
   *
   * Concurrent calls with the same key share one inflight promise.
   */
  function fetchKeyed(key, fetcher, opts) {
    opts = opts || {}
    const ttl = opts.ttlMs != null ? opts.ttlMs : DEFAULT_TTL_MS
    const cached = cacheRead(key)
    const now = Date.now()
    const isFresh = cached && now - cached.t < ttl

    if (cached && isFresh) {
      // Don't even hit the network — caller gets cached value, no revalidation.
      return Promise.resolve(cached.v)
    }
    if (cached && !isFresh) {
      // Stale-while-revalidate: return cached now, refresh in background.
      revalidate(key, fetcher, opts)
      return Promise.resolve(cached.v)
    }
    // No cache — share inflight or kick off a network fetch.
    if (inflight.has(key)) return inflight.get(key)
    const p = Promise.resolve()
      .then(fetcher)
      .then((value) => {
        cacheWrite(key, value)
        inflight.delete(key)
        return value
      })
      .catch((err) => {
        inflight.delete(key)
        throw err
      })
    inflight.set(key, p)
    return p
  }
  function revalidate(key, fetcher, opts) {
    if (inflight.has(key)) return // already revalidating
    const p = Promise.resolve()
      .then(fetcher)
      .then((value) => {
        cacheWrite(key, value)
        inflight.delete(key)
        if (typeof opts.onUpdate === "function") {
          try { opts.onUpdate(value) } catch (err) { console.warn("[SQ] onUpdate:", err) }
        }
        return value
      })
      .catch((err) => {
        inflight.delete(key)
        console.warn("[SQ] revalidate failed for", key, err.message || err)
      })
    inflight.set(key, p)
    return p
  }

  // ─── Section loader ──────────────────────────────────────────────────────
  /**
   * SQ.section({
   *   target,       // selector "[data-rebuild=...]" or Element
   *   fetcher,      // () => Promise<data> — caller is free to call SQ.api here
   *   render,       // (data, el) => void  | returns string (set as innerHTML)
   *   skeleton?,    // string | "list:5" | "card" | (el) => void
   *   onError?,     // (err, el) => void
   *   isEmpty?,     // (data) => boolean — if true, shows empty state
   *   emptyHtml?,   // EN/ZH HTML for empty state (default localized stub)
   *   cacheKey?,    // string — enables SWR; omit to bypass cache
   *   ttlMs?,       // override default 5min TTL
   * })
   *
   * The loader paints a skeleton immediately, fires the fetcher, and on
   * success calls render(data). If a cached value exists, render runs
   * synchronously with cache then again with fresh data — no flicker because
   * the second render sees nearly-identical HTML.
   */
  function section(opts) {
    const el = typeof opts.target === "string" ? $(opts.target) : opts.target
    if (!el) {
      console.warn("[SQ.section] target not found:", opts.target)
      return Promise.resolve(null)
    }

    // Paint skeleton immediately so users see structure.
    paintSkeleton(el, opts.skeleton)

    const doRender = (data) => {
      try {
        if (typeof opts.isEmpty === "function" && opts.isEmpty(data)) {
          el.innerHTML = opts.emptyHtml || defaultEmptyHtml()
          return
        }
        const html = opts.render(data, el)
        if (typeof html === "string") el.innerHTML = html
      } catch (err) {
        console.warn("[SQ.section] render threw:", err)
        if (typeof opts.onError === "function") opts.onError(err, el)
        else paintError(el, err)
      }
    }

    const onErr = (err) => {
      if (err && err.status === 401) return // redirect already triggered
      if (typeof opts.onError === "function") opts.onError(err, el)
      else paintError(el, err)
    }

    let p
    if (opts.cacheKey) {
      p = fetchKeyed(opts.cacheKey, opts.fetcher, {
        ttlMs: opts.ttlMs,
        onUpdate: (fresh) => doRender(fresh),
      })
    } else {
      p = Promise.resolve().then(opts.fetcher)
    }
    return p.then(doRender, onErr)
  }

  function paintSkeleton(el, shape) {
    if (typeof shape === "function") { shape(el); return }
    if (typeof shape === "string" && shape.startsWith("list:")) {
      const n = parseInt(shape.split(":")[1], 10) || 3
      el.innerHTML = Array.from({ length: n })
        .map(() => `
          <div class="sq-skel-row">
            <div class="sq-skel sq-skel-line short"></div>
            <div class="sq-skel sq-skel-line"></div>
          </div>
        `).join("")
      return
    }
    if (shape === "card" || !shape) {
      el.innerHTML = `
        <div class="sq-skel-card">
          <div class="sq-skel sq-skel-line short"></div>
          <div class="sq-skel sq-skel-line"></div>
          <div class="sq-skel sq-skel-line"></div>
        </div>`
      return
    }
    el.innerHTML = shape // raw HTML passthrough
  }
  function paintError(el, err) {
    const status = err && err.status ? ` (${err.status})` : ""
    el.innerHTML = `
      <div class="sq-error">
        <span class="en-inline">Couldn't load this section${status}. Refresh to retry.</span>
        <span class="zh-inline">此处加载失败${status}，请刷新重试。</span>
      </div>`
  }
  function defaultEmptyHtml() {
    return `
      <div class="sq-empty">
        <span class="en-inline">No items yet.</span>
        <span class="zh-inline">暂无内容。</span>
      </div>`
  }

  // ─── Toast ───────────────────────────────────────────────────────────────
  let toastEl = null
  let toastTimer = null
  function toast(msg, opts) {
    if (!toastEl) {
      toastEl = document.createElement("div")
      toastEl.className = "sq-toast"
      document.body.appendChild(toastEl)
    }
    toastEl.textContent = msg
    toastEl.classList.toggle("err", !!(opts && opts.error))
    toastEl.classList.add("show")
    clearTimeout(toastTimer)
    toastTimer = setTimeout(() => toastEl.classList.remove("show"), (opts && opts.ms) || 2800)
  }

  // ─── Formatters ──────────────────────────────────────────────────────────
  const fmt = {
    date(d, opts) {
      if (!d) return "—"
      const date = d instanceof Date ? d : new Date(d)
      const lang = isZh() ? "zh-CN" : "en-US"
      return date.toLocaleDateString(lang, opts || { weekday: "short", month: "short", day: "numeric" })
    },
    time(d) {
      if (!d) return "—"
      const date = d instanceof Date ? d : new Date(d)
      return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false })
    },
    datetime(d) {
      if (!d) return "—"
      const date = d instanceof Date ? d : new Date(d)
      return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    },
    relative(iso) {
      if (!iso) return "—"
      const ms = Date.now() - new Date(iso).getTime()
      const min = Math.round(ms / 60_000)
      const zh = isZh()
      if (Math.abs(min) < 60) return zh ? `${min} 分钟前` : `${min}m ago`
      const hr = Math.round(min / 60)
      if (Math.abs(hr) < 24) return zh ? `${hr} 小时前` : `${hr}h ago`
      const day = Math.round(hr / 24)
      if (Math.abs(day) < 7) return zh ? `${day} 天前` : `${day}d ago`
      const wk = Math.round(day / 7)
      return zh ? `${wk} 周前` : `${wk}w ago`
    },
    /** Minutes → "1d · 3h · 30m" form. Handy for reminder lead-times. */
    duration(min) {
      if (min == null) return "—"
      if (min >= 60 * 24) return `${Math.round(min / (60 * 24))}d`
      if (min >= 60) return `${Math.round(min / 60)}h`
      return `${min}m`
    },
    money(n, ccy) {
      if (n == null) return "—"
      const x = Number(n)
      if (!isFinite(x)) return "—"
      try {
        return new Intl.NumberFormat(undefined, {
          style: "currency",
          currency: ccy || "USD",
          maximumFractionDigits: x < 1 ? 4 : 0,
        }).format(x)
      } catch {
        return `$${x.toLocaleString()}`
      }
    },
    pct(n, d) {
      if (n == null) return "—"
      const v = Number(n)
      if (!isFinite(v)) return "—"
      return `${(v * 100).toFixed(d == null ? 2 : d)}%`
    },
    tzShort() {
      try {
        const dtf = new Intl.DateTimeFormat("en-US", { timeZoneName: "short" })
        const part = dtf.formatToParts(new Date()).find((p) => p.type === "timeZoneName")
        return part ? part.value : "local"
      } catch { return "local" }
    },
  }

  // ─── User identity (replaces SQ-USER-IDENTITY-V1 across all pages) ───────
  // Populates [data-bind="user.*"] from /account/me. Uses SQ.fetch so the
  // identity is shared across pages — first nav pays the network cost, the
  // rest hydrate instantly from sessionStorage.
  async function loadUserIdentity() {
    try {
      const me = await fetchKeyed("user.identity",
        () => api("/account/me"),
        {
          ttlMs: DEFAULT_TTL_MS,
          onUpdate: applyUserBindings,
        },
      )
      applyUserBindings(me)
    } catch (err) {
      if (err && err.status !== 401) console.warn("[SQ] user identity:", err.message || err)
    }
  }
  function applyUserBindings(me) {
    if (!me) return
    const map = {
      "user.initial":              (me.profile && me.profile.initial) || "?",
      "user.preferredName":        (me.profile && me.profile.preferredName) || (me.user && me.user.email) || "—",
      "user.preferredChineseName": (me.profile && me.profile.preferredChineseName) || (me.profile && me.profile.preferredName) || "—",
      "user.fullEn":               (me.profile && me.profile.preferredName) || (me.user && me.user.email) || "—",
      "user.fullZh":               (me.profile && me.profile.preferredChineseName) || (me.profile && me.profile.preferredName) || "—",
      "user.email":                (me.profile && me.profile.primaryEmail) || (me.user && me.user.email) || "—",
    }
    for (const k in map) bind(k, map[k])
  }

  // Auto-boot the identity hydrator after DOM is interactive so even pages
  // that don't call SQ.* explicitly still get their nav avatars populated.
  function bootIdentity() {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", loadUserIdentity, { once: true })
    } else {
      loadUserIdentity()
    }
  }
  bootIdentity()

  // ─── Public surface ──────────────────────────────────────────────────────
  window.SQ = {
    __v: 1,
    API_BASE,
    api,
    fetch: fetchKeyed,
    invalidate,
    section,
    bind,
    rebuild,
    escape: escapeHtml,
    $,
    $$,
    isZh,
    onLang,
    toast,
    fmt,
    redirectToLogin,
    // Re-exposed so pages that want to wire their own identity logic can:
    loadUserIdentity,
  }
})()
