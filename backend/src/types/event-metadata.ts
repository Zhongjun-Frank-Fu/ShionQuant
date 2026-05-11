/**
 * Schema for `events.metadata` (jsonb column) — drives the rich rendering
 * on Shion Quant Event Detail.html. See docs/event-metadata-schema.md for
 * the human-readable spec.
 *
 * Frontend block renderers live in `Shion Quant Event Detail.html` and
 * key off `block.kind`. Adding a new block kind requires touching:
 *   1. this file (add a member to `Section`)
 *   2. docs/event-metadata-schema.md (document it)
 *   3. Event Detail's renderSection dispatcher (add a renderer)
 */

/**
 * Bilingual string. Either a {en, zh} pair (preferred) or a plain string
 * for genuinely-identical-in-both-languages content (tickers, currency
 * figures). The frontend's render helper accepts both.
 */
export type BilingualString =
  | string
  | { en: string; zh: string }

export interface ProseBlock {
  kind: "prose"
  title?: BilingualString
  eyebrow?: BilingualString
  body: BilingualString
}

export interface TableColumn {
  key: string
  label: BilingualString
  align?: "left" | "right" | "center"
  /** If "sign", cells turn green/red based on leading `+`/`-`. */
  tone?: "sign"
}

export interface TableBlock {
  kind: "table"
  title?: BilingualString
  eyebrow?: BilingualString
  columns: TableColumn[]
  /** Row cell values are pre-formatted strings (or numbers cast to display). */
  rows: Array<Record<string, string | number | null>>
}

export interface KvGridItem {
  label: BilingualString
  value: string | number
  sub?: BilingualString
  pill?: {
    text: BilingualString
    tone?: "default" | "warn" | "gain" | "loss"
  }
}

export interface KvGridBlock {
  kind: "kvgrid"
  title?: BilingualString
  eyebrow?: BilingualString
  items: KvGridItem[]
}

export interface ActionItem {
  priority: "high" | "medium" | "low"
  action: BilingualString
  rationale?: BilingualString
}

export interface ActionsBlock {
  kind: "actions"
  title?: BilingualString
  eyebrow?: BilingualString
  items: ActionItem[]
}

export interface ReactionRow {
  period: BilingualString
  surprise: BilingualString
  reaction: BilingualString
  tone?: "gain" | "loss" | "neutral"
}

export interface ReactionBlock {
  kind: "reaction"
  title?: BilingualString
  eyebrow?: BilingualString
  rows: ReactionRow[]
}

/**
 * Figure block — display an inline figure (chart screenshot, diagram).
 * Source is either an external URL or a base64 data URI. Captions are
 * optional and bilingual.
 */
export interface FigureBlock {
  kind: "figure"
  title?: BilingualString
  eyebrow?: BilingualString
  /** Image URL (https://...) or data: URI. Frontend doesn't transform it. */
  src: string
  /** Alt text for screen readers + load-failure fallback. */
  alt: BilingualString
  caption?: BilingualString
  /** Optional: "16:9", "4:3", "1:1", or "auto" (browser-natural). */
  aspect?: "16:9" | "4:3" | "1:1" | "auto"
}

/**
 * Code block — fixed-pitch source listing. Language is informational
 * (used for label) but not interpreted by the renderer (no syntax
 * highlighting in MVP). For multi-line snippets, pass the full string
 * with embedded `\n`.
 */
export interface CodeBlock {
  kind: "code"
  title?: BilingualString
  eyebrow?: BilingualString
  /** e.g. "python", "sql", "r", "ts". Free-form string. */
  language?: string
  /** Optional filename / origin label shown above the code body. */
  filename?: string
  /** The actual source. Preserved verbatim. */
  code: string
}

export type Section =
  | ProseBlock
  | TableBlock
  | KvGridBlock
  | ActionsBlock
  | ReactionBlock
  | FigureBlock
  | CodeBlock

/**
 * Shape stored in events.metadata. Future fields belong here too
 * (`location`, `meetingUrl`, etc.). `sections` is the structured
 * deep-dive content; everything else is freeform.
 */
export interface EventMetadata {
  sections?: Section[]
  // Freeform side-channel fields used by various event types.
  location?: string
  meetingUrl?: string
  // Adding new top-level metadata keys is non-breaking — the detail page
  // ignores anything it doesn't know about.
  [key: string]: unknown
}
