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

export type Section =
  | ProseBlock
  | TableBlock
  | KvGridBlock
  | ActionsBlock
  | ReactionBlock

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
