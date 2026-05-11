# Event Metadata Schema (v1)

This document defines the JSON structure stored in `events.metadata` (a
`jsonb` column on the `events` table) and consumed by
`Shion Quant Event Detail.html`.

The goal is to keep the **rich, multi-section detail page driven by data**
rather than by per-event-type HTML templates. A future "event editor" UI
can write to this exact same structure.

---

## Top-level shape

```jsonc
{
  // Optional. When present, the Event Detail page renders these blocks
  // top-to-bottom in the main column, replacing the static 4-section demo.
  "sections": [ <Block>, <Block>, ... ],

  // Other freeform fields are allowed and ignored by the detail renderer.
  // Examples already in use: location, meetingUrl, source-specific IDs.
  "location": "Zoom (link in confirmation email)"
}
```

Rules:

- `sections` is **optional**. If missing or empty, the main column shows
  "No additional context for this event".
- Each block must have a `kind` discriminator. Unknown kinds are skipped
  (with a `console.warn`) so adding a new kind is purely additive.
- All human-readable strings are **bilingual objects** (`{en, zh}`) unless
  noted otherwise. The frontend picks the active language at render time.

## Bilingual string convention

A `BilingualString` is:

```jsonc
{ "en": "Position Context", "zh": "仓位背景" }
```

If a string is genuinely identical in both languages (e.g. a ticker
`"NVDA"` or a USD figure `"$1,876,500"`), you may pass a **plain string**
and the renderer will display it as-is regardless of language. Don't
abuse this — proper translation is almost always preferable.

---

## Block kinds

### 1. `prose` — paragraph of explanatory text

```jsonc
{
  "kind": "prose",
  "title": { "en": "Position Context", "zh": "仓位背景" },     // optional
  "eyebrow": { "en": "Direct + linked exposures",              // optional small caps line
               "zh": "直接 + 关联敞口" },
  "body": {
    "en": "Three positions on the book are directly affected ...",
    "zh": "三笔仓位将直接受到本次财报影响……"
  }
}
```

Rendered as the standard `.det-section` head + `.det-prose` paragraph.

### 2. `table` — tabular data

```jsonc
{
  "kind": "table",
  "title": { "en": "Linked positions", "zh": "关联仓位" },     // optional
  "eyebrow": { "en": "...", "zh": "..." },                     // optional
  "columns": [
    { "key": "symbol",   "label": { "en": "Symbol",   "zh": "代码" } },
    { "key": "mark",     "label": { "en": "Mark",     "zh": "现价"  }, "align": "right" },
    { "key": "notional", "label": { "en": "Notional", "zh": "名义"  }, "align": "right" },
    { "key": "pl",       "label": { "en": "P/L",      "zh": "盈亏"  }, "align": "right", "tone": "sign" }
  ],
  "rows": [
    { "symbol": "NVDA", "mark": "$642.18", "notional": "$513,744", "pl": "+$123,904" },
    { "symbol": "SPY",  "mark": "$523.40", "notional": "$1.24M",   "pl": "+$8,200" }
  ]
}
```

Column options:

| Field   | Type                                        | Meaning                            |
|---------|---------------------------------------------|------------------------------------|
| `key`   | string                                      | matches `rows[i][key]`              |
| `label` | BilingualString                             | column header                       |
| `align` | `"left"` (default) / `"right"` / `"center"` | text-align                          |
| `tone`  | `"sign"` (auto green/red based on leading `+`/`-`) / omitted | cell color  |

Rows are arrays of `{key: string|number|null}` records. Values are passed
through as **pre-formatted strings**. The frontend does NOT format
numbers — the producer (seed / event-editor) is responsible for currency
symbols, comma separators, `+/-` signs, etc. This keeps `metadata` self-
contained and makes Locale handling explicit.

### 3. `kvgrid` — label/value tiles (e.g. consensus & implied)

```jsonc
{
  "kind": "kvgrid",
  "title": { "en": "Consensus & implied", "zh": "市场共识与隐含" },
  "items": [
    {
      "label": { "en": "Consensus EPS", "zh": "EPS 共识" },
      "value": "$1.62",                              // string, pre-formatted
      "sub":   { "en": "vs $1.51 prior", "zh": "高于上季 $1.51" },   // optional
      "pill":  { "text": { "en": "BEAT?", "zh": "可能超预期" }, "tone": "gain" }    // optional
    },
    { "label": { "en": "IV before", "zh": "事件前隐含波动" }, "value": "52%" }
  ]
}
```

`pill.tone`: `"default"` / `"warn"` (orange) / `"gain"` (green) /
`"loss"` (red). Defaults to `"default"`.

Layout: 2-column grid by default, becomes 1-column on narrow viewports.

### 4. `actions` — recommended actions / playbook

```jsonc
{
  "kind": "actions",
  "title":   { "en": "Recommended actions", "zh": "建议动作" },
  "eyebrow": { "en": "Three options to consider",
               "zh": "三种可选方案" },                            // optional
  "items": [
    {
      "priority": "high",                                       // high | medium | low
      "action":   { "en": "Roll the 580P down to 560P",
                    "zh": "将 580P 滚动到 560P" },
      "rationale":{ "en": "Cuts cost by 38% with negligible delta change.",
                    "zh": "成本降低 38%，delta 变化可忽略。" }    // optional
    },
    {
      "priority": "medium",
      "action":   { "en": "Hold the existing put",
                    "zh": "保留现有 put" },
      "rationale":{ "en": "Current hedge still covers downside through earnings.",
                    "zh": "当前对冲足以覆盖财报下行。" }
    }
  ]
}
```

Items render as a numbered list with a priority badge on the left.

### 5. `reaction` — historical reaction table (used for earnings)

```jsonc
{
  "kind": "reaction",
  "title": { "en": "Historical reaction", "zh": "历史反应" },
  "eyebrow": { "en": "Last 4 quarters", "zh": "近 4 季度" },     // optional
  "rows": [
    {
      "period":    { "en": "Q4 2025", "zh": "Q4 2025" },
      "surprise":  { "en": "+12.3% vs consensus",
                     "zh": "实际超共识 +12.3%" },
      "reaction":  { "en": "Stock +6.4% next session",
                     "zh": "次个交易日 +6.4%" },
      "tone":      "gain"                          // gain | loss | neutral
    },
    {
      "period":    { "en": "Q3 2025", "zh": "Q3 2025" },
      "surprise":  { "en": "−2.1% miss", "zh": "低于共识 2.1%" },
      "reaction":  { "en": "Stock −8.7% next session",
                     "zh": "次个交易日 −8.7%" },
      "tone":      "loss"
    }
  ]
}
```

Renders as a 3-column table with the tone driving row-level color
accents.

---

## Adding a new block kind

1. Decide the JSON shape and add it to this doc as a new section above.
2. Update the TypeScript type union in
   `backend/src/types/event-metadata.ts`.
3. Add a renderer in `Shion Quant Event Detail.html` inside the
   `renderSection(block)` dispatcher — defensive about missing fields.
4. (Optional) Add Zod validation in
   `backend/src/schemas/schedules.ts` once `metadata` is accepted via
   user input (currently it isn't — `POST /events` only writes generic
   fields, no `metadata`).

---

## Versioning

This is **v1**. Breaking changes to existing block shapes should bump
the version with a top-level `metadataVersion: 2` marker so old events
keep rendering. Adding new optional fields / new kinds is non-breaking
and doesn't need a version bump.

---

## Examples in the repo

The dev seed in [`backend/src/db/seed.ts`](../src/db/seed.ts) populates
`metadata.sections` for all 8 fixture events. Read those for realistic
shapes per event type:

| Event type           | Block kinds typically used                          |
|----------------------|-----------------------------------------------------|
| `advisor_call`       | prose, kvgrid (meeting facts), actions (agenda)     |
| `earnings`           | prose, table, kvgrid, reaction, actions             |
| `macro`              | prose, kvgrid (probabilities), actions (scenarios)  |
| `option_expiry`      | prose, table, actions (roll / close / expire)       |
| `bond_coupon`        | prose, kvgrid (coupon facts), actions               |
| `compliance_renewal` | prose, actions                                      |
| `report_delivery`    | prose, actions                                      |
| `personal`           | prose                                               |
