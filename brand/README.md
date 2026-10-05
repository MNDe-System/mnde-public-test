# MNDe Brand Kit

The canonical MNDe logo and usage rules. Use these assets for **all marketing and logo needs**.

## The mark

The mark is a schematic of what MNDe does: **inputs (requests, actions, commands, agents) converge into the authority node — it evaluates, decides, enforces — and only allowed execution flows out (blue arrow).**

- **Input traces** (left): four circuit traces with square terminals — the things trying to execute.
- **Authority node** (center): hexagon outline with a navy core — the decision point.
- **Output arrow** (right, blue): allowed execution. The only thing that leaves the node.

It reads as a circuit / infrastructure element, not a SaaS glyph — consistent with MNDe being local execution infrastructure. **No tagline is part of the logo.**

## Assets

| File | Use |
| --- | --- |
| `mnde-mark.svg` | Primary icon — mark on the dark plate. App icon, social avatar, favicon source. |
| `mnde-mark-mono.svg` | Mark only, transparent. `currentColor` adapts to any surface; node core stays navy, arrow stays blue. |
| `mnde-wordmark.svg` | Horizontal lockup (mark + "MNDe", no tagline). Headers, README, decks, site nav. |
| `favicon.svg` | Simplified mark for ≤32px (node + arrow only; traces dropped for legibility). |

All assets are SVG (vector) — infinitely scalable, themeable, and tiny. They are the source of truth; rasterize from these for any PNG/ICO need (e.g. `mnde-mark.svg` → 1024/512/256/128/64 PNG, then `.ico`).

## Palette

| Token | Hex | Use |
| --- | --- | --- |
| MNDe Blue | `#2563EB` | The output arrow — allowed execution. The action color. |
| Node Navy | `#1E3A8A` | The authority-node core. Never used for lines or text. |
| Ink White | `#FFFFFF` | Traces, node outline, wordmark on dark. |
| Plate | `#0E1318` | Logo background plate / dark surfaces. |
| Accent on dark | `#4C9AFF` | Small blue UI text/labels on dark surfaces (readability); not part of the mark itself. |

Over light backgrounds set `color:#0E1318` on the mono/wordmark (traces + outline follow `currentColor`).

## Clearspace & sizing

- Clearspace ≥ the height of the hexagon on all sides.
- Minimum legible size: wordmark ≥ 120px wide; mark ≥ 24px; below that use `favicon.svg`.
- Do not place the mono mark on a light background without setting `color` to ink.

## Do / Don't

**Do** — keep blue strictly on the output arrow (execution that was allowed); keep the navy core inside the node only; preserve direction (inputs left, output right); use on `#0E1318` or comparably dark surfaces, or the mono mark with correct `color`.

**Don't** — recolor the node outline or traces; put blue on the input side; add a tagline to the lockup; add gradients/shadows/glows; rotate or reflect the mark (direction is meaningful); stretch non-uniformly; reintroduce SaaS styling.

## In product

The Authority Console ([../desktop/dashboard.html](../desktop/dashboard.html)) uses the mono mark in its header and a data-URI favicon derived from `favicon.svg`. The README uses the wordmark.
