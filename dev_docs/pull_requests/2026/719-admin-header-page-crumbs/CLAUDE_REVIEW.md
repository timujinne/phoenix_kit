# PR #719 — Admin header breadcrumb: page_crumbs, progressive collapse, and Core.ColumnSettings

- **Author:** Max Don (`mdon`)
- **Merged:** 2026-08-16 as `2c9194d3` (from `mdon:main`)
- **Reviewed:** 2026-08-16, post-merge, against `main`
- **Scope reviewed:** `page_crumbs` + progressive header collapse,
  `Core.ColumnSettings`, `table_row_menu_link` `patch` attr, UrlState
  extras-from-query-string fix.

Verdict: **the header trail and the UrlState leak fix are the right
shape; ColumnSettings shipped with a dead drag handle.** SortableGrid
never reads `data-sortable-items` — it hardcodes `.sortable-item` —
so the Shown list could not reorder. The breadcrumb half of the same
catalogue drill also only emitted `navigate`, remounting the LiveView
the row-menu `patch` attr was added to keep alive. Both are fixed
below.

---

## BUG - HIGH

### F1. ColumnSettings drag-to-reorder never fired

Shown rows used `class="col-item"` and `data-sortable-items=".col-item"`.
The SortableGrid hook in `phoenix_kit.js` ignores that attribute. It
sets `draggable: ".sortable-item"`, counts `.sortable-item[data-id]`,
and builds `ordered_ids` from the same selector. A `.col-item` list is
inert: no drag, empty payload if anything did fire.

The handle class was painted (`pk-drag-handle` on the bars icon) but
`data-sortable-handle` was not set, so even after the class fix the
whole row — including the remove button — would have been the drag
surface.

**Fixed.** Rows are `sortable-item`. The list declares
`data-sortable-items=".sortable-item"` and
`data-sortable-handle=".pk-drag-handle"`. Render tests pin the hook
contract and refuse `col-item`.

---

## BUG - MEDIUM

### F2. `page_crumbs` could only `navigate`, remounting the drill LiveView

The same PR added `patch` to `table_row_menu_link` because catalogue
detail drills via `push_patch`. The breadcrumb — the other half of
that trail — rendered every crumb as `<.link navigate={crumb[:path]}>`.
Clicking "Plumbing" would remount the LiveView the row menu had just
been taught not to remount.

**Fixed.** A crumb may carry `patch:` (same-LiveView) or `path:`
(`push_navigate`). `patch` wins when both are present. Header test
pins `data-phx-link="patch"`.

### F3. UrlState extras still seeded from the merged params map on mount

`handle_params/3` now reads extras from the URI query string (the
actual bug — `/:uuid` was re-encoded as `?uuid=`). `on_mount/4` still
called `extra_params(params, cfg)` on LiveView's merged path+query
map. Harmless in `:patch` (overwritten before first paint) but a
leak window in `:history` until the client hook reports.

The new helper was also untested: the codec suite never saw a URI
with a path segment.

**Fixed.** `on_mount` seeds extras as `%{}`. New public
`extras_from_uri/2` is what `handle_params` uses; tests pin
"uuid in the path is not an extra" vs "uuid in the query still is".

---

## IMPROVEMENT - MEDIUM

### F4. `column_settings_modal` was not in the html helper import list

Same hole as `tree_name_cell` on #718: every other list-UI primitive
is imported from `PhoenixKitWeb.core_components/0`. The first
catalogue caller would have compiled only after a manual import.

**Fixed.** `import PhoenixKitWeb.Components.Core.ColumnSettings` next
to `ReorderModal`. The export (`column_settings_modal/1`) is a unique
name.

### F5. Modal slots and LiveComponent `target` were unused

The title was an `<h3>` in the inner block, so the dialog's
`aria-labelledby` pointed at a missing `#…-title`. Reset/Close sat in
the scrollable body instead of `<:actions>`. The moduledoc told LC
callers to "add `phx-target` wiring yourself" but the component
accepted no `target` / `rest` attr, so that was impossible.

**Fixed.** `<:title>` / `<:actions>`, optional `target` forwarded to
every `phx-click` and `data-sortable-target`. `max_width="lg"` so the
two-column editor is not cramped in the default `md` box.

---

## IMPROVEMENT - LOW

### F6. `table_row_menu_link` docs still said "navigate or href"

The attr was added; the moduledoc and `@doc` list were not.

**Fixed.** Docs name `patch`.

---

## NITPICK (changed with the docs)

- **`page_crumbs` attr doc** said the extra crumbs collapse on mobile
  with the rest of the prefix. The last crumb is the point of the
  left-truncation and stays visible below `sm`. Doc updated; `patch`
  is named there too.

---

## What was checked and left alone

- **Progressive collapse CSS.** Site name + "Admin Panel" hide below
  `lg` in favour of a home-linked `…`; section + non-last crumbs hide
  below `sm`. Matches the claimed `… / parent / page` tail. Ellipsis
  `href="/"` is the same home link the project title already uses
  (not locale-aware; pre-existing).
- **`decode/2` still reads LiveView's merged params.** Correct for
  *declared* keys — a spec that wants a path segment as state can
  still see it. Only extras had to move to the query string.
- **`URI.decode_query/1`** is what history-mode already uses. On
  Elixir 1.18 it does not raise on `foo=%` / `foo=%ZZ`. Left as-is.
- **Modal `:if={@show}`** (no `keep_in_dom`). Right call for a
  SortableGrid that should remount on open; `keep_in_dom` would leave
  the hook sitting on a hidden list.
- **Crumb `path` / `patch` are not run through `Routes.local_path?/1`.**
  Same contract as `page_section_path`: the LiveView builds the URL,
  it is not user input. A consumer that interpolates raw params owns
  the guard.
- **UrlState `@spec decode(map() | :not_mounted_at_router, map())`.**
  Matches the fallback clause; the previous `map()`-only spec is what
  made dialyzer flag the extras fallback as dead.

---

## Gate

`mix format`, then `mix precommit` — compile (warnings as errors),
unused deps, format-check, credo --strict, dialyzer, JS tests.
Targeted tests: `column_settings`, `layout_wrapper_admin_header`,
`url_state`. All green.

Ships as **2.8.0**.
