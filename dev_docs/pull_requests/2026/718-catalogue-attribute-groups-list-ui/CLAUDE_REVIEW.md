# PR #718 — Catalogue attribute-group support (V173) and list-UI component additions

- **Author:** Max Don (`mdon`)
- **Merged:** 2026-08-15 as `e7fd0646` (from `mdon:main`)
- **Reviewed:** 2026-08-15, post-merge, against `main`
- **Scope reviewed:** V173 + ExpectedSchema, `Core.TreeTable`, FolderExplorer
  `class` attr, comfortable view mode, always-visible drag handles, multilang
  tab polish, media picker header/empty/search, UploadStats + MediaBrowser
  drain queue. Gettext churn and the 1,163-line manifest append were checked
  for shape, not line-by-line.

Verdict: **nothing big, and the design calls hold up.** V173 is prefix-safe
and matches the documented contract (RESTRICT definition tree, droppable
one-group-per-item unique, catalog-emitted manifest entries). The UI pieces
are small and well-cut. Findings below are follow-ups, not holes in the
feature.

---

## IMPROVEMENT - MEDIUM

### F1. `tree_name_cell` was not in the html helper import list

Every other list-UI primitive (`table_default`, `sortable_*`, bulk-select,
reorder modal, sort selector) is imported from `PhoenixKitWeb.core_components/0`.
`TreeTable` was added as the reusable file-explorer cell that composes into
those tables, then left as a manual `import`. The first catalogue caller
would have compiled only after discovering that.

**Fixed.** `import PhoenixKitWeb.Components.Core.TreeTable` next to
`TableDefault`. `tree_name_cell/1` is a unique name, so it does not trip
the generic-export hazard documented above `EmailStatusBadge`.

### F2. Uncontrolled tables first-painted compact, then jumped to comfy

The hook's default is `"comfy"` (`localStorage.getItem(key) || "comfy"`).
The markup for `view_mode == nil` was `hidden md:block` with no `pk-comfy`
marker. First paint was compact; `mounted` then added the marker. The
PR's own product call is that comfortable is the default when nothing is
stored — the HTML should match that, not flash the old density.

**Fixed.** The uncontrolled branch is now `hidden md:block pk-comfy`.
The hook still toggles the class off when the stored preference is
`"table"` or `"card"`. Tests pin the three `data-view-action`s and the
marker on both the uncontrolled default and controlled `comfy`.

---

## IMPROVEMENT - LOW

### F3. Long tree names could blow the flex cell

`tree_name_cell` puts the chevron, optional icon, and the name in a
`flex … min-w-0` row, but the slot itself was an unwrapped text node.
Flex items default to `min-width: auto`, so a long name refuses to
shrink and overflows the cell. The component's job is "file-explorer
name cell"; truncation belongs here, not in every caller.

**Fixed.** The slot is wrapped in `<span class="min-w-0 truncate">`.
Render test added. Custom `icon_class` is now asserted too — the
moduledoc already claimed it.

### F4. Media-selector search form had no `id`

`<.form for={%{}} phx-submit="search">` supplies no id of its own.
This form is submit-only (not `phx-change`), so it is outside the
strict `missing_form_id` warning, but the same file was already being
edited and LiveComponent forms are supposed to derive from `@id`.

**Fixed.** `id={"media-selector-search-#{@id}"}`.

---

## NITPICK (not changed)

- **Activity / Users keep a private card|table dropdown.** They pass
  `view_mode` + `show_toggle={false}` and persist only `"card"` /
  `"table"`. They do not pick up the new comfortable default. That is
  consistent with opting out of the built-in toggle; promoting comfy
  there is a product change, not a merge bug.
- **Toggle `title`s stay untranslated** (`Card view` / `Comfortable view`
  / `Compact view`). Same as before the PR; extracting them would churn
  every locale for three tooltips.
- **`table_default` moduledoc still talked about a two-way card/table
  toggle.** Updated to name `comfy`.

---

## What was checked and left alone

- **V173.** Bare index names on CREATE, `Helpers.uuid_v7_call/1`,
  schema-qualified table/FK targets, `COMMENT ON TABLE` version stamp,
  rollback is plain `DROP TABLE` in dependency order (no CASCADE). The
  `UNIQUE (item_uuid)` vs future `(item_uuid, attribute_group_uuid)`
  split is documented in the migration. Manifest objects are
  owner-tagged `:catalogue` and use the name-based `pg_constraint` JOIN
  (no `'table'::regclass` in IMMEDIATE checks).
- **Upload drain queue.** Two-phase `send_update_after` is correct:
  cycle 1 paints `:upload_processing`, cycle 2 stores inside `update/2`
  so the previous render's spinner stays on screen for the duration,
  then clears the assign so the post-store render does not leave a
  ghost row. `commit_upload_batch/1` defers while the queue is live.
- **`phx-dblclick` → `quick_confirm`.** The two `toggle_selection`
  clicks of a double-click are overwritten by an explicit
  `selected_uuids = [file_uuid]` before confirm. Single-mode only.
- **ExpectedSchema `chain_hash`.** Restamped with the V173 file;
  body is the catalog snapshot, not a hand transcription.

---

## Gate

`mix format`, then `mix precommit` — compile (warnings as errors), unused
deps, format-check, credo --strict, dialyzer, JS tests including the new
`upload_stats` suite. Targeted component tests for `tree_table` and
`table_default` comfy added alongside the fixes. All green.

Ships as **2.7.0**.
