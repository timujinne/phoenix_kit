# Media module extraction — PhoenixKit Core ← host application

> Date: 2026-05-17
> Supersedes the narrower `media-gallery-component.md` (kept for history).

## Goal

Make the image gallery / picker / preview functionality — currently working in the
host application's Documents tab — a reusable part of the PhoenixKit Core **Media
module**, then wire the host app to consume it and delete its now-duplicated code.

Constraint: **no loss of functionality**. The host app's Documents tab must keep working
exactly as it does today (gallery under each template checkbox, "view" preview,
"×" remove, drag reorder, draft autosave/restore).

## Current state (verified 2026-05-17)

**PhoenixKit (`/www/phoenix_kit`) — uncommitted:**
- `lib/phoenix_kit_web/components/media_gallery.ex` + `.html.heex` — `MediaGallery`
  LiveComponent (gallery + embedded `MediaSelectorModal` picker + inline lightbox).
  Built from the host app's `TemplatePickerComponent` pattern; reviewed.
- `lib/modules/storage/storage.ex` — added `get_files/1` (batch).
- `lib/phoenix_kit_web/live/components/media_selector_modal.ex` — added `notify:` option.
- `test/phoenix_kit_web/components/media_gallery_test.exs` — 33 tests, passing.

**Already in PhoenixKit (committed, reusable):** `MediaBrowser`, `MediaSelectorModal`,
`UserMediaSelectorModal`, `MediaSelector` (legacy full-page), `<.image_set>`,
JS hooks `SortableGrid` / `ViewerKeydown` / `MediaDragDrop`.

**Host application (`<host-app>/`) — all committed:**
- `MyAppWeb.Documents.TemplatePickerComponent` — Documents-tab LiveComponent. Owns a
  bespoke image-slot gallery: thumbnail strip (`SortableGrid`), per-item eye/×
  buttons, an inline lightbox modal, "Choose images" button → `MediaSelectorModal`.
- Host-app-specific glue (stays): `MyApp.Orders.StorageFolders`,
  `MyApp.Orders.DocumentCreator`, `MyApp.Documents.SupportedMimes`, document_draft
  persistence, taxonomy/template/slot logic.
- `MyAppWeb.Documents.GenerateFormComponent` — older standalone page, uses the
  legacy `PhoenixKitDocumentCreator.Web.Components.ImagePicker`. **Out of scope.**

**Clarifications:**
- There is **no `ImagePicker` in the PhoenixKit media module**. `ImagePicker` exists
  only in the `phoenix_kit_document_creator` package (older generation, host-data
  driven, no upload). The PhoenixKit picker is `MediaSelectorModal`.
- The host app's inline lightbox is a subset of `MediaGallery`'s lightbox (no prev/next,
  no download, bare `<img>`). Migrating to `MediaGallery` is an upgrade, not a loss.

## Scope

PhoenixKit-side extraction **and** host-app-side internal rework: remove host-app code that
moved into PhoenixKit, wire the host app to consume the PhoenixKit Media module.

`GenerateFormComponent` / the legacy `ImagePicker` are **not** in scope.

---

## Part A — PhoenixKit Media module

### A1. Extract a standalone `MediaViewer` LiveComponent

The lightbox is currently inline in `media_gallery.html.heex` (lines ~95-183).
Extract it into its own reusable component so it can be used independently of the
gallery.

- Module: `PhoenixKitWeb.Components.MediaViewer` —
  `lib/phoenix_kit_web/components/media_viewer.ex` (+ `.html.heex`).
- LiveComponent, modal "slide box" — **images only** (per decision).
- Attrs: `id`, `files` (ordered list of file UUIDs or resolved file maps),
  `index` (currently shown), `show` (boolean). Optional `on_close` /
  notification tuple to tell the parent it closed / stepped.
- Features: prev/next chevrons + `←`/`→` (`ViewerKeydown` hook), `Esc` / backdrop
  close, Download link, large image via `<.image_set>`, filename in sidebar.
- `MediaGallery` is refactored to embed `<MediaViewer>` instead of its own inline
  lightbox markup — no behavior change for `MediaGallery` consumers.

### A2. Fix the `SortableGrid` payload inconsistency

`MediaGallery` reads `%{"ids" => ids}`; the host app's `TemplatePickerComponent` reads
`%{"ordered_ids" => ids}`. Pick one canonical key (recommend `"ids"`, matching the
hook's current emit per the JS audit) and make all PhoenixKit consumers use it.
Document the hook contract in the component moduledoc.

### A3. Commit the Media module work

Commit, as one coherent change: `MediaGallery`, `MediaViewer`, the `Storage.get_files/1`
addition, the `MediaSelectorModal` `notify:` option, and the tests. Update
`CHANGELOG.md` against the bumped `@version`.

### A4. Tests

- `MediaViewer` — new test file: renders for a given `files`/`index`, prev/next
  stepping with boundary clamps, keyboard events, close, download link.
- `MediaGallery` — existing 33 tests stay green after the `MediaViewer` refactor.

---

## Part B — Host application integration

### B1. Replace the bespoke gallery in `TemplatePickerComponent`

In `render_image_slots/1`, replace the bespoke thumbnail strip + inline lightbox +
"Choose images" button with `<.live_component module={PhoenixKitWeb.Components.MediaGallery} …>`
per image slot:
- `id` — stable per `template_uuid` + `slot.name`
- `title` — the humanized slot label (already computed in the host app)
- `selected` — the slot's ordered list of file UUIDs
- `mode` — `:single` for `image` slots, `:multiple` for `image_list`
- `scope_folder_id` — the order's storage folder UUID (from `StorageFolders`)
- `phoenix_kit_current_user` — the current admin

### B2. Delete the moved host-app code

Remove from `TemplatePickerComponent` (and the host LV `orders/edit.ex` where it
only existed to forward picker events): the inline lightbox markup + `preview_image`
/ `close_preview` handlers, the bespoke thumbnail-strip HEEX, the `remove_image`
handler, the `open_image_picker` handler + embedded `MediaSelectorModal`, and the
`{:media_selected,…}` / `reorder_images:*` forwarding plumbing — all now handled
inside `MediaGallery`.

### B3. Keep host-app-specific glue, wire it to `MediaGallery`

Stays in the host app, unchanged in purpose:
- `document_draft` autosave/restore — now driven by `MediaGallery`'s
  `{PhoenixKitWeb.Components.MediaGallery, id, {:changed, uuids}}` message: the
  component handles each `:changed` event, updates `image_values`, and persists the
  draft. Restore on init still seeds `selected` from `order.document_draft`.
- `StorageFolders` folder scoping, template/slot detection, taxonomy tabs,
  `DocumentCreator` composition, `SupportedMimes` whitelist.

### B4. Resolve the file-struct mismatch

`StorageFolders.image_files_for/2` returns simplified `%{uuid, name, url}` maps;
`MediaGallery` resolves UUIDs to `Storage.File` structs itself. The host app therefore only
needs to pass **UUID lists** to `MediaGallery` — drop the `image_files_for/2` call
from the picker render path (keep it if `DocumentCreator` still needs it elsewhere;
verify).

### B5. Verify in the live app

Documents tab: select a template, gallery appears per slot; pick images, reorder,
remove, preview (now with prev/next + download); compose a document; reload the
order — draft restores. Use `elixir-debugger` against the running app if needed.

---

## Out of scope

- `GenerateFormComponent` and the legacy `PhoenixKitDocumentCreator.ImagePicker`.
- The MediaBrowser heavy viewer (Fresco/Tessera/Etcher) — stays coupled; not extracted.
- Video / PDF support in `MediaViewer` — images only for now.
- `MediaSelector` legacy full-page LiveView — left as-is.

## Risks / notes

- The host app's Documents tab is freshly refined (draft persistence). B1–B3 must keep
  the draft autosave/restore observable behavior identical.
- `MediaGallery`'s `MediaSelectorModal` is mounted lazily (`show_picker`); confirm
  it works embedded inside `TemplatePickerComponent` (a LiveComponent inside a
  LiveComponent).
- Host-app changes ship as a separate commit/PR against the `phoenix_kit` dependency
  bump that includes Part A.
