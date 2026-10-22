# MediaGallery component

## Goal

A general PhoenixKit LiveComponent for selecting, ordering, previewing and removing
a set of images. Generalizes a host application's project-specific
`MyAppWeb.Documents.TemplatePickerComponent` (`render_image_slots/1`,
`<host-app>/lib/my_app_web/documents/template_picker_component.ex:449-527`) so any
PhoenixKit consumer can embed it instead of re-implementing the gallery + picker
plumbing.

It replaces, in consumers, the bespoke "Choose images" button + selected-images
list. It does **not** know about document templates, slots, or persistence — it
only manages an ordered list of file UUIDs and reports changes to the parent.

## Module / files

- `PhoenixKitWeb.Components.MediaGallery` — LiveComponent
- `lib/phoenix_kit_web/components/media_gallery.ex`
- `lib/phoenix_kit_web/components/media_gallery.html.heex`

## Attributes

| Attr | Type | Notes |
|---|---|---|
| `id` | string | required |
| `title` | string | heading above the gallery; optional (replaces the hardcoded humanized slot name) |
| `selected` | list | ordered list of file UUIDs (current selection) |
| `mode` | atom | `:single` \| `:multiple` (default `:multiple`) |
| `scope_folder_id` | string | folder scope passed to the picker / upload |
| `phoenix_kit_current_user` | struct | required for upload in the picker |
| `readonly` | boolean | default `false`; hides the button, `×`, and DnD — preview still works |

## Behavior

- **Resolve files:** on `update/2`, resolve `selected` UUIDs to file structs via
  `PhoenixKit.Modules.Storage` (`get_file/1` + `list_image_set_variants_for_files/1`
  for variant data, to avoid N+1). Order follows `selected`.
- **Picker button:** "Choose images" opens an embedded `MediaSelectorModal`
  (`mode`, `scope_folder_id`, `file_type_filter: :image`,
  `selected_uuids` = current selection, `phoenix_kit_current_user`).
- **Self-contained delivery:** extend `MediaSelectorModal` with an optional
  `notify: {module, id}` attr. When set, `confirm_selection` delivers the result
  via `send_update(module, id: id, media_selected: uuids)` instead of
  `send(self(), {:media_selected, uuids})`. Default behavior unchanged. This lets
  `MediaGallery` receive the picker result without any host-LiveView plumbing.
- **Thumbnail strip:** `SortableGrid` hook with `phx-target={@myself}` and
  `data-sortable-event`. Each item has `class="sortable-item"`, `data-id={uuid}`;
  the `×` and eye buttons carry `sortable-ignore`. Thumbnails render via
  `<.image_set>` (`PhoenixKit.Modules.Shared.Components.ImageSet`) — responsive
  `<picture>`, not a raw `<img>`.
- **Reorder:** `SortableGrid` fires the sortable event to `@myself`;
  the component reorders its `selected` list.
- **Remove:** `×` drops the UUID from the selection only — the file in the media
  library is untouched.
- **Lightbox:** MediaBrowser-style "slide box" — a daisyUI modal showing the large
  image via `<.image_set>`, with prev/next buttons + `←`/`→` keys, `Esc` to close,
  and a Download link. Server-side `preview_uuid` state.
- **Change reporting:** after any change (pick / remove / reorder), the component
  emits `{PhoenixKitWeb.Components.MediaGallery, id, {:changed, ordered_uuids}}`
  to the parent LiveView via `send/2`. The parent persists / uses the list.

## Out of scope (YAGNI)

- No persistence, no document template / slot awareness.
- No bespoke upload UI — uploads go through `MediaSelectorModal`.
- Not migrating the host app's `TemplatePickerComponent` or document_creator's old
  `ImagePicker` to use it — that is follow-up work for the consumers.

## Tests

`test/phoenix_kit_web/components/media_gallery_test.exs` (new dir) —
`Phoenix.LiveViewTest` coverage: renders title + thumbnails for `selected`;
`readonly` hides button/`×`/DnD; remove drops a UUID and emits `:changed`;
reorder updates order; lightbox opens/steps/closes.
