# Media Module Extraction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the image gallery/preview functionality into the PhoenixKit Core Media module as reusable components, then wire the host application to consume them and delete its duplicated code.

**Architecture:** Part A works in `/www/phoenix_kit` — extract a standalone `MediaViewer` lightbox LiveComponent from `MediaGallery`, then commit. Part B works in `<host-app>/` (the host application checkout) — replace the bespoke gallery in `TemplatePickerComponent` with `<MediaGallery>` and delete the moved code. The host app depends on phoenix_kit via `path: "../phoenix_kit"` (verified `mix.exs:66`), so Part A changes are available to the host app immediately — no hex publish needed.

**Tech Stack:** Elixir, Phoenix LiveView (LiveComponents), daisyUI 5, `ExUnit` + `Phoenix.LiveViewTest`.

**Spec:** `dev_docs/plans/2026-05-17-media-module-extraction.md`

---

## File Structure

**Part A — `/www/phoenix_kit`:**
- Create: `lib/phoenix_kit_web/components/media_viewer.ex` — standalone lightbox LiveComponent
- Create: `lib/phoenix_kit_web/components/media_viewer.html.heex` — its template
- Create: `test/phoenix_kit_web/components/media_viewer_test.exs` — tests
- Modify: `lib/phoenix_kit_web/components/media_gallery.ex` — delegate lightbox to `MediaViewer`
- Modify: `lib/phoenix_kit_web/components/media_gallery.html.heex` — replace inline lightbox markup
- Modify: `CHANGELOG.md`, `mix.exs` — version bump + entry

**Part B — `<host-app>/` (the host application checkout):**
- Modify: `lib/my_app_web/documents/template_picker_component.ex` — embed `<MediaGallery>`, delete bespoke gallery
- Modify: `lib/my_app_web/live/admin/orders/edit.ex` — delete picker-event forwarding plumbing

---

## PART A — PhoenixKit Media module

### Task 1: Create the `MediaViewer` LiveComponent

`MediaViewer` is a standalone, image-only lightbox modal. It owns its current-image
state and prev/next navigation, resolves what it needs from Storage, and notifies a
parent when it closes. Logic moves out of `MediaGallery` (`media_gallery.ex` handlers
`close_preview`/`viewer_keydown`/`step_preview`, helpers `step_preview/2`,
`download_url_for/2`, `file_name_for/2`, and the inline lightbox HEEX
`media_gallery.html.heex:94-182`).

**Files:**
- Create: `lib/phoenix_kit_web/components/media_viewer.ex`
- Create: `lib/phoenix_kit_web/components/media_viewer.html.heex`
- Test: `test/phoenix_kit_web/components/media_viewer_test.exs`

**Component contract:**

Attrs (via `update/2`):
- `id` — required
- `files` — ordered list of file UUIDs (the navigable set)
- `current` — UUID currently shown; must be a member of `files`
- `variants_map` — optional `%{uuid => [variant_map]}`; resolved internally if absent
- `file_structs` — optional `[%Storage.File{}]`; resolved internally if absent
- `notify` — optional `{module, id}`; on close `send_update(module, id: id, media_viewer_closed: true)`, else `send(self(), {PhoenixKitWeb.Components.MediaViewer, id, :closed})`

Internal assigns: `current_uuid`, `files`, `variants_map`, `file_structs`, `notify`.

Events (all `phx-target={@myself}`): `close_viewer`, `step_viewer` (`%{"dir" => "prev"|"next"}`), `viewer_keydown` (`%{"key" => "Escape"|"ArrowLeft"|"ArrowRight"}`).

- [ ] **Step 1: Write the failing test file**

```elixir
defmodule PhoenixKitWeb.Components.MediaViewerTest do
  @moduledoc """
  Unit tests for PhoenixKitWeb.Components.MediaViewer.
  Render tests use pre-built assigns and `rendered_to_string/1`; event tests
  invoke `handle_event/3` against a minimal socket. No DB required.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]

  alias PhoenixKitWeb.Components.MediaViewer

  @u1 "01900000-0000-7000-8000-000000000001"
  @u2 "01900000-0000-7000-8000-000000000002"
  @u3 "01900000-0000-7000-8000-000000000003"

  defp viewer_assigns(opts) do
    files = Keyword.get(opts, :files, [@u1, @u2, @u3])
    current = Keyword.get(opts, :current, @u1)

    %{
      id: "test-viewer",
      current_uuid: current,
      files: files,
      variants_map: Keyword.get(opts, :variants_map, Map.new(files, &{&1, []})),
      file_structs: Keyword.get(opts, :file_structs, []),
      notify: Keyword.get(opts, :notify, nil),
      myself: %Phoenix.LiveComponent.CID{cid: 1}
    }
  end

  defp render(assigns), do: rendered_to_string(MediaViewer.render(assigns))

  defp call(event, params, assigns) do
    socket = %Phoenix.LiveView.Socket{assigns: Map.put(assigns, :__changed__, %{})}
    MediaViewer.handle_event(event, params, socket)
  end

  describe "render" do
    test "renders the modal with the current image" do
      html = render(viewer_assigns(current: @u1))
      assert html =~ "modal modal-open"
      assert html =~ "test-viewer"
    end

    test "shows next chevron but not prev on the first image" do
      html = render(viewer_assigns(current: @u1))
      assert html =~ ~s(phx-value-dir="next")
      refute html =~ ~s(phx-value-dir="prev")
    end

    test "shows prev chevron but not next on the last image" do
      html = render(viewer_assigns(current: @u3))
      assert html =~ ~s(phx-value-dir="prev")
      refute html =~ ~s(phx-value-dir="next")
    end
  end

  describe "stepping" do
    test "step_viewer next advances current_uuid" do
      {:noreply, socket} = call("step_viewer", %{"dir" => "next"}, viewer_assigns(current: @u1))
      assert socket.assigns.current_uuid == @u2
    end

    test "step_viewer prev goes back" do
      {:noreply, socket} = call("step_viewer", %{"dir" => "prev"}, viewer_assigns(current: @u2))
      assert socket.assigns.current_uuid == @u1
    end

    test "step_viewer next at the last image is a no-op" do
      {:noreply, socket} = call("step_viewer", %{"dir" => "next"}, viewer_assigns(current: @u3))
      assert socket.assigns.current_uuid == @u3
    end

    test "ArrowRight steps forward, ArrowLeft steps back" do
      {:noreply, s1} = call("viewer_keydown", %{"key" => "ArrowRight"}, viewer_assigns(current: @u1))
      assert s1.assigns.current_uuid == @u2
      {:noreply, s2} = call("viewer_keydown", %{"key" => "ArrowLeft"}, viewer_assigns(current: @u2))
      assert s2.assigns.current_uuid == @u1
    end
  end
end
```

- [ ] **Step 2: Run the test, verify it fails**

Run: `cd /www/phoenix_kit && mix test test/phoenix_kit_web/components/media_viewer_test.exs`
Expected: FAIL — `MediaViewer` is undefined.

- [ ] **Step 3: Create `media_viewer.ex`**

Implement the module. Move the logic from `media_gallery.ex`: the `step_preview/2`
helper becomes `step_viewer/2`, plus `download_url_for/2` and `file_name_for/2`
copied verbatim. `update/2` resolves `variants_map` (via
`Storage.list_image_set_variants_for_files/1`) and `file_structs` (via
`Storage.get_files/1`) only when not supplied, wrapped in the same
`rescue DBConnection.ConnectionError, Ecto.Query.CastError` guard `MediaGallery`
uses (`media_gallery.ex:170-174`). `close` resolves the `notify` tuple as specified
in the contract. Keep `current_uuid` as the navigation state.

```elixir
defmodule PhoenixKitWeb.Components.MediaViewer do
  @moduledoc """
  Standalone image lightbox ("slide box") LiveComponent.

  Renders a modal showing one image from an ordered set, with prev/next
  navigation (chevrons + ←/→ keys), Escape/backdrop close, and a Download link.
  Images render via `<.image_set>` (responsive `<picture>`).

  Reusable on its own or embedded by `MediaGallery`.

  ## Attrs
  - `id` — required
  - `files` — ordered list of file UUIDs (the navigable set)
  - `current` — UUID currently shown (must be in `files`)
  - `variants_map` — optional `%{uuid => variants}`; resolved internally if absent
  - `file_structs` — optional `[%Storage.File{}]`; resolved internally if absent
  - `notify` — optional `{module, id}`; see Close below

  ## Close
  On close, if `notify: {module, id}` is set:
  `send_update(module, id: id, media_viewer_closed: true)`.
  Otherwise: `send(self(), {__MODULE__, id, :closed})`.
  """
  use PhoenixKitWeb, :live_component

  require Logger

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.URLSigner

  import PhoenixKit.Modules.Shared.Components.ImageSet

  @impl true
  def update(assigns, socket) do
    socket =
      socket
      |> assign(:id, assigns.id)
      |> assign(:files, assigns[:files] || [])
      |> assign(:current_uuid, assigns[:current])
      |> assign(:notify, assigns[:notify])
      |> assign_new(:variants_map, fn -> assigns[:variants_map] end)
      |> assign_new(:file_structs, fn -> assigns[:file_structs] end)
      |> resolve_data()

    {:ok, socket}
  end

  @impl true
  def handle_event("close_viewer", _params, socket) do
    close(socket)
    {:noreply, socket}
  end

  def handle_event("step_viewer", %{"dir" => "prev"}, socket),
    do: {:noreply, step_viewer(socket, :prev)}

  def handle_event("step_viewer", %{"dir" => "next"}, socket),
    do: {:noreply, step_viewer(socket, :next)}

  def handle_event("viewer_keydown", %{"key" => "Escape"}, socket) do
    close(socket)
    {:noreply, socket}
  end

  def handle_event("viewer_keydown", %{"key" => "ArrowLeft"}, socket),
    do: {:noreply, step_viewer(socket, :prev)}

  def handle_event("viewer_keydown", %{"key" => "ArrowRight"}, socket),
    do: {:noreply, step_viewer(socket, :next)}

  def handle_event("viewer_keydown", _params, socket), do: {:noreply, socket}

  # ── private ──────────────────────────────────────────────────────────

  defp resolve_data(socket) do
    files = socket.assigns.files

    variants_map =
      socket.assigns.variants_map ||
        safe(fn -> Storage.list_image_set_variants_for_files(files) end, %{})

    file_structs =
      socket.assigns.file_structs ||
        safe(fn -> Storage.get_files(files) end, [])

    assign(socket, variants_map: variants_map, file_structs: file_structs)
  end

  defp safe(fun, fallback) do
    fun.()
  rescue
    e in [DBConnection.ConnectionError, Ecto.Query.CastError] ->
      Logger.warning("MediaViewer: could not load data — #{Exception.message(e)}")
      fallback
  end

  defp close(socket) do
    case socket.assigns.notify do
      {module, id} -> send_update(module, id: id, media_viewer_closed: true)
      _ -> send(self(), {__MODULE__, socket.assigns.id, :closed})
    end
  end

  defp step_viewer(socket, direction) do
    current = socket.assigns.current_uuid
    list = socket.assigns.files

    with idx when is_integer(idx) <- Enum.find_index(list, &(&1 == current)),
         next_idx <- if(direction == :prev, do: idx - 1, else: idx + 1),
         true <- next_idx >= 0 and next_idx < length(list),
         uuid when is_binary(uuid) <- Enum.at(list, next_idx) do
      assign(socket, :current_uuid, uuid)
    else
      _ -> socket
    end
  end

  defp download_url_for(uuid, variants) do
    case Enum.find(variants, &(&1.variant_name == "original")) do
      %{url: url} ->
        url

      _ ->
        try do
          URLSigner.signed_url(uuid, "original", locale: :none)
        rescue
          e in [ArgumentError, FunctionClauseError, KeyError] ->
            Logger.warning(
              "MediaViewer: could not sign download URL for #{uuid} — #{Exception.message(e)}"
            )

            nil
        end
    end
  end

  defp file_name_for(files, uuid) do
    case Enum.find(files, &(&1.uuid == uuid)) do
      %{original_file_name: name} when is_binary(name) -> name
      %{file_name: name} when is_binary(name) -> name
      _ -> uuid
    end
  end
end
```

- [ ] **Step 4: Create `media_viewer.html.heex`**

Move the lightbox markup from `media_gallery.html.heex:102-181`. Substitutions:
`@preview_uuid` → `@current_uuid`; `@selected` → `@files`; `@files` (struct list) →
`@file_structs`; `close_preview` → `close_viewer`; `step_preview` → `step_viewer`;
element id `"#{@id}-lightbox"` → `"#{@id}"`. The `<.image_set>`, `ViewerKeydown`
hook, prev/next chevrons, sidebar, download link, and backdrop stay identical in
structure. Compute `preview_variants`, `preview_idx`, `has_prev`, `has_next`,
`download_url`, `file_name` from the new assign names at the top of the template.

- [ ] **Step 5: Run the tests, verify they pass**

Run: `cd /www/phoenix_kit && mix test test/phoenix_kit_web/components/media_viewer_test.exs`
Expected: PASS — all tests green.

- [ ] **Step 6: Format + quality**

Run: `cd /www/phoenix_kit && mix format && mix credo --strict lib/phoenix_kit_web/components/media_viewer.ex`
Expected: no issues.

- [ ] **Step 7: Commit**

```bash
cd /www/phoenix_kit
git add lib/phoenix_kit_web/components/media_viewer.ex lib/phoenix_kit_web/components/media_viewer.html.heex test/phoenix_kit_web/components/media_viewer_test.exs
git commit -m "Add MediaViewer standalone image lightbox LiveComponent"
```

---

### Task 2: Refactor `MediaGallery` to delegate the lightbox to `MediaViewer`

**Files:**
- Modify: `lib/phoenix_kit_web/components/media_gallery.ex`
- Modify: `lib/phoenix_kit_web/components/media_gallery.html.heex`
- Test: `test/phoenix_kit_web/components/media_gallery_test.exs` (existing — must stay green)

- [ ] **Step 1: Update `media_gallery.ex`**

- Delete handlers `close_preview`, the three `viewer_keydown` clauses, and the two
  `step_preview` clauses (`media_gallery.ex:107-133`).
- Delete private helpers `step_preview/2`, `download_url_for/2`, `file_name_for/2`
  (`media_gallery.ex:192-234`) — they now live in `MediaViewer`.
- Keep the `preview_image` handler (sets `:preview_uuid`).
- Add a `update/2` head clause to clear the preview when `MediaViewer` reports close:

```elixir
def update(%{media_viewer_closed: true}, socket) do
  {:ok, assign(socket, :preview_uuid, nil)}
end
```

- [ ] **Step 2: Update `media_gallery.html.heex`**

Replace the inline lightbox block (`media_gallery.html.heex:94-182`) with a
conditional `MediaViewer` mount inside the existing single root `<div>`:

```heex
  <.live_component
    :if={@preview_uuid}
    module={PhoenixKitWeb.Components.MediaViewer}
    id={"#{@id}-viewer"}
    files={@selected}
    current={@preview_uuid}
    variants_map={@variants_map}
    file_structs={@files}
    notify={{__MODULE__, @id}}
  />
```

- [ ] **Step 3: Run the existing MediaGallery tests**

Run: `cd /www/phoenix_kit && mix test test/phoenix_kit_web/components/media_gallery_test.exs`
Expected: the lightbox-internal tests that asserted on now-removed inline markup
will fail. Update those tests to assert the `MediaViewer` live_component is mounted
when `preview_uuid` is set (e.g. assert the rendered output contains
`"test-gallery-viewer"`) instead of asserting chevron/download markup directly —
that markup is now `MediaViewer`'s responsibility and covered by its own tests.
Keep all non-lightbox tests unchanged.

- [ ] **Step 4: Run the full media test suite**

Run: `cd /www/phoenix_kit && mix test test/phoenix_kit_web/components/`
Expected: PASS.

- [ ] **Step 5: Format + quality**

Run: `cd /www/phoenix_kit && mix format && mix quality`
Expected: no issues.

- [ ] **Step 6: Commit**

```bash
cd /www/phoenix_kit
git add lib/phoenix_kit_web/components/media_gallery.ex lib/phoenix_kit_web/components/media_gallery.html.heex test/phoenix_kit_web/components/media_gallery_test.exs
git commit -m "Refactor MediaGallery to use MediaViewer for the lightbox"
```

---

### Task 3: Commit the remaining Media module work + CHANGELOG

The `Storage.get_files/1` addition and the `MediaSelectorModal` `notify:` option are
still uncommitted (`git status` shows `M lib/modules/storage/storage.ex`,
`M .../media_selector_modal.ex`), along with the `MediaGallery` files from earlier
work and `dev_docs/plans/media-gallery-component.md` / the two specs.

**Files:**
- Modify: `mix.exs` (`@version` bump), `CHANGELOG.md`

- [ ] **Step 1: Bump version**

Get current version: `cd /www/phoenix_kit && mix run --eval "IO.puts Mix.Project.config[:version]"`.
Bump the patch (or minor) `@version` in `mix.exs`.

- [ ] **Step 2: Add CHANGELOG entry**

Under the bumped `@version` heading, match the existing Added/Changed style:

```markdown
### Added
- `PhoenixKitWeb.Components.MediaGallery` — reusable LiveComponent for selecting,
  ordering, previewing and removing a set of images.
- `PhoenixKitWeb.Components.MediaViewer` — standalone image lightbox LiveComponent
  (prev/next, keyboard, download).
- `Storage.get_files/1` — batch file fetch preserving input order.

### Changed
- `MediaSelectorModal` accepts an optional `notify: {module, id}` to deliver the
  selection via `send_update` instead of a process message.
```

- [ ] **Step 3: Run the full suite + quality**

Run: `cd /www/phoenix_kit && mix format && mix quality && mix test`
Expected: PASS (integration tests auto-excluded if no PostgreSQL).

- [ ] **Step 4: Commit**

```bash
cd /www/phoenix_kit
git add lib/modules/storage/storage.ex lib/phoenix_kit_web/live/components/media_selector_modal.ex lib/phoenix_kit_web/components/media_gallery.ex lib/phoenix_kit_web/components/media_gallery.html.heex test/phoenix_kit_web/components/media_gallery_test.exs mix.exs CHANGELOG.md dev_docs/plans/media-gallery-component.md dev_docs/plans/2026-05-17-media-module-extraction.md dev_docs/plans/2026-05-17-media-module-extraction-plan.md
git commit -m "Add MediaGallery + MediaViewer media components; Storage.get_files/1"
```

(Delete the throwaway `dev_docs/plans/_research-*.md` files before committing —
they are scratch notes, not part of the repo.)

---

## PART B — Host application integration (`<host-app>/`)

> Prerequisite: Part A complete on disk. The host app uses `phoenix_kit` via
> `path: "../phoenix_kit"`, so the new components are immediately available.

### Task 4: Embed `<MediaGallery>` in `TemplatePickerComponent` image slots

Replace the bespoke per-slot gallery in `render_image_slots/1`
(`lib/my_app_web/documents/template_picker_component.ex:457-534`) with one
`<MediaGallery>` per image slot.

**Files:**
- Modify: `lib/my_app_web/documents/template_picker_component.ex`

- [ ] **Step 1: Read the current component**

Read `template_picker_component.ex` in full — focus on `render_image_slots/1`
(457-534), the inline lightbox (426-449), and event handlers `open_image_picker`
(~234-247), `remove_image` (~257-267), `preview_image`/`close_preview`,
`reorder_images:*` (~269-282), and the `image_values` assign
(`%{template_uuid => %{slot_name => [file_uuid]}}`).

- [ ] **Step 2: Replace the per-slot markup**

In `render_image_slots/1`, for each slot render:

```heex
<.live_component
  module={PhoenixKitWeb.Components.MediaGallery}
  id={"img-gallery-#{@tmpl.uuid}-#{slot.name}"}
  title={Variable.humanize(slot.name)}
  selected={slot_uuids(@image_values, @tmpl.uuid, slot.name)}
  mode={if slot.kind == "image", do: :single, else: :multiple}
  scope_folder_id={@scope_folder_uuid}
  phoenix_kit_current_user={@current_user}
/>
```

Add a private helper `slot_uuids/3` that reads the ordered UUID list out of
`image_values`. Delete the bespoke thumbnail strip, the "Choose images" button, the
embedded `MediaSelectorModal`, and the inline lightbox markup (426-449).

- [ ] **Step 3: Verify it compiles**

Run: `cd <host-app> && mix compile --warnings-as-errors`
Expected: success (handlers from Task 5 not yet removed — may warn about unused;
acceptable until Task 5).

(No commit yet — Tasks 4–6 land as one host-app commit in Task 7.)

---

### Task 5: Delete the moved host-app code

**Files:**
- Modify: `lib/my_app_web/documents/template_picker_component.ex`
- Modify: `lib/my_app_web/live/admin/orders/edit.ex`

- [ ] **Step 1: Remove dead handlers in `template_picker_component.ex`**

Delete: `open_image_picker`, `remove_image`, `preview_image`, `close_preview`, the
`reorder_images:*` handler, the `__media_selected__` / `__media_selector_closed__` /
`__reorder_images__` `update/2` clauses, the `:preview_uuid` assign, and any
`MediaSelectorHelper`/`StorageFolders.image_files_for` calls used only by the old
picker render path. Keep `:scope_folder_uuid` resolution and the `__slots_loaded__`
flow (template-slot detection is unrelated).

- [ ] **Step 2: Remove forwarding plumbing in `orders/edit.ex`**

Delete the `{:media_selected, uuids}`, `{:media_selector_closed}`, and
`"reorder_images:" <> ...` handlers (`orders/edit.ex` ~600-684) that existed only to
`send_update` picker events into `TemplatePickerComponent`. Keep the
`{:template_slots_result, ...}` handler (unrelated background slot load). Keep the
`MediaBrowser` Step-5 wiring untouched.

- [ ] **Step 3: Verify it compiles clean**

Run: `cd <host-app> && mix compile --warnings-as-errors`
Expected: success, no unused-function warnings.

---

### Task 6: Wire `MediaGallery`'s `{:changed, uuids}` into `image_values` + draft

`MediaGallery` reports every pick/remove/reorder via
`{PhoenixKitWeb.Components.MediaGallery, gallery_id, {:changed, uuids}}` sent to the
host LiveView process. The Documents-tab draft autosave/restore behavior
(`order.document_draft`, commits `b1250e9`/`ed900fd`/`6c0aae5`) must keep working.

**Files:**
- Modify: `lib/my_app_web/live/admin/orders/edit.ex`
- Modify: `lib/my_app_web/documents/template_picker_component.ex`

- [ ] **Step 1: Handle `:changed` in the host LiveView**

In `orders/edit.ex`, add:

```elixir
def handle_info({PhoenixKitWeb.Components.MediaGallery, gallery_id, {:changed, uuids}}, socket) do
  {t_uuid, slot_name} = parse_gallery_id(gallery_id)
  send_update(MyAppWeb.Documents.TemplatePickerComponent,
    id: "template-picker-#{socket.assigns.order.uuid}",
    __image_slot_changed__: {t_uuid, slot_name, uuids}
  )
  {:noreply, socket}
end
```

Add `parse_gallery_id/1` to recover `{template_uuid, slot_name}` from the
`"img-gallery-<t>-<slot>"` id used in Task 4 Step 2.

- [ ] **Step 2: Apply the change in `TemplatePickerComponent`**

Add an `update/2` clause for `__image_slot_changed__: {t_uuid, slot, uuids}` that
writes `uuids` into `image_values` at `[t_uuid][slot]` and then runs the SAME draft
autosave path the old `remove_image`/`reorder` handlers used (reuse the existing
`save_document_draft`/`MyApp.Orders.save_document_draft/2` call). Restore-on-init
already seeds `image_values` from `order.document_draft` — leave it.

- [ ] **Step 3: Verify it compiles**

Run: `cd <host-app> && mix compile --warnings-as-errors`
Expected: success.

- [ ] **Step 4: Run the host app's documents tests**

Run: `cd <host-app> && mix test test/my_app_web/documents/ test/my_app/orders/`
Expected: PASS. Fix any test that referenced the deleted handlers — update it to
drive the new `__image_slot_changed__` path.

---

### Task 7: Verify in the live app + commit the host app

- [ ] **Step 1: Live verification (elixir-debugger)**

Use the `elixir-debugger` agent against the running host app. Open an order →
Documents tab → select a template. Confirm per-slot: gallery appears, "Choose
images" opens the scoped `MediaSelectorModal`, picking adds thumbnails, drag
reorders, "×" removes, the eye opens the `MediaViewer` lightbox with prev/next +
download. Compose a document. Reload the order — the draft restores all slot
selections.

- [ ] **Step 2: Format + quality**

Run: `cd <host-app> && mix format && mix credo --strict`
Expected: no issues.

- [ ] **Step 3: Commit the host app**

```bash
cd <host-app>
git add lib/my_app_web/documents/template_picker_component.ex lib/my_app_web/live/admin/orders/edit.ex
git commit -m "Use PhoenixKit MediaGallery for documents-tab image slots"
```

---

## Notes

- The `SortableGrid` payload inconsistency (`ordered_ids` vs `ids`) resolves
  automatically: the host app's bespoke `reorder_images:*` handler is deleted in Task 5;
  reordering now flows through `MediaGallery`'s `"ids"` handler.
- `GenerateFormComponent` and the legacy `ImagePicker` are explicitly out of scope
  and left untouched (confirmed with the user).
- Part A and Part B are separate commits in separate repos.
