# PR #4 — Media module extraction — Frontend / JS review

Reviewer: reviewer-frontend (Claude)
Scope: `priv/static/assets/phoenix_kit.js` hooks (`MediaViewerDialog`, `PkDialog`),
`media_viewer.html.heex`, `media_selector_modal.html.heex`, `media_gallery.html.heex`.
Range reviewed: `git diff f080f55f..feature/media-module-extraction` (frontend parts only).

## Verdict: **PASS**

No CRITICAL or HIGH defects. The `<dialog showModal()>` + LiveView integration is
coherent; open/close ownership is well thought out. Findings below are MEDIUM
improvements and nitpicks.

---

## Stage 1 — Spec compliance

- A1 `MediaViewer` standalone lightbox: present, `<dialog>` single root, prev/next
  chevrons + ←/→, Esc/backdrop close, Download link, `<.image_set>`. PASS.
- A2 `SortableGrid` canonical key: `media_gallery.html.heex` emits
  `reorder_images:{id}`, `media_gallery.ex:121` reads `%{"ids" => ids}`, moduledoc
  documents the contract (`media_gallery.ex:43-47`). PASS.
- Deviation (acceptable): spec A1 mentioned the `ViewerKeydown` hook; the PR instead
  routes keyboard via the new `MediaViewerDialog` hook. This is the later `<dialog>`
  rework and is functionally superior (top-layer + keydown in one hook). Not a fail.

**Spec Verdict: PASS**

---

## Stage 2 — Code quality

### IMPROVEMENT-MEDIUM — `MediaViewerDialog` has no `updated()`
`phoenix_kit.js` `MediaViewerDialog` only implements `mounted()`. This is currently
**correct** for step prev/next: the `<dialog>` root in `media_viewer.html.heex:1-6`
has only static attributes (`id`, `class`, `phx-hook`, `phx-target`), so LiveView
never patches the dialog's opening tag and the `open` state set by `showModal()`
survives re-renders. The dialog also relies on mount/unmount (`:if={@preview_uuid}`
in `media_gallery.html.heex:95`) for the full open/close lifecycle.

The risk is **fragility, not a current bug**: if any dynamic attribute is ever added
to the `<dialog>` tag, morphdom will reconcile the opening tag and may strip the
JS-added `open` attribute, silently closing the viewer. `PkDialog` already guards
this exact case with `updated()` + `_sync()`. Recommend either (a) add a defensive
`updated()` that re-calls `showModal()` if `!this.el.open`, or (b) add a code comment
on the `<dialog>` pinning the "root attributes must stay static" invariant.

### IMPROVEMENT-MEDIUM — `modal-box` fights daisyUI `.modal` layout
`media_viewer.html.heex:13` overrides the daisyUI `.modal-box` with a long chain of
`!important` utilities (`!fixed !inset-0 !w-auto … lg:!relative`) to get a mobile
fullscreen / desktop-centered box. It works, but pulling `modal-box` out of the
`.modal` grid with `!fixed` defeats the point of using the daisyUI `modal`
component. Consider a plain Tailwind-styled `<dialog>` (as `media_selector_modal`
does) rather than `class="modal"` + a wall of `!` overrides. Cosmetic/maintainability.

### IMPROVEMENT-MEDIUM — Accessibility: no dialog labelling / focus return
Neither `<dialog>` sets `aria-labelledby` (the `<h2>` "Select Media" /
filename heading are good candidates). Also, when the viewer closes by LiveView
removing the node (`:if` false), the browser does not reliably restore focus to the
triggering "eye" button. `showModal()` auto-focus on open is fine; the gap is on
close. Low-effort wins for keyboard/AT users.

### NITPICK — hardcoded `id="media-selector-modal-backdrop"`
`media_selector_modal.html.heex:2` keeps a hardcoded element id (pre-existing, not
introduced here). With the host app rendering one `MediaGallery` — hence one embedded
`MediaSelectorModal` — per image slot, this is a duplicate-id hazard. In practice a
modal opened via `showModal()` makes the rest of the page inert, so two pickers
cannot be open at once and the collision never materialises. Still worth deriving
the id from the component (`@id`) for correctness.

### NITPICK — JS style consistency
`MediaViewerDialog` / `PkDialog` use `function () {}` + `const self = this` capture,
while neighbouring hooks (e.g. `AnnotationComposerPosition`) use arrow functions and
`this`. Harmless, but inconsistent within the same file. Also `t.isContentEditable
=== true` (`MediaViewerDialog._onKey`) — `isContentEditable` is already boolean, the
`=== true` is redundant.

### NITPICK — hover-only reveal of eye/remove buttons
`media_gallery.html.heex:36,50` reveal the preview/remove buttons via
`opacity-0 group-hover:opacity-100`. On touch devices there is no hover, so the
buttons are effectively unreachable. Known pattern in this codebase; flagging only.

---

## Things verified OK (no action)

- `pushEventTo(this.el, …)` in both hooks correctly targets the LiveComponent — the
  `<dialog>` is each component's root and carries `phx-target={@myself}`.
- Event-listener cleanup: both hooks remove `cancel`/`keydown` listeners and call
  `close()` in `destroyed()`. No leak; top-layer cleanup also happens automatically
  when LiveView removes the node.
- `cancel` handling: `e.preventDefault()` keeps the server as single source of truth;
  Escape routes to `viewer_keydown`/`close_modal` and the server then unmounts the
  component. No double-close, no double-handling (arrow `_onKey` early-returns on
  non-arrow keys, so Escape is handled once via `cancel`).
- Input-focus suppression: `_onKey` correctly skips `INPUT`/`TEXTAREA`/contentEditable.
- `PkDialog._sync()` is correct — `updated()` re-asserts desired open state, which is
  the necessary guard against morphdom stripping `open` when `data-show` changes.
- `SortableGrid` wiring: `phx-hook` gated on `not @readonly`, `data-sortable-event`
  set, `sortable-item`/`data-id`/`sortable-ignore` classes present and consistent
  with the `reorder_images:{id}` + `%{"ids"=>…}` server contract.
- MediaViewer template satisfies the stateful single-root constraint (`<dialog>` is
  the lone root; computed `<% %>` blocks are inside it).

## Quality Summary
0 critical, 0 major, 3 minor (IMPROVEMENT-MEDIUM), 3 nitpick.
**Quality Verdict: Ship** (address MEDIUM items in a follow-up if not now).
