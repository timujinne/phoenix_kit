# PR #556 — MediaGallery `max_count` + (undisclosed) table_default controlled view_mode / card_media / header default

State: MERGED into `dev` (merge commit `75b11f6b`).
Author: @timujinne
Diff: +249 / -16 across 4 files.

## Scope recap

The PR title/description describe **only** the MediaGallery `max_count` work.
The branch actually carries **three** commits:

1. `0805bb59` — MediaGallery `max_count` attr + disable Add button at limit (the described change).
2. `15ddac1e` — table_default: new `card_media` slot, controlled `view_mode` (+`view_event`), `class` override on `table_default_header`.
3. `20132de6` — table_default_header: flip default from `bg-primary text-primary-content` → `bg-base-300`.

I read the full merge diff (`git diff 75b11f6b^1 75b11f6b`) plus the final
state of `media_gallery.{ex,html.heex}` and `table_default.ex`.

## Verdict

Functionally sound and the `max_count` logic is clean and well-tested. But two
things merged here are broader than the PR title implies and deserve an
explicit product sign-off — a global table-header recolor and a behavioral
change to `:single`-mode pickers — and the entire table_default `view_mode` /
`card_media` surface landed with **zero tests**. Nothing is broken, but the
mismatch between the PR description and what shipped is the headline issue.

---

## Follow-up changes applied post-merge — @timujinne

Heads-up on what I changed on `dev` on top of your PR (commit `91d14ddc`),
so it's not a surprise next time you pull:

1. **credo `--strict` was red on `dev` because of this PR (now fixed).**
   `selection_at_limit?(selected, :single, _) -> length(selected) >= 1`
   (`media_gallery.ex`) tripped credo's "prefer comparing against an empty
   list" check, so `mix credo --strict` exited 16 — which means
   `mix quality.ci` / `mix precommit` (and the CI lint job) were failing on
   `dev` after the merge. Changed it to `selected != []` (same semantics,
   credo-clean). Worth running `mix precommit` — not just `mix test` — before
   pushing; it's the gate CI enforces.
2. **`table_default` card-view display cleanup.** The card `<div>` carried a
   permanent `grid` class and *also* got `hidden` in controlled `view_mode="table"`,
   so it relied on Tailwind emitting `.hidden` after `.grid` for the element to
   actually hide. Made the `display` utility per-branch (only `hidden` in table
   mode), matching the sibling table `<div>` — no behavior change, just removes
   the source-order dependency.

Still needs **your / a maintainer's** decision (I did not touch these — see
findings below): the `:single`-mode Add-button disable behavior change, the
global `table_default_header` recolor, and the missing test coverage for the
controlled `view_mode` / `card_media` surface.

---

## IMPROVEMENT - MEDIUM — PR scope vastly exceeds its description

The description is titled "MediaGallery: add max_count attr" and its Summary
talks only about the gallery cap. But ~93 of the 249 added lines are in
`table_default.ex` (a core component used across the whole admin UI), plus a
global default color change. A reviewer reading the PR body would not know to
look at table_default at all. This isn't a code bug, but for a foundation
library it's a real review-hygiene risk: sweeping changes to shared components
should be in a PR that announces them. Recommend the table_default work and the
header recolor be called out explicitly in the CHANGELOG entry for this version
so consumers aren't surprised.

## IMPROVEMENT - MEDIUM — `:single` mode now disables Add after one selection (contradicts "behave unchanged")

`media_gallery.html.heex:77-85` gates the Add tile's `disabled=` and
`cursor-not-allowed` on `selection_at_limit?/3`, and
`selection_at_limit?(selected, :single, _) = length(selected) >= 1`
(`media_gallery.ex:213`). The new test
`"Add button is disabled in :single mode with one item"` enshrines this.

Before this PR there was no `disabled` attribute and no `selection_at_limit?`,
so in `:single` mode the Add tile was **always clickable** — clicking it
reopened the picker, which (single mode) let the user pick a replacement in one
step. After this PR the Add tile is disabled once an image is selected, so
replacing the single image now requires Remove (the hover ✕) → Add → pick.

The PR body claims `:single` callers "behave unchanged." That's inaccurate: the
*selection cap* was always 1 (`apply_selection(_,_, :single, _) -> [uuid]`), but
the *button disable* is new. Whether this is desirable depends on the
single-mode consumers (the PR references a host app's document picker). If
click-Add-to-replace was an intended flow, this is a UX regression. Please
confirm with the single-mode consumers; if replace-via-Add should stay,
`:single` mode should not disable Add (the picker already replaces on pick).

## IMPROVEMENT - MEDIUM — `table_default_header` default recolored globally

`table_default.ex:449` flips the default from
`bg-primary text-primary-content` to `bg-base-300`. Every `<.table_default_header>`
call site that doesn't pass an explicit `class` changes appearance (and loses
the `text-primary-content` text color, now falling back to `base-content`). The
new docstring documents this as a deliberate "calm, theme-neutral" choice and
it is internally consistent, but it's a sweeping visual default change across
all admin tables shipped under a MediaGallery-titled PR. Confirm this was an
intended product decision (and that base-300/base-content contrast is
acceptable in every theme), and note it in the CHANGELOG so downstream apps
expecting the primary header know to pass `class="bg-primary text-primary-content"`.

## IMPROVEMENT - MEDIUM — controlled `view_mode` / `card_media` shipped untested

`15ddac1e` adds non-trivial branching to `table_default.ex`: controlled vs.
JS-hook mode toggles `phx-hook`, `data-storage-key`, `data-view-action`,
`phx-click`/`phx-value-mode`, and three sets of display classes on the
toolbar/table/card containers — plus the new `card_media` slot. None of it has
a test. `CLAUDE.md`'s own TODO already flags
`test/phoenix_kit_web/components/core/` as missing and calls out `<.table_default>`
specifically. This PR grows that surface further. At minimum, a couple of
rendered-HTML asserts for: (a) `view_mode=nil` keeps `phx-hook="TableCardView"`
and `data-view-action`; (b) `view_mode="table"` drops the hook, emits
`view_event` with `phx-value-mode`, hides the card div; (c) `card_media` slot
renders above the card body.

## NITPICK — card-view container relies on Tailwind's `hidden`-last ordering

`table_default.ex:353-360`: the card `<div>` always carries the base `grid`
class and additionally gets `hidden` when `view_mode == "table"`, so the
element ends up with both `grid` and `hidden`. This works only because Tailwind
emits `.hidden` after `.grid` in the compiled stylesheet (equal specificity →
source order wins). The sibling table `<div>` (`:295-302`) avoids the issue by
having no permanent display base. It's correct today, but fragile and
inconsistent with its sibling — consider making the card div's base display
conditional the same way for clarity/robustness.

---

## Positives

- `max_count` logic is tight: `apply_selection/4` clauses cleanly separate
  `:single`, `:multiple`+`nil`, `:multiple`+positive-int, and the
  zero/negative/non-int fallback; `selection_at_limit?/3` mirrors it so the
  button state can't drift from the clamp rule. Defence-in-depth (disabled
  button *and* server-side clamp) is the right call.
- 7 focused tests on the gallery cap, including the `apply_selection` clamp via
  a real `update/2` round-trip.
- Controlled `view_mode` wiring itself is correct (nil-guards on hook/data attrs,
  same event with distinct `phx-value-mode`, `btn-active` on the selected view).
