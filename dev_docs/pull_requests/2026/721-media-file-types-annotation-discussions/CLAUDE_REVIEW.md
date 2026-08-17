# PR #721 review — Media file-type integrity + annotation discussion flow

**Author:** alexdont · **Merged as:** 1563c34b (merge of 099131db)

## Summary

Two bodies of work on one branch:

1. **Media file-type integrity.** `Storage.store_file_in_buckets/7` gains a
   `:mime_type` opt (browser-observed mime, stored verbatim; falls back to
   `MIME.type/1` + an `@audio_mime_fallbacks` map for the extensions it still
   answers octet-stream for). The claimed `file_type` is now cross-checked
   against the mime/filename evidence (`reconcile_file_type/3`) before the row
   is written, so one call site claiming `"image"` for everything (the bug
   that motivated this PR — an external module's board-upload path) can no
   longer poison the column for every downstream surface. `display_file_type/1`
   applies the same evidence-over-claim rule for rows written before the
   defense existed, and V174 repairs those rows in the database (audio mime
   resurrection on files + file_instances, then generic `file_type`
   reclassification; idempotent; deliberately no-op `down/1`).

2. **Annotation discussions.** Drawing a shape no longer opens a composer —
   every kind saves silently via `annotations-changed`, labels go through
   Etcher's inline editor. The tooltip (Etcher 0.13's `tooltipActions`) gets
   Reply/Edit/View header buttons: Reply lazily creates the shape's *master*
   comment (content = label or kind, author = shape creator, `inserted_at`
   backdated to the shape's creation) and opens a body-only popup that threads
   under it; the master is excluded from `comment_count`/preview
   (`metadata.annotation_master`) and its uuid surfaces as
   `master_comment_uuid` for threading. A live badge (`metadata.badge`)
   refreshes on comment create/delete via the existing `{:comments_updated,
   ...}` relay (`Embed` macro → `MediaBrowser`/`MediaDetail` → `send_update`
   with `action: :refresh_annotations`).

Also fixed on the way: labels typed inline were silently dropped
(`annotation_unchanged?` compared geometry/style/kind only, missing the
label-only change), a label commit crashed the LV (`current.title` read on a
curated map, not a schema struct — curated maps surface it as
`metadata.title`), and deleting a sidebar comment killed the whole LiveView
(no `handle_info` clause for `{:comments_updated, ...}` on the host process).

## Findings

No bugs found in the PR's own diff. Specifics checked:

- `resolve_claimed_type/2` / the mirrored SQL `CASE` in V174 agree on the
  "generic claim vs. evidence" rule, including the `"other"`/no-evidence
  carve-out and the `"tile"` system-type carve-out — verified against
  `test/modules/storage/determine_file_type_test.exs` and
  `test/phoenix_kit/migrations/v174_test.exs` (idempotency, instance-row
  repair, dotted-extension tolerance, tile/unknown-mime left alone).
- `persistable_attrs/2` deliberately never persists wire metadata verbatim —
  confirmed intentional (not a stripped-field regression) against
  `media_canvas_viewer_label_sync_test.exs`'s "wire metadata is never
  persisted verbatim" case; `comment_author` (the marker byline stamp)
  survives updates because it's dropped from neither `@etcher_label_meta_keys`
  nor `@load_injected_meta_keys`, and `put_marker_author/2` only runs on
  creation, after `persistable_attrs/2` has already narrowed the map — order
  is correct.
- `MediaBrowser.update(%{file_comments_changed: ...}, socket)` /
  `viewer_component_id/1` — the id used to address the canvas viewer via
  `send_update` is the exact same helper the heex template uses to mount it,
  so a refresh poke can't target a stale/mismatched component id.
  `MediaDetail`'s separate static `"media-detail-canvas-" <> uuid` scheme is
  consistent between its own `send_update` call and its own template mount
  (different id scheme from `MediaBrowser`, but each is internally
  consistent).
- `window.Etcher.tooltipActions` is assigned onto `window.Etcher =
  window.Etcher || {}` (pre-declared earlier in the same IIFE), so the
  assignment doesn't race the CDN-loaded Etcher script.
- All three upload call sites that gained the `mime_type:` opt
  (`MediaBrowser`, `MediaSelectorModal`, `MediaSelector`) bind it from the
  same `entry.client_type || MIME.from_path(entry.client_name)` pattern —
  no drift between call sites.

**IMPROVEMENT - MEDIUM (pre-existing, surfaced by this PR touching
`priv/gettext/`, not introduced by #721):** `default.pot` was stale — the
composer's copy change ("Add a note to your annotation" /
"Post to add the note..." → "Reply to this annotation") had never been
extracted, leaving the new string untranslated in all locales. Fixed as part
of this pass: `mix gettext.extract` + `mix gettext.merge priv/gettext`, then
translated `"Reply to this annotation"` into de/es/et/fr/it/pl/ru (`en` left
empty per the project's fallback-to-msgid convention). Also noted but **not**
fixed (out of scope for this PR — pre-existing debt, ~79 untranslated
strings per locale unrelated to #721's changes): translation coverage has
drifted below the "100% as of 1.7.232" state recorded in memory; worth a
dedicated sweep separately.

## Fixes applied

- `mix gettext.extract` + `mix gettext.merge priv/gettext` to resync
  `default.pot` and all locale `.po` files (mostly `#:` line-number churn,
  plus the one new/three removed msgids from the composer copy change).
- Translated `"Reply to this annotation"` into de, es, et, fr, it, pl, ru.
- Version bump `2.8.1` → `2.9.0` (mix.exs `@version`) and CHANGELOG entry —
  the PR intentionally left both to the maintainer/release pass.

## Gate

- `mix compile --warnings-as-errors` — clean.
- `mix precommit` (format-check, compile --warnings-as-errors, deps.unlock
  --check-unused, quality.ci [credo --strict, dialyzer 226/226], JS tests
  [45/45]) — clean. First run raced a concurrent `gettext.extract` compile
  and dialyzer spuriously reported "No .beam files to analyze"; a clean
  sequential rerun passed.
- `mix gettext.extract --check-up-to-date` — clean after the merge/translate
  above.
- `mix test` — 43 doctests, 3708 tests, 0 failures (108.7s, real Postgres).
