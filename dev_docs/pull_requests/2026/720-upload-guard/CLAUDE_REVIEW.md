# PR #720 review — UploadGuard: native leave-page protection for in-flight uploads

**Author:** mdon · **Merged as:** 88ab3d2c (merge of 207aa210 / 05746bad)

## Summary

Adds a `phx-hook="UploadGuard"` to both `file_upload.ex` variants (`full_upload`,
`button_upload`). The div wrapping each upload carries `data-active`, patched
server-side from `@upload.entries != []`. The hook installs a `beforeunload`
listener that calls `preventDefault()` / sets `returnValue` while `data-active`
is `"true"`, so an accidental tab close/refresh during an in-flight upload gets
the browser's native confirmation dialog instead of silently losing the
transfer (LiveView uploads aren't resumed). Listener is torn down in
`destroyed()`. Scoped to full page unloads only — LiveView `patch`/`navigate`
is untouched, as intended.

Also: `label` attr default changed from a hardcoded `"Upload Files"` string to
`nil` + `gettext` fallback, and the remaining hardcoded UI strings in the
component (`"Cancel upload"`, `"Drag files here or click to browse"`,
`"Drop your files to upload"`, `"Maximum file size: %{size}"`) were wrapped in
`gettext/1`/`gettext/2`.

## Findings

No bugs in the PR's own diff. The hook logic, id derivation
(`pk-upload-guard-<ref>` / `pk-upload-guard-btn-<ref>`, unique per upload
config and per variant), and the `data-active` boolean patching are all
correct — reading `dataset.active` live at `beforeunload` time means no
`updated()` hook callback is needed. Two tests pin the `full_upload` hook
contract (armed/disarmed); `button_upload` isn't separately tested but shares
the same trivial wiring.

**IMPROVEMENT - MEDIUM (pre-existing, surfaced by this PR touching
`priv/gettext/`, not introduced by #720):** `default.pot` was stale — the
`column_settings.ex` component added in #719 (already released as 2.8.0)
calls `gettext("Columns")` and `gettext("Shown")`, but neither string had ever
been extracted, so they were untranslated in all 7 non-English locales despite
the "all locales 100% translated" state recorded after 1.7.232. Fixed as part
of this pass: ran `mix gettext.extract` + `mix gettext.merge priv/gettext`,
then translated `"Columns"` / `"Shown"` in de/es/et/fr/it/pl/ru to match the
existing `"Available"` label's register (the three render as a matched
heading set in the column-settings modal).

**NITPICK:** `file_upload.ex`'s moduledoc still says `label` (optional) -
Button label (default: "Upload Files")`, which is now only true indirectly
(default is `nil`, falls back to the same translated string). Not worth a
separate commit-worthy fix; left as-is since the visible behavior is
unchanged and the doc isn't misleading about behavior, just about the literal
default value.

## Fixes applied

- `mix gettext.extract` + `mix gettext.merge priv/gettext` to resync
  `default.pot`/`phoenix_kit.pot` and all locale `.po` files (mostly `#:`
  line-number churn from unrelated prior commits, plus the two missing
  `column_settings.ex` msgids).
- Translated `"Columns"` / `"Shown"` into de, es, et, fr, it, pl, ru.

## Gate

- `mix gettext.extract --check-up-to-date` — clean after the merge/translate above.
- `mix precommit` — clean (format, compile --warnings-as-errors, deps.unlock
  --check-unused, quality.ci [format-check, credo --strict, dialyzer], JS
  tests). First run raced a concurrent `gettext.extract` compile and dialyzer
  spuriously reported "No .beam files to analyze"; a clean rerun passed.
- `mix test` — run separately (see release report for result).
