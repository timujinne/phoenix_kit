# PR #936 — Add date_input: dates in the site format with a clear button and a calendar in the UI language

**Author:** timujinne · **Merged:** 2026-10-19 (dbd5526c2) · **Reviewer:** Claude

## Summary

New `<.date_input>` (visible text field in the site's `date_format` + a hidden-but-real `<input type="date">` carrying the
name and ISO value, hook `PkDateInput`, Cally calendar vendored and served through `ViewerLibraries`). `<.input type="date">`
and `<.date_nav>` now render it; `native` / `config :phoenix_kit, native_date_inputs: true` opt out.

Verdict: sound. Progressive enhancement is handled (a page with no hook still submits a native date input; the hook
detects a stylesheet without the `group-data-[enhanced]` utilities and undoes the swap), the commit contract keeps half-typed
text away from LiveView, the vendored `cally.js` sha256 matches the README and `ViewerLibraries`, the parser (two-digit year
window, digits-only, month names, impossible dates) matches its JS tests, and the nine `.po` files carry the new strings.
`date_input` tests, the diff test, `date_nav` tests and `test/js/date_input.test.cjs` (74) pass.

## Findings

- **NITPICK (not changed):** a two-digit year window is anchored on the server-rendered `data-today`; a page left open across
  New Year keeps the old anchor until the next patch. Irrelevant in practice (the window is ±50 years).
- **NITPICK (not changed):** the "Known gap" in the moduledoc stands — PkDialog's unsaved-input guard does not see edits to the
  text field, so a dialog with only a date change closes without the guard.
- **NITPICK (not changed):** `phx-feedback-for` is still emitted on the wrapper like the other core inputs; consistent with
  the rest of core, nothing to do here.
