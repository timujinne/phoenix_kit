# PR #940 — Add per-module API switches on Settings -> API and an API badge on the Modules page

**Author:** timujinne · **Merged:** 2026-10-19 (8805eb62c) · **Reviewer:** Claude

## Summary

`api_disabled_modules` (newline-separated module keys): `Registry` withholds a listed module's tools exactly like `api_disabled_tools`
ones (`not_found`, fail-closed when either list is unreadable); `ModuleRegistry.api_modules/0` feeds a per-module switch card on
Settings -> API and an "API on / off / idle" badge on the Modules page; `Settings.modify_setting_with_module/4` writes the list
under a row lock so two admins' toggles cannot lose each other's change.

Verdict: sound. The event names the module by key and the wanted state (a replay does not undo itself), the key must be one the page
lists, rights are re-read by `with_access/2`, the setting is read through the one `Config.fetch_disabled_modules/0`, and
no module switch can reach core's `system.*` tools.

## Findings

- **BUG - MEDIUM (fixed, test only):** `mcp_tools_call_test.exs` "a tool of a module whose API is switched off is not_found in either
  form" still expected an `isError` result. PR #941, merged right after this one, makes an unknown or hidden tool name a JSON-RPC
  `-32602` error, and the module switch hides a tool the same way (`Registry.find/2` answers `:not_found`). The two PRs were
  never run together. The test now asserts the `-32602` "Unknown tool: …" answer for both name forms; the behaviour is the
  documented one.
- **BUG - MEDIUM (fixed):** `mix precommit` failed on this PR's `Settings.modify_setting_with_module/4`: dialyzer
  `call_without_opaque` on `Ecto.Multi.run(Ecto.Multi.new(), ...)` (the fresh multi's `MapSet` seen through its opaque `names`).
  Nothing runs dialyzer on merge, so main was red. The multi is now built with a pipe, and a regex ignore limited to that
  warning in `settings.ex` (`call_without_opaque ... in run.`) is in `.dialyzer_ignore.exs`; another opaque misuse in the file still shows.
- **NITPICK (not changed):** the Modules-page badge is rendered only in the external-module card; core modules that start declaring
  API tools would need the same `<.api_badge>` in their card.
- **NITPICK (not changed):** `Modules` calls `ModuleRegistry.api_modules/0` (asks every module for its tools) at both mounts and
  after each enable/disable. No DB query, but it runs module code; fine at today's module count.
