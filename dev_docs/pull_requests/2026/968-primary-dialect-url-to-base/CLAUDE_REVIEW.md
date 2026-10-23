# PR #968 — Send a base language's own dialect URL to the base code

**Author:** timujinne · **Merged:** 2026-10-22 (6cdb4e531) · **Reviewer:** Claude

## Summary

A URL carries a base code (`/en/`). A full dialect appears only for an enabled *sibling* that does not own its base's URLs (`/en-gb/` next to `en-US`).
`Languages.resolve_url_locale/1` / `url_locale_segment/1` decide it, and three places use the one rule: the HTTP plug (`sibling_dialect/1` replaces
`enabled_full_dialect/1`), the LiveView lifecycle (a new clause sends any other full dialect to its base), and `Routes` (an explicit `locale: "en-US"`
is emitted as `en`, with a base-code fallback when settings are unreachable). The full-dialect → base redirect becomes a 307 for non-GET/HEAD.

Verdict: correct. The core owner rule matches `Auth.resolve_active_dialect/1` (default dialect if enabled, else first enabled alphabetically), and
"no dialect owns the base when core and content disagree" keeps both full-code URLs reachable rather than picking one. A POST to
`/en-US/users/log-in` now keeps its body (302 would have replayed a GET). Tests (`auth_locale_test.exs`, `routes_test.exs`) pass.

## Findings

- **NITPICK (not changed):** `url_locale_segment/1`'s `iex>` examples depend on stored languages and are not doctested (`Languages` doctests are disabled
  repo-wide); the integration tests carry the same cases.
- **NITPICK (not changed):** `resolve_url_locale/1` does not check `Languages.enabled?/0`, unlike `resolve_active_dialect/1`. The plug's single-language branch returns first and `Routes` emits no segment
  while the switch is off, so it is harmless there; a new caller outside them would see the stored languages while the switch is off.
- Release note: a site that linked `/en-us/…` (primary en-US only) now answers 302 to `/en/…`; no CHANGELOG entry was written for this PR.
