# PR #969 — Render time_ago in the user's language on the server

**Author:** timujinne · **Merged:** 2026-10-22 (4926ba5d8) · **Reviewer:** Claude

## Summary

`<.time_ago>` drops its `TimeAgo` client hook (which rewrote the text in English once the page was live), renders with `ngettext` plural forms, shows a
`YYYY-MM-DD HH:MM` tooltip in the site time zone (settings cache), and clamps a future moment to "0s ago". `.po` files gain the plural entries
(et/ru/uk/pl full-word day forms); the hook stays in the bundle for host markup. Changelog entry included.

Verdict: correct. Plural forms checked in ru/et/pl/uk (1 / 2–4 / 5+ and 21); no fuzzy or empty entry in the nine catalogues; the removal of the
generated DOM id and `data-datetime` has no remaining reader in `lib/` or `test/`. Tests (`time_display_test.exs`, `time_display_site_zone_test.exs`,
the picker test) pass.

## Findings

- **NITPICK (not changed):** the text no longer ticks, so a long-lived LiveView shows "just now"-style text frozen until its next render. Documented in
  the CHANGELOG and accepted by the PR; a view that needs live ageing re-renders on a timer.
- **NITPICK (not changed):** a scheduled moment in the future reads "0s ago", which is misleading for a future time (the old code printed a negative
  count). Not checked per caller; an "in 3 days" form would be a new feature.
- `priv/gettext/en` carries 54 fuzzy flags with empty msgstrs; they predate this PR and are not served, so they are left alone.
