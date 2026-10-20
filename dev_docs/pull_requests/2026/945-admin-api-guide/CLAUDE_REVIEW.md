# PR #945 — Add an admin API guide page under Settings -> API

**Author:** timujinne · **Reviewer:** Claude · **State at review:** open, `CONFLICTING` (merged by hand, see below)

## Merge conflict

The PR branched before #940/#941/#943/#936 landed. Only the ten gettext catalogs
(`default.pot` + nine `.po`) conflicted: both sides appended new entries at the same
spot at the end of the file. Resolved by keeping both sides in every catalog (main's
entries first, the PR's after), with one wrinkle — in `default.pot` and `en/default.po`
git had split off the shared trailing `msgstr ""`, so each needed it put back between the
two blocks (the file did not parse otherwise: `Expo.PO.SyntaxError` at the join).

Checked afterwards: no conflict markers, no duplicate `msgid` in any catalog, `mix compile
--warnings-as-errors` clean, 0 fuzzy entries added, and the PR's own tests plus
`test/phoenix_kit/api`, `test/phoenix_kit_web/live/settings` and `auth_test.exs` pass
(1651 tests, 0 failures).

⚠️ Do **not** "finish" this kind of merge with `mix gettext.extract --merge`: on today's main
it rewrites hundreds of `#:` reference lines and marks 27 entries per locale fuzzy (which
are served). It is pre-existing drift, unrelated to the PR; the minimal both-sides join is
the right resolution.

## Review

The page is sound. `ApiGuide` is read-only (no events), gated by `api` through the
`permission_key_for_admin_view` map (with a test), and holds no key: every snippet carries
`<your key>` or a VS Code `inputs` prompt. The Claude Code line puts `--header` after the URL
(the option is variadic) and shell-quotes both values. Tools, errors and limits come from the
live registry / `Problem.statuses/0` / `FlowConfig`, so nothing is hand-copied.

- **NITPICK** — `mount/3` reads settings (`get_project_title`, `Config.*`, `FlowConfig.*`).
  They are cache reads and the page has no `handle_params`, so there is no duplicate query
  to speak of; left as is.
- **NITPICK** — `ClientName.slug/1` falls back to `"shop"`, so the admin server of a
  site with an unslugable title is `shop-admin`; fine, documented in the moduledoc.

No fixes needed.
