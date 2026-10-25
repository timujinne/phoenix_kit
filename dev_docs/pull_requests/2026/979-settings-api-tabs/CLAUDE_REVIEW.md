# PR #979 — Settings -> API: tabs, with the guide as one of them

**Author:** timujinne · **Merged:** 2026-10-23 (`72b7c8d0c`) · **Reviewer:** Claude

Splits `Settings.Api` into four URL-held tabs (`?tab=access|keys|approvals|guide`, via
`UrlTabs`), moves the guide into `ApiGuidePanel` (built in `handle_params/3` only when its
tab is open), and turns `ApiGuide` into a `push_navigate` redirect from the retired
`/admin/settings/api/guide`, keeping the `api` gate and the locale.

## Verdict

Sound. The tab mechanism is the established `UrlTabs` pattern; the redirect keeps the
`api` permission mapping (`Auth` view map still lists `ApiGuide`) and the locale, and the
new `api_tabs_test.exs` covers the tabs, the lazy guide, an `api`-only role, the locale
of the old address and the gate on the old route. Gettext is complete (the three new tab
labels are translated in all nine locales, 0 fuzzy).

## Findings

### IMPROVEMENT - MEDIUM — the guide's "Review approvals" button went through a retired redirect

`ApiGuidePanel.assign_guide/1` still built `approvals_path` from
`/admin/settings/api/approvals`, which is now a compatibility
redirect (`ApiApprovals`) to `/admin/approvals`. The button was a `navigate` into a
`push_navigate` from `mount/3`: two LiveView hops, and it would break the day the
compatibility route is deleted. **Fixed:** points at `/admin/approvals` directly; the
`api_guide_test` assertion follows.

### IMPROVEMENT - MEDIUM — `machine-api.md` still described the old pages

The component table named `ApiGuide` as the read-only guide page at
`/admin/settings/api/guide`, and the "Switching it on" section sent readers there.
**Fixed:** table rows and the pointer now name the `API guide` tab
(`/admin/settings/api?tab=guide`, `ApiGuidePanel`) and say `ApiGuide` is the redirect.

### NITPICK — the guide stays in assigns after leaving its tab

`@guide` is set on entering `?tab=guide` and never cleared, so after a tab change the
(hidden) guide pane keeps being rendered and diffed with its tool registry snapshot. It is
rebuilt on the next visit, so nothing shows stale, and the cost is a hidden pane. Not
changed: clearing it would re-send the pane's DOM on every tab switch, which is the thing
the "render all panes, hide with CSS" design avoids.

### NITPICK — `handle_params/3` builds the guide twice per page load

`handle_params/3` runs in the dead and the connected render, so `?tab=guide` reads the
registry and `Routes.base_url/0` twice. Harmless (admin page, reads only); left as is.

## Checked and fine

- No `push_patch`/`navigate` in `api.ex` drops the active tab; key/token handling is
  untouched (no token in a URL — the tab param is the only query).
- `guide-switches-link` is a `patch` to `/admin/settings/api` inside the same LiveView.
- `UrlTabs.active/2` falls back to the default for an unknown tab.

## Validation

`api_tabs_test`, `api_guide_test`, `api_guide_translations_test`, `auth_test`: 128 tests, 0 failures.
