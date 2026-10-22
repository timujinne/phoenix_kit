# PR #970 — Fix the admin menu to offer Approvals only while the site uses them

**Author:** timujinne · **Merged:** 2026-10-23 (b53b1ee09) · **Reviewer:** Claude

## Summary

The Approvals sidebar entry gains `visible: &AdminTabs.approvals_visible?/1`, which asks the new `Approvals.in_use?/0`: a key that has not reached its
`revoked_at`/`expires_at` is marked `requires_approval`, or any `kind == "approval"` confirmation row is still kept. `/admin/approvals` and the link on
Settings -> API are unchanged. CHANGELOG, AGENTS.md and the machine-API guide updated.

Verdict: correct. Verified against the code rather than the description:

- The SQL mirrors `Keys.dead_reason/1` (a future revocation is a rotation's grace period and still counts; both tested).
- `Registry.get_tabs/1` filters by permission **before** visibility, so the two `exists?` queries run only for `api` holders, who already pay the badge
  query (`pending_count/1`) on the same render. Viewers without `api` pay nothing.
- A failed read shows the tab (rescue + `catch :exit`), so a pending approval cannot drop out of the menu; `Tab.visible?/2` would otherwise hide on a raise.
- Hiding the tab does not gate the route: `approvals_test.exs` opens the page and the Settings link with approvals unused. Rejected/decided rows keep the
  entry (history), and `kind == "token"` codes do not count (tested).
- Tests (`admin_approvals_tab_test.exs`, `approvals_test.exs`, 81 tests with #971's) pass.

## Findings

- **NITPICK (not changed):** `in_use?/0` is two sequential `exists?` queries per sidebar render for `api` holders; one `UNION`/`OR` query would halve it.
  Both are index-light on small, pruned tables and the render already runs the badge count, so not worth the complexity.
- **NITPICK (not changed):** decided approval rows are pruned after the retention cutoff (`Confirm`, ~line 369), so on a site that stopped using approvals
  the entry disappears by itself later. That is the intended reading of "in use"; noting it so a vanishing entry is not reported as a bug.
