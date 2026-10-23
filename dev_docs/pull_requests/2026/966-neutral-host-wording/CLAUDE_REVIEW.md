# PR #966 — Use neutral host-application wording in comments, docs and test data

**Author:** timujinne · **Merged:** 2026-10-22 (2239d7dc2) · **Reviewer:** Claude

## Summary

Replaces a specific host application's name and private paths/IPs in plans, old review docs, squash tooling, two migration/component comments and two JS
test fixtures with neutral wording (`a host app`, `ACME`, `<host-app>`, `<db-host>`).

Verdict: no behaviour change. The only `lib/` hunks are comments (`v176.ex`, `preview_card.ex`, `url_state.ex`); the JS tests change fixture strings on
both sides of each assertion. A repo-wide grep finds no remaining occurrence of the old name or the `/www/app` path; the `172.18.0.x` addresses that
remain are the documented private-network examples for `:trusted_proxies`.

## Findings

None.
