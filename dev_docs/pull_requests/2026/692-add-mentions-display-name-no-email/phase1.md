# PR #692 — Phase 1 Surface Review

**PR:** [Add cross-module mentions, one canonical display name, and stop publishing email addresses](https://github.com/BeamLabEU/phoenix_kit/pull/692)  
**Author:** Max Don (mdon)  
**Opened:** 2026-08-09 15:03 UTC  
**Reviewer:** Pincer  
**Review date:** 2026-08-09  
**Phase:** 1 — Surface sanity check (pre-merge)

---

## Stats

- +4,507 / -106 lines
- 43 files changed

---

## Files changed

All modified files are appropriate for the described feature set. No unexpected file types.

| Area | Files |
|---|---|
| Core Elixir | `.dialyzer_ignore.exs`, `lib/phoenix_kit/**/*.ex`, `lib/phoenix_kit_web/**/*.ex`, `lib/modules/**/*.ex` |
| Migrations | `lib/phoenix_kit/migrations/postgres/v165.ex`, `v166.ex`, `postgres.ex` |
| Templates | `lib/phoenix_kit_web/live/settings.html.heex` |
| Compiled JS asset | `priv/static/assets/phoenix_kit.js` |
| Tests | `test/**/*.exs`, `test/js/collapse_space.test.cjs` |

---

## Red flag checks

### 1. Unexpected files
**PASS.** All files fall squarely within the described scope (mentions, display name, image sanitizer, comment attribution, accordion scroll fix). No build artifacts, swap files, crash dumps, or archives.

### 2. Dependency changes (`mix.exs`)
**PASS.** `mix.exs` is not modified. No new dependencies introduced.

### 3. Secrets / credentials
**PASS.** Grepped the full diff for secret-shaped strings. Nothing found.

### 4. Suspicious JS
**PASS.** The `phoenix_kit.js` change appends 478 lines of the "collapse scroll keeper" — readable, commented JavaScript that matches the corresponding `accordion.ex` changes. No `eval()`, `innerHTML =`, `document.write`, `XMLHttpRequest`, or remote fetches.

### 5. Endpoint changes
**NOTE (non-blocking).** `endpoint.ex` adds `:peer_data` to the WebSocket `connect_info`. This is a standard Phoenix pattern for reading client IP in LiveView — needed here so the access-request handler can record origin metadata. Legitimate.

### 6. Migration renumbering
**NOTE (non-blocking, documented).** Migrations were originally V163/V164 and were renumbered to V165/V166 during the rebase onto upstream. The PR description explains this clearly, and the `release_check` output it includes confirms: floor, contiguity, and loadability all pass.

### 7. Deliberately failing tests
**NOTE (expected, documented).** Two tests fail:
- `check_manifest_chain_hash/0`
- `check_migration_sync/0` (hash assertion only)

Per `dev_docs/squash/README.md`, this is expected for migration PRs. The manifest must be regenerated before release, not in this PR. `mix precommit` exits 0.

### 8. Email address privacy fix
The direct motivation for this PR — `Users.CommentResources.display_name/1` previously fell back to `user.email`, publishing full addresses on public issue boards — is addressed cleanly. The private helper is replaced with a call to the new canonical `User.display_name/1`, which never returns a full address.

---

## Summary

No red flags. This is a well-scoped, well-documented PR:

- **New feature** (Mentions V165): large but coherent, all within `lib/phoenix_kit/mentions/` and matching test coverage
- **Security/privacy fix** (display name, frozen attribution, image sanitizer): addresses real leaks, clearly explained
- **Smaller fixes** (nested form in `file_upload`, JSONB orphan detection, accordion scroll jump): plausible and narrow

The two deliberate test failures and the stale schema manifest are properly documented and are release-time concerns, not merge blockers.

---

## Verdict

**RECOMMEND MERGE.** No blockers found at the surface level. Ready for Phase 2 when Dmitri approves.
