# PR #984 — permission sweep: review record

**Author:** Max Don (with Claude)
**Reviewers:** codex (round 1 and the fix review); findings checked against the code by Claude before fixing
**Verdict:** every confirmed finding fixed in this PR, each with a test that fails when the fix is reverted.

The sweep's rules: a sub-key `<base>.<sub>` is checked with `Scope.can?/2` in `mount/3` and every write
event against the live scope; new sub-keys are backfilled once to current base-key holders, with the
flag set only after every grant succeeded. Round 1 reviewed the whole change, round 2 only the fixes.

## Findings

- BUG-HIGH — `update_settings/2` persisted any posted key, so a settings-only holder could post `settings_security_backfilled="false"` and get `settings.security` from the next boot's backfill → fixed: only `form_setting_keys/0` are written.
- BUG-HIGH — `role_manageable?` and the backfill read permissions through functions that turn a DB error into `[]` (a failed read passed the subset check / set the flag) → fixed: `fetch_*` lookups, fail closed.
- BUG-MEDIUM — `promote_to_admin`, `demote_to_user`, `safely_remove_role` had no actor check → fixed: `actor:` option (no web caller today).
- BUG-MEDIUM — `crawlers_no_index` (and the `auth_background_*` keys) missing from the security keys → fixed after enumerating every key the two gated pages write.
- BUG-MEDIUM — a stored "Admin" default role failed every General save → fixed: the stored value is reported as what registration uses.
- Tests — the session-confirm test confirmed a refused dialog; the security-page test exercised only router admission → both rewritten so removing the fix turns them red.
