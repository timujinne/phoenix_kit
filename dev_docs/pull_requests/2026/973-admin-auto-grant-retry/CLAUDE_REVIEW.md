# PR #973 — Retry and report boot-time Admin permission grants, and let a host await them

**Author:** timujinne · **Merged:** 2026-10-23 (4b9d192b0) · **Reviewer:** Claude

## Summary

The boot `Task` that granted every key to Admin swallowed database errors (a warning, `:ok`, "retried next boot"), so an Admin could silently lack a
section for a whole uptime. It is now `Permissions.AdminGrants`, a permanent GenServer: sweeps in `handle_continue`, waits for `Dashboard.Registry`, keeps
failed keys pending and retries with a doubling backoff (6 attempts, about 63 s), gives up loudly once, and `Permissions.await_admin_grants/1` lets a host
wait. Grant failures are returned (`{:error, [{key, reason}]}`), a concurrent flag write is re-read before counting as a failure, a missing sandbox owner is
not retried.

Verdict: sound. Checked: child order (`Dashboard.Registry` starts before `AdminGrants`, so the registry wait is real, and `noproc` degrades to `:ok`);
`handle_continue` never blocks the supervisor; `await` before and after `:initial_done` both resolve; the `:failed` status restarts its backoff on a fresh
report; opt-in keys stay un-granted at both chokepoints; `Dashboard.Registry.handle_call(:sync, ...)` is answered after its own continue. `admin_grants_test`
(496 lines) green against a real DB.

## Findings

- **BUG - MEDIUM (fixed):** `mix precommit` fails on this merge: dialyzer `pattern_match_cov` at `permissions.ex` (`flag_not_saved/1`'s fallback clause can never
  match, `Settings.update_setting/2,3` returns only `{:ok, _}` or `{:error, _}`). `save_flag/1` now has one `{:error, reason}` clause (re-read the flag row,
  else `{:flag_not_saved, reason}`) and `flag_not_saved/1` is gone. Behaviour for both reachable outcomes is unchanged; `admin_grants_test` green.
- **IMPROVEMENT - MEDIUM (fixed):** `AdminGrantsNoOwnerTest` failed about one run in four (seed dependent): without its own pool mode it inherited a shared
  owner an earlier test had left, so the lookup exited (`owner exited`) instead of raising `OwnershipError`, and `{:no_owner, _}` never matched. It now sets
  the sandbox to `:manual` in `setup`; eight consecutive green runs.
- **NITPICK (not changed):** `handle_continue(:sweep)` can hold the server for up to 30 s on the registry wait, during which `report_failure/2` casts only
  queue. Harmless (they are evaluated afterwards), but `await/2` with the default 5 s timeout returns `{:error, :timeout}` for a registry that is merely slow.
  The docs already say the retries take about 63 s.
- **NITPICK (not changed):** a key in `dropped` stays reported until restart even if someone grants it by hand. Documented in the moduledoc.
