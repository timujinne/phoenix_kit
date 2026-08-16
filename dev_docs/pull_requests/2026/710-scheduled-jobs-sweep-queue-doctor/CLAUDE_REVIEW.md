# PR #710 — Scheduled-jobs sweep, the missing queue on upgrade, and the doctor check

**Reviewed:** 2026-08-13 · **Author:** @mdon · **Verdict:** merged, with one follow-up applied on main.

## Summary

Three fixes: the `:debug`-fatal `KeyError` in `ProcessScheduledJobsWorker.perform/1`,
`ensure_scheduled_jobs_queue/2` for the upgrade path, and a new
`check_cron_queues/1` doctor check. The PR's own analysis is accurate throughout —
everything it claims about Oban's behaviour I verified against the vendored source
rather than taking on trust, and all of it holds.

## Verified against Oban's source, not the description

- **`plugins: false` genuinely drops a top-level `crontab:`.** `check_cron_queues/1`
  returns `{:pass, ...}` for `plugins: false` without consulting `crontab:`, which
  would be a false negative if Oban still promoted the key. It does not:
  `Oban.Config.crontab_to_plugin/1` (`deps/oban/lib/oban/config.ex:320`) only
  promotes when `plugins` is a list or nil, and otherwise
  `Keyword.drop(opts, @cron_keys)` discards the crontab outright. The pass is correct.
- **`testing: :inline | :manual` really does overwrite both.**
  `deps/oban/lib/oban/config.ex:94-99` puts `plugins: []` and `queues: []`. The
  early pass is correct, and the test that `:disabled` still warns is the right
  companion to it.
- **`normalize_oban_list(false)` returns `[]`**, so the eager
  `queues = normalize_oban_list(raw_queues)` above the `cond` cannot raise on
  `queues: false`. The explicit `raw_queues == false` clause is belt-and-braces
  rather than load-bearing — harmless.
- **`{:ok, worker, queue} <- [entry_queue(entry)]`** filters `:skip` out of the
  comprehension correctly, and `Code.ensure_loaded?/1 and function_exported?/2`
  is the right guard for a release where a crontab names an unloaded dependency.

## The worker fix

Deleting the announce block rather than correcting `job.id` → `job.uuid` is the
right call: the count it logged duplicates the completion line, and it cost a
second `get_pending_jobs/0` over the same rows every minute. `perform/1` still
returns `:ok` unconditionally, matching the moduledoc's stated contract.

The regression test drives the fatal combination (`:debug` + a due job) and
restores `Logger.level()` in `on_exit`, so it cannot leak the level into the rest
of an `async: false` run.

## IMPROVEMENT - HIGH: the six sibling helpers kept every defect this PR fixed

**Applied on main after merge** — the one thing this PR left on the table.

`ensure_scheduled_jobs_queue/2` was written hardened against six ways string
surgery on a `queues:` list goes wrong, and the PR is explicit that it
"deliberately does not copy its siblings' regexes". But it also did not fix the
siblings, and all six — `posts`, `sitemap`, `shop_imports`,
`newsletters_delivery`, `catalogue_pdf`, `notifications` — each hand-rolled the
same surgery with the same

```elixir
~r/(^config\s+:#{app_name},\s+Oban.*?queues:\s*\[)(.*?)(\n\s*\])/ms
```

and therefore reproduced every defect. That is worse than the gap it repairs:
a missing queue leaves jobs stuck, but a bad **insert corrupts the host's
`config.exs`** — `queues: [\n]` writes `queues: [,`, a nested `default: [limit: 10]`
swallows the insert into an option Oban rejects at boot, and an Oban block with no
`queues:` of its own lets the lazy `.*?` walk into a neighbouring application's
config.

There is also a seventh defect the siblings have and `scheduled_jobs` never
could, because its guard is anchored and theirs are not: `~r/notifications:\s*\d+/`
is satisfied by a host's own `push_notifications: 5`, so the real `notifications`
queue is silently never added — the exact missing-queue failure this PR exists to
fix, one guard further up.

**Fix:** the hardened implementation is now `ensure_queue/4`, parameterised by
queue name and limit, and all seven call it. The six trivial wrappers are gone;
`update_existing_oban_config/3` pipes through `ensure_queue/4` directly and
carries the per-queue rationale (why `catalogue_pdf` and `notifications` exist)
as a comment on the list. `queue_configured?/2` anchors with `^\s*` and escapes
the queue name. `ensure_scheduled_jobs_queue/2` stays as a public named wrapper
because the PR's tests call it.

8 new tests in `test/phoenix_kit/install/oban_config_test.exs` cover all seven
queues through a real host config (insert, parses, idempotent) plus the
`push_notifications` false-positive, the commented-out entry, the keyword form,
the neighbouring app, nested options, a list ending in a comment, and the empty
list.

## NITPICK — not changed

- `check_entry_queues/2`'s pass message counts `length(entries)` including
  entries `entry_queue/1` skipped, so "12 crontab entries, every queue
  configured" can include entries that were never actually checked. Cosmetic;
  the warn path names each real offender, which is what matters.
- `add_queue_entry/3` indents a new entry at `queues:`-indent + 2 rather than
  matching the existing entries' indentation. Only visible on a host whose
  entries are indented unusually, and the result still parses.

## Deliberately not addressed

The PR's "Deliberately not in this PR" section — `unique:` on the worker and an
atomic claim in `process_pending_jobs/0` — is well-reasoned and its evidence
checks out (`Oban.Job`'s `job.ex:848` does exempt only `[:scheduled]` from the
`IO.warn`). The double-execution exposure on host-written handlers is real and
deserves the separate PR the author proposes; it is not a regression from this
change.
